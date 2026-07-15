package inspection

import (
	"fmt"
	"sync"
	"time"
)

const (
	// maxTablesPerUser limits the number of tables tracked per user profile
	// to prevent memory exhaustion attacks
	maxTablesPerUser = 1000
	// maxProfiles limits the total number of user profiles to prevent memory exhaustion
	maxProfiles = 10000
)

// AnomalyDetector tracks query patterns per user and flags anomalies.
// It learns a baseline of normal behavior (query types, tables, frequency)
// and alerts when patterns deviate significantly.
type AnomalyDetector struct {
	mu       sync.RWMutex
	profiles map[string]*userProfile
	window   time.Duration // sliding window for baseline
}

type userProfile struct {
	commandCounts map[CommandType]int64
	tableCounts   map[string]int64
	hourCounts    [24]int64 // queries per hour of day
	totalQueries  int64
	firstSeen     time.Time
	lastSeen      time.Time
	// Frequency spike tracking: sliding window of 6 × 10-second sub-buckets.
	// This catches sharp bursts (e.g. 100 queries in 2 seconds) that a single
	// per-minute counter would smooth into the minute average.
	subBuckets    [6]int64    // 6 x 10s buckets in a rolling 1-minute window
	bucketStart   time.Time   // start time of the current (index 0) bucket
	peakSubRate   int64       // historical peak per-sub-bucket rate (×6 = minute-equivalent)
}

// AnomalyAlert represents a detected anomaly.
type AnomalyAlert struct {
	Username    string    `json:"username"`
	Type        string    `json:"type"` // "unusual_command", "unusual_table", "unusual_hour", "frequency_spike"
	Description string    `json:"description"`
	Score       float64   `json:"score"` // 0.0 to 1.0
	Timestamp   time.Time `json:"timestamp"`
}

// NewAnomalyDetector creates a detector with the given baseline window.
func NewAnomalyDetector(window time.Duration) *AnomalyDetector {
	if window <= 0 {
		window = 24 * time.Hour
	}
	return &AnomalyDetector{
		profiles: make(map[string]*userProfile),
		window:   window,
	}
}

// Record records a query for baseline learning.
func (d *AnomalyDetector) Record(username string, cmdType CommandType, tables []string, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Enforce profile limit to prevent memory exhaustion
	if len(d.profiles) >= maxProfiles {
		// Evict oldest profile
		var oldest string
		var oldestTime time.Time
		for name, p := range d.profiles {
			if oldestTime.IsZero() || p.lastSeen.Before(oldestTime) {
				oldest = name
				oldestTime = p.lastSeen
			}
		}
		delete(d.profiles, oldest)
	}

	p, ok := d.profiles[username]
	if !ok {
		p = &userProfile{
			commandCounts: make(map[CommandType]int64),
			tableCounts:   make(map[string]int64),
			firstSeen:     ts,
		}
		d.profiles[username] = p
	}

	p.commandCounts[cmdType]++
	for _, t := range tables {
		// Enforce table limit per user to prevent memory exhaustion
		if len(p.tableCounts) < maxTablesPerUser {
			p.tableCounts[t]++
		}
	}
	p.hourCounts[ts.Hour()]++
	p.totalQueries++
	p.lastSeen = ts

	// Update frequency tracking with sub-bucket sliding window.
	// Each bucket covers 10 seconds; 6 buckets = 1 minute rolling window.
	if p.bucketStart.IsZero() {
		p.bucketStart = ts
	}
	elapsed := ts.Sub(p.bucketStart)

	// Advance buckets as needed (may skip multiple if time jumped)
	if elapsed >= 10*time.Second {
		steps := int(elapsed / (10 * time.Second))
		if steps >= 6 {
			// More than a full window elapsed — reset entirely
			p.subBuckets = [6]int64{}
			p.bucketStart = ts
		} else {
			// Shift buckets left by `steps` positions
			copy(p.subBuckets[:], p.subBuckets[steps:])
			for i := 6 - steps; i < 6; i++ {
				p.subBuckets[i] = 0
			}
			p.bucketStart = p.bucketStart.Add(time.Duration(steps) * 10 * time.Second)
		}
	}

	// Increment current (front) bucket before peak detection so the peak
	// reflects the state after this query (not before it).
	p.subBuckets[0]++

	// Update peak detection — compare the current sub-bucket rate
	// (projected to minute-equivalent via ×6) against the historical peak.
	// The max single bucket ×6 catches sharp bursts (e.g. 100 queries in
	// 2 seconds) that a per-minute counter would smooth into the average.
	var maxBucket int64
	for _, v := range p.subBuckets {
		if v > maxBucket {
			maxBucket = v
		}
	}
	minuteEq := maxBucket * 6
	if minuteEq > p.peakSubRate {
		p.peakSubRate = minuteEq
	}
}

// Check analyzes a query against the user's baseline and returns any anomalies.
func (d *AnomalyDetector) Check(username string, cmdType CommandType, tables []string, ts time.Time) []AnomalyAlert {
	d.mu.RLock()
	defer d.mu.RUnlock()

	p, ok := d.profiles[username]
	if !ok {
		return nil // no baseline yet
	}

	// Need minimum queries for baseline
	if p.totalQueries < 100 {
		return nil
	}

	var alerts []AnomalyAlert

	// Check unusual command type
	cmdRatio := float64(p.commandCounts[cmdType]) / float64(p.totalQueries)
	if cmdRatio < 0.01 { // less than 1% of historical queries
		alerts = append(alerts, AnomalyAlert{
			Username:    username,
			Type:        "unusual_command",
			Description: cmdType.String() + " is rarely used by this user",
			Score:       1.0 - cmdRatio*100,
			Timestamp:   ts,
		})
	}

	// Check unusual tables
	for _, table := range tables {
		if p.tableCounts[table] == 0 {
			alerts = append(alerts, AnomalyAlert{
				Username:    username,
				Type:        "unusual_table",
				Description: "table " + table + " has never been accessed by this user",
				Score:       1.0,
				Timestamp:   ts,
			})
		}
	}

	// Check unusual hour
	hourTotal := p.hourCounts[ts.Hour()]
	avgPerHour := float64(p.totalQueries) / 24.0
	if avgPerHour > 0 && float64(hourTotal) < avgPerHour*0.1 {
		alerts = append(alerts, AnomalyAlert{
			Username:    username,
			Type:        "unusual_hour",
			Description: "query at an unusual time of day",
			Score:       0.7,
			Timestamp:   ts,
		})
	}

	// Check frequency spike: current sub-bucket minute-equivalent rate
	// > 3x historical peak. Using sub-buckets catches sharp bursts
	// (e.g. 100 queries in 2 seconds) that a per-minute counter would hide.
	var currentSubBucket int64
	for _, v := range p.subBuckets {
		if v > currentSubBucket {
			currentSubBucket = v
		}
	}
	burstRate := currentSubBucket * 6 // project to minute-equivalent
	if p.peakSubRate > 0 && burstRate > p.peakSubRate*3 {
		alerts = append(alerts, AnomalyAlert{
			Username:    username,
			Type:        "frequency_spike",
			Description: fmt.Sprintf("query rate spike: ~%d/min (sub-bucket peak %d/10s) vs historical peak %d/min", burstRate, currentSubBucket, p.peakSubRate),
			Score:       0.9,
			Timestamp:   ts,
		})
	}

	return alerts
}

// UserStats returns stats for a user.
func (d *AnomalyDetector) UserStats(username string) map[string]any {
	d.mu.RLock()
	defer d.mu.RUnlock()

	p, ok := d.profiles[username]
	if !ok {
		return nil
	}

	cmdStats := make(map[string]int64)
	for k, v := range p.commandCounts {
		cmdStats[k.String()] = v
	}

	topTables := make(map[string]int64)
	for k, v := range p.tableCounts {
		topTables[k] = v
	}

	return map[string]any{
		"total_queries":  p.totalQueries,
		"first_seen":     p.firstSeen,
		"last_seen":      p.lastSeen,
		"command_counts": cmdStats,
		"top_tables":     topTables,
	}
}

// TrackedUsers returns the number of tracked user profiles.
func (d *AnomalyDetector) TrackedUsers() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.profiles)
}
