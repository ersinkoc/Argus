package inspection

import (
	"sync"
	"time"
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
}

// AnomalyAlert represents a detected anomaly.
type AnomalyAlert struct {
	Username    string  `json:"username"`
	Type        string  `json:"type"`        // "unusual_command", "unusual_table", "unusual_hour", "frequency_spike"
	Description string  `json:"description"`
	Score       float64 `json:"score"`       // 0.0 to 1.0
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
		p.tableCounts[t]++
	}
	p.hourCounts[ts.Hour()]++
	p.totalQueries++
	p.lastSeen = ts
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
