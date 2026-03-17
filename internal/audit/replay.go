package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"time"
)

// ReplaySession reconstructs a session's query history from recorded queries.
type ReplaySession struct {
	SessionID string         `json:"session_id"`
	Username  string         `json:"username"`
	Database  string         `json:"database"`
	Queries   []ReplayQuery  `json:"queries"`
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time"`
	Duration  string         `json:"duration"`
}

// ReplayQuery is a single query in a replay session.
type ReplayQuery struct {
	Timestamp   time.Time `json:"timestamp"`
	SQL         string    `json:"sql"`
	CommandType string    `json:"command_type"`
	Tables      []string  `json:"tables,omitempty"`
	Duration    int64     `json:"duration_us"`
	RowCount    int64     `json:"row_count"`
	Action      string    `json:"action"`
	Fingerprint string    `json:"fingerprint"`
}

// ReplayFromFile reads recorded queries and reconstructs a session timeline.
func ReplayFromFile(path, sessionID string) (*ReplaySession, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	session := &ReplaySession{SessionID: sessionID}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var rec QueryRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}

		if rec.SessionID != sessionID {
			continue
		}

		if session.Username == "" {
			session.Username = rec.Username
			session.Database = rec.Database
		}

		session.Queries = append(session.Queries, ReplayQuery{
			Timestamp:   rec.Timestamp,
			SQL:         rec.SQL,
			CommandType: rec.CommandType,
			Tables:      rec.Tables,
			Duration:    rec.Duration,
			RowCount:    rec.RowCount,
			Action:      rec.Action,
			Fingerprint: rec.Fingerprint,
		})
	}

	if len(session.Queries) == 0 {
		return session, nil
	}

	// Sort by timestamp
	sort.Slice(session.Queries, func(i, j int) bool {
		return session.Queries[i].Timestamp.Before(session.Queries[j].Timestamp)
	})

	session.StartTime = session.Queries[0].Timestamp
	session.EndTime = session.Queries[len(session.Queries)-1].Timestamp
	session.Duration = session.EndTime.Sub(session.StartTime).String()

	return session, scanner.Err()
}

// TopFingerprints returns the most common query patterns from recordings.
func TopFingerprints(path string, limit int) ([]FingerprintStat, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	counts := make(map[string]*FingerprintStat)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var rec QueryRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}

		fp := rec.Fingerprint
		if fp == "" {
			continue
		}

		stat, ok := counts[fp]
		if !ok {
			stat = &FingerprintStat{
				Fingerprint: fp,
				ExampleSQL:  rec.SQL,
				CommandType: rec.CommandType,
			}
			counts[fp] = stat
		}
		stat.Count++
		stat.TotalDurationUS += rec.Duration
		stat.TotalRows += rec.RowCount
	}

	// Convert to sorted slice
	result := make([]FingerprintStat, 0, len(counts))
	for _, s := range counts {
		if s.Count > 0 {
			s.AvgDurationUS = s.TotalDurationUS / int64(s.Count)
		}
		result = append(result, *s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, scanner.Err()
}

// FingerprintStat holds aggregated stats for a query fingerprint.
type FingerprintStat struct {
	Fingerprint     string `json:"fingerprint"`
	ExampleSQL      string `json:"example_sql"`
	CommandType     string `json:"command_type"`
	Count           int    `json:"count"`
	TotalDurationUS int64  `json:"total_duration_us"`
	AvgDurationUS   int64  `json:"avg_duration_us"`
	TotalRows       int64  `json:"total_rows"`
}
