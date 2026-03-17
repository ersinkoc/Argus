package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"
)

// SearchFilter defines criteria for searching audit logs.
type SearchFilter struct {
	SessionID   string
	Username    string
	Database    string
	EventType   string
	Action      string
	StartTime   time.Time
	EndTime     time.Time
	CommandType string
	Limit       int
}

// SearchResult holds matched audit events.
type SearchResult struct {
	Events []Event `json:"events"`
	Total  int     `json:"total"`
}

// SearchFile scans a JSON lines audit log file and returns matching events.
func SearchFile(path string, filter SearchFilter) (*SearchResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := &SearchResult{
		Events: make([]Event, 0),
	}

	if filter.Limit <= 0 {
		filter.Limit = 100
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}

		if matchesFilter(&event, &filter) {
			result.Total++
			if len(result.Events) < filter.Limit {
				result.Events = append(result.Events, event)
			}
		}
	}

	return result, scanner.Err()
}

func matchesFilter(event *Event, filter *SearchFilter) bool {
	if filter.SessionID != "" && event.SessionID != filter.SessionID {
		return false
	}
	if filter.Username != "" && !strings.EqualFold(event.Username, filter.Username) {
		return false
	}
	if filter.Database != "" && !strings.EqualFold(event.Database, filter.Database) {
		return false
	}
	if filter.EventType != "" && event.EventType != filter.EventType {
		return false
	}
	if filter.Action != "" && event.Action != filter.Action {
		return false
	}
	if filter.CommandType != "" && event.CommandType != filter.CommandType {
		return false
	}
	if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
		return false
	}
	if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
		return false
	}
	return true
}
