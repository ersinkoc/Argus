package audit

import (
	"log"
	"time"
)

// SlowQueryLogger logs queries that exceed a duration threshold.
type SlowQueryLogger struct {
	threshold time.Duration
	logger    *Logger
}

// NewSlowQueryLogger creates a slow query logger.
func NewSlowQueryLogger(threshold time.Duration, logger *Logger) *SlowQueryLogger {
	return &SlowQueryLogger{
		threshold: threshold,
		logger:    logger,
	}
}

// Check logs the query if its duration exceeds the threshold.
// Returns true if the query was slow.
func (s *SlowQueryLogger) Check(event Event, duration time.Duration) bool {
	if duration < s.threshold {
		return false
	}

	event.EventType = "slow_query"
	event.Duration = duration
	event.Reason = "query exceeded slow threshold"

	if s.logger != nil {
		s.logger.Log(event)
	}

	log.Printf("[argus] SLOW QUERY (%v): session=%s user=%s sql=%s",
		duration, event.SessionID, event.Username, truncate(event.Command, 100))

	return true
}

// Threshold returns the configured threshold.
func (s *SlowQueryLogger) Threshold() time.Duration {
	return s.threshold
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
