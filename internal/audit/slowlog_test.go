package audit

import (
	"testing"
	"time"
)

func TestSlowQueryLogger(t *testing.T) {
	logger := NewLogger(100, LevelStandard, 4096)
	logger.Start()
	defer logger.Close()

	slow := NewSlowQueryLogger(100*time.Millisecond, logger)

	// Fast query — should not be flagged
	event := Event{SessionID: "s1", Username: "alice", Command: "SELECT 1"}
	if slow.Check(event, 10*time.Millisecond) {
		t.Error("10ms should not be slow (threshold=100ms)")
	}

	// Slow query — should be flagged
	if !slow.Check(event, 200*time.Millisecond) {
		t.Error("200ms should be slow (threshold=100ms)")
	}
}

func TestSlowQueryThreshold(t *testing.T) {
	slow := NewSlowQueryLogger(5*time.Second, nil)
	if slow.Threshold() != 5*time.Second {
		t.Errorf("threshold = %v, want 5s", slow.Threshold())
	}
}
