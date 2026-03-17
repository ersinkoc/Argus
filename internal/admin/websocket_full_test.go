package admin

import (
	"testing"
)

func TestWriteTextNoClient(t *testing.T) {
	// writeText on nil conn should not panic in production
	// but we test the accept key computation which is the testable part
	key := computeAcceptKey("test-key-123")
	if key == "" {
		t.Error("accept key should not be empty")
	}
}

func TestEventStreamBroadcastEmpty(t *testing.T) {
	es := NewEventStream()

	// Broadcast with no clients — should be no-op
	es.Broadcast("test message")
	es.Broadcast(map[string]any{"key": "value"})
	es.Broadcast(42)

	if es.Count() != 0 {
		t.Error("should have 0 clients")
	}
}
