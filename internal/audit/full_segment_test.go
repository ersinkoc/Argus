package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotatingWriterDefaults(t *testing.T) {
	dir := t.TempDir()
	rw, err := NewRotatingWriter(filepath.Join(dir, "test.jsonl"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Defaults: 100MB, 10 files
	rw.Close()
}

func TestRotatingWriterCloseNilFile(t *testing.T) {
	rw := &RotatingWriter{}
	err := rw.Close()
	if err != nil {
		t.Error("close nil file should not error")
	}
}

func TestRecorderCloseNilFile(t *testing.T) {
	r := &QueryRecorder{}
	err := r.Close()
	if err != nil {
		t.Error("close nil file should not error")
	}
}

func TestSearchFilterTimeRange(t *testing.T) {
	now := time.Now()
	event := Event{Timestamp: now}

	// StartTime in future — should not match
	filter := SearchFilter{StartTime: now.Add(time.Hour)}
	if matchesFilter(&event, &filter) {
		t.Error("future start should not match")
	}

	// EndTime in past — should not match
	filter = SearchFilter{EndTime: now.Add(-time.Hour)}
	if matchesFilter(&event, &filter) {
		t.Error("past end should not match")
	}

	// Both match
	filter = SearchFilter{
		StartTime: now.Add(-time.Hour),
		EndTime:   now.Add(time.Hour),
	}
	if !matchesFilter(&event, &filter) {
		t.Error("within range should match")
	}
}

func TestSearchFilterCommandType(t *testing.T) {
	event := Event{CommandType: "SELECT"}

	if !matchesFilter(&event, &SearchFilter{CommandType: "SELECT"}) {
		t.Error("matching command type should pass")
	}
	if matchesFilter(&event, &SearchFilter{CommandType: "INSERT"}) {
		t.Error("non-matching command type should fail")
	}
}

func TestWebhookFlushError(t *testing.T) {
	// Webhook to invalid URL — flush should not panic
	wh := NewWebhookWriter(WebhookConfig{
		URL:     "http://127.0.0.1:1/noop",
		Timeout: 100 * time.Millisecond,
	})

	// Add event and flush
	wh.Write([]byte(`{"event_type":"test"}`))
	wh.flush() // will fail to POST but should not panic
}

func TestRotatingWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	rw, err := NewRotatingWriter(path, 1, 3) // 1MB max
	if err != nil {
		t.Fatal(err)
	}

	// Write enough to trigger rotation
	chunk := make([]byte, 100*1024) // 100KB
	for i := range chunk {
		chunk[i] = 'X'
	}
	chunk = append(chunk, '\n')

	for range 12 { // 12 * 100KB = 1.2MB > 1MB
		rw.Write(chunk)
	}
	rw.Close()

	entries, _ := os.ReadDir(dir)
	if len(entries) < 2 {
		t.Errorf("should have rotated files, got %d", len(entries))
	}
}

func TestLoggerWriteLoopDrain(t *testing.T) {
	logger := NewLogger(100, LevelStandard, 4096)
	logger.Start()

	// Fill buffer
	for range 50 {
		logger.Log(Event{EventType: "test", Action: "allow"})
	}

	// Close should drain
	logger.Close()

	// Verify drained (no panic, no hang)
}
