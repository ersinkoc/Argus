package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEventTypeStringAll(t *testing.T) {
	types := []EventType{
		ConnectionOpen, ConnectionClose, AuthSuccess, AuthFailure,
		CommandExecuted, CommandBlocked, ResultMasked, ResultTruncated,
		PolicyViolation, SessionTimeout, SessionKilled, PolicyReloaded,
	}
	for _, et := range types {
		s := et.String()
		if s == "unknown" {
			t.Errorf("%d.String() = unknown", et)
		}
	}
	// Unknown type
	if EventType(99).String() != "unknown" {
		t.Error("99 should be unknown")
	}
}

func TestShouldLog(t *testing.T) {
	logger := NewLogger(10, LevelStandard, 4096)
	if !logger.ShouldLog(CommandExecuted, LevelStandard) {
		t.Error("standard should log at standard level")
	}
	if !logger.ShouldLog(CommandExecuted, LevelMinimal) {
		t.Error("minimal should log at standard level")
	}
	if logger.ShouldLog(CommandExecuted, LevelVerbose) {
		t.Error("verbose should not log at standard level")
	}
}

func TestLoggerAddFileWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	logger := NewLogger(10, LevelStandard, 4096)
	err := logger.AddFileWriter(path)
	if err != nil {
		t.Fatalf("AddFileWriter: %v", err)
	}
	logger.Start()
	logger.Log(Event{EventType: "test", Action: "allow"})
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("audit file should have content")
	}
}

func TestLoggerAddFileWriterInvalidPath(t *testing.T) {
	logger := NewLogger(10, LevelStandard, 4096)
	err := logger.AddFileWriter("Z:\\nonexistent_drive_xyz\\dir\\file.jsonl")
	if err == nil {
		t.Error("should fail for invalid path")
	}
}

func TestQueryRecorder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queries.jsonl")

	recorder, err := NewQueryRecorder(path)
	if err != nil {
		t.Fatalf("NewQueryRecorder: %v", err)
	}
	if !recorder.Enabled() {
		t.Error("should be enabled")
	}

	recorder.Record(QueryRecord{
		Timestamp:   time.Now(),
		SessionID:   "s1",
		Username:    "alice",
		SQL:         "SELECT 1",
		CommandType: "SELECT",
	})

	recorder.Close()
	if recorder.Enabled() {
		t.Error("should be disabled after close")
	}

	// Verify file content
	data, _ := os.ReadFile(path)
	if len(data) == 0 {
		t.Error("query record file should have content")
	}

	var rec QueryRecord
	json.Unmarshal(data, &rec)
	if rec.Username != "alice" {
		t.Errorf("username = %q", rec.Username)
	}
}

func TestQueryRecorderInvalidPath(t *testing.T) {
	_, err := NewQueryRecorder("Z:\\nonexistent_drive_xyz\\dir\\queries.jsonl")
	if err == nil {
		t.Error("should fail for invalid path")
	}
}

func TestQueryRecorderDisabled(t *testing.T) {
	dir := t.TempDir()
	recorder, _ := NewQueryRecorder(filepath.Join(dir, "q.jsonl"))
	recorder.Close()
	// Record after close should be no-op
	recorder.Record(QueryRecord{SQL: "SELECT 1"})
}

func TestLoggerDoubleClose(t *testing.T) {
	logger := NewLogger(10, LevelStandard, 4096)
	logger.Start()
	logger.Close()
	logger.Close() // should not panic
}

func TestLoggerLogAfterClose(t *testing.T) {
	logger := NewLogger(10, LevelStandard, 4096)
	logger.Start()
	logger.Close()
	// Should not panic
	logger.Log(Event{EventType: "test", Action: "allow"})
}
