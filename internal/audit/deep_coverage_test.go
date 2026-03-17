package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- ExportCSV edge cases ---

func TestExportCSVWithUsernameFilter(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.jsonl")

	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(Event{Timestamp: time.Now(), EventType: "cmd", Username: "alice", Action: "allow"})
	enc.Encode(Event{Timestamp: time.Now(), EventType: "cmd", Username: "bob", Action: "block"})
	enc.Encode(Event{Timestamp: time.Now(), EventType: "cmd", Username: "alice", Action: "allow"})
	f.Close()

	var buf bytes.Buffer
	count, err := ExportCSV(logFile, &buf, SearchFilter{Username: "alice"})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestExportCSVWithLimit(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.jsonl")

	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	for range 10 {
		enc.Encode(Event{Timestamp: time.Now(), EventType: "test", Username: "u"})
	}
	f.Close()

	var buf bytes.Buffer
	count, err := ExportCSV(logFile, &buf, SearchFilter{Limit: 3})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestExportCSVBadFile(t *testing.T) {
	var buf bytes.Buffer
	_, err := ExportCSV("/nonexistent/file.jsonl", &buf, SearchFilter{})
	if err == nil {
		t.Error("bad file should fail")
	}
}

// --- SearchFile edge cases ---

func TestSearchFileTimeRange(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.jsonl")

	now := time.Now()
	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(Event{Timestamp: now.Add(-2 * time.Hour), EventType: "old", Username: "u"})
	enc.Encode(Event{Timestamp: now, EventType: "current", Username: "u"})
	enc.Encode(Event{Timestamp: now.Add(2 * time.Hour), EventType: "future", Username: "u"})
	f.Close()

	results, err := SearchFile(logFile, SearchFilter{
		StartTime: now.Add(-time.Hour),
		EndTime:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if len(results.Events) != 1 {
		t.Errorf("events = %d, want 1", len(results.Events))
	}
}

func TestSearchFileBadFile(t *testing.T) {
	_, err := SearchFile("/nonexistent/file.jsonl", SearchFilter{})
	if err == nil {
		t.Error("bad file should fail")
	}
}

func TestSearchFileWithDatabaseFilter(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.jsonl")

	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(Event{Timestamp: time.Now(), EventType: "cmd", Username: "u", Database: "prod"})
	enc.Encode(Event{Timestamp: time.Now(), EventType: "cmd", Username: "u", Database: "dev"})
	f.Close()

	results, err := SearchFile(logFile, SearchFilter{Database: "prod"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if len(results.Events) != 1 {
		t.Errorf("events = %d, want 1", len(results.Events))
	}
}

func TestSearchFileWithEventTypeFilter(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.jsonl")

	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(Event{Timestamp: time.Now(), EventType: "command_executed", Username: "u"})
	enc.Encode(Event{Timestamp: time.Now(), EventType: "auth_success", Username: "u"})
	enc.Encode(Event{Timestamp: time.Now(), EventType: "command_executed", Username: "u"})
	f.Close()

	results, err := SearchFile(logFile, SearchFilter{EventType: "command_executed"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if len(results.Events) != 2 {
		t.Errorf("events = %d, want 2", len(results.Events))
	}
}

// --- CompactLogs ---

func TestCompactLogsBasic(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some log files
	for i := range 3 {
		name := filepath.Join(tmpDir, "audit-"+time.Now().Add(time.Duration(-i)*24*time.Hour).Format("2006-01-02")+".jsonl")
		os.WriteFile(name, []byte(`{"event_type":"test"}`+"\n"), 0644)
	}

	result, err := CompactLogs(tmpDir, CompactionConfig{MaxAge: time.Hour, MaxFiles: 10})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	if result.ScannedFiles == 0 {
		t.Error("should scan files")
	}
}

func TestCompactLogsBadDir(t *testing.T) {
	_, err := CompactLogs("/nonexistent/dir", CompactionConfig{})
	if err == nil {
		t.Error("bad dir should fail")
	}
}

func TestCompactLogsDryRunOldFile(t *testing.T) {
	tmpDir := t.TempDir()

	name := filepath.Join(tmpDir, "old.jsonl")
	os.WriteFile(name, []byte(`{"event_type":"test"}`+"\n"), 0644)
	// Make file appear old by setting mod time
	os.Chtimes(name, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))

	result, err := CompactLogs(tmpDir, CompactionConfig{MaxAge: time.Hour, DryRun: true})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	_ = result
}
