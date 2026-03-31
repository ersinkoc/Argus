package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	_, err := CompactLogs("Z:\\nonexistent_drive_xyz\\dir", CompactionConfig{})
	if err == nil {
		t.Error("bad dir should fail")
	}
}

func TestCompactLogsDryRunOldFile(t *testing.T) {
	tmpDir := t.TempDir()

	name := filepath.Join(tmpDir, "old.jsonl")
	os.WriteFile(name, []byte(`{"event_type":"test"}`+"\n"), 0644)
	os.Chtimes(name, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))

	result, err := CompactLogs(tmpDir, CompactionConfig{MaxAge: time.Hour, DryRun: true})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	_ = result
}

// --- WebhookWriter ---

func TestWebhookWriterFlush(t *testing.T) {
	received := make(chan []byte, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		received <- buf.Bytes()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	w := NewWebhookWriter(WebhookConfig{
		URL:        ts.URL,
		BatchSize:  10,
		FlushEvery: 50 * time.Millisecond,
		Timeout:    time.Second,
		Headers:    map[string]string{"X-Test": "1"},
	})
	w.Start()

	eventJSON, _ := json.Marshal(Event{EventType: "test", Username: "u"})
	w.Write(eventJSON)

	select {
	case data := <-received:
		if len(data) == 0 {
			t.Error("should receive event data")
		}
	case <-time.After(2 * time.Second):
		t.Error("flush timeout")
	}

	w.Stop()
}

func TestWebhookWriterBatchFull(t *testing.T) {
	received := make(chan []byte, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		received <- buf.Bytes()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	w := NewWebhookWriter(WebhookConfig{
		URL:        ts.URL,
		BatchSize:  2,
		FlushEvery: time.Hour,
		Timeout:    time.Second,
	})
	w.Start()

	e1, _ := json.Marshal(Event{EventType: "e1"})
	e2, _ := json.Marshal(Event{EventType: "e2"})
	w.Write(e1)
	w.Write(e2)

	select {
	case data := <-received:
		if len(data) == 0 {
			t.Error("should receive batched events")
		}
	case <-time.After(2 * time.Second):
		t.Error("batch flush timeout")
	}

	w.Stop()
}

func TestWebhookWriterBadURL(t *testing.T) {
	w := NewWebhookWriter(WebhookConfig{
		URL:        "http://127.0.0.1:1/nonexistent",
		BatchSize:  1,
		FlushEvery: 50 * time.Millisecond,
		Timeout:    100 * time.Millisecond,
	})
	w.Start()
	eventJSON, _ := json.Marshal(Event{EventType: "test"})
	w.Write(eventJSON)
	time.Sleep(200 * time.Millisecond)
	w.Stop()
}

// --- RotatingWriter ---

func TestRotatingWriterWrite(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	w, err := NewRotatingWriter(logPath, 1, 5)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	data := []byte(`{"event":"test"}` + "\n")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("wrote %d bytes", n)
	}
}

func TestRotatingWriterLargeWrite(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	w, err := NewRotatingWriter(logPath, 1, 5) // 1MB max, 5 files
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	bigData := make([]byte, 512*1024) // 512KB
	w.Write(bigData)
	w.Write(bigData) // should trigger rotation
}

// --- Logger writeLoop overflow ---

func TestLoggerWriteLoopOverflow(t *testing.T) {
	logger := NewLogger(2, LevelVerbose, 4096)
	logger.Start()

	for range 100 {
		logger.Log(Event{EventType: "flood", Username: "u"})
	}

	time.Sleep(100 * time.Millisecond)
	logger.Close()
}
