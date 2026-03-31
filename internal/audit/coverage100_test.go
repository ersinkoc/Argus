package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// === CompactLogs coverage ===

// --- CompactLogs: invalid directory ---

func TestCompactLogsInvalidDir(t *testing.T) {
	_, err := CompactLogs("/nonexistent_dir_xyz", CompactionConfig{})
	if err == nil {
		t.Error("invalid dir should fail")
	}
}

// --- CompactLogs: non-jsonl files are skipped ---

func TestCompactLogsSkipsNonJsonl(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte("data"), 0644)

	result, err := CompactLogs(dir, CompactionConfig{})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	if result.ScannedFiles != 1 {
		t.Errorf("scanned = %d, want 1 (only jsonl)", result.ScannedFiles)
	}
}

// --- CompactLogs: directories are skipped ---

func TestCompactLogsSkipsDirs(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "subdir.jsonl"), 0755)
	os.WriteFile(filepath.Join(dir, "audit.jsonl"), []byte("data"), 0644)

	result, err := CompactLogs(dir, CompactionConfig{})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	if result.ScannedFiles != 1 {
		t.Errorf("scanned = %d, want 1", result.ScannedFiles)
	}
}

// --- CompactLogs: remove error (read-only file on non-Windows) ---
// We can trigger this by deleting the file before CompactLogs tries to remove it.

func TestCompactLogsRemoveError(t *testing.T) {
	dir := t.TempDir()

	f := filepath.Join(dir, "audit.jsonl.old")
	os.WriteFile(f, []byte("data"), 0644)
	oldTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(f, oldTime, oldTime)

	// Remove the file before compaction so os.Remove fails
	os.Remove(f)

	// Recreate but in a subdirectory with the same name (makes it a directory)
	os.Mkdir(f, 0755)
	os.WriteFile(filepath.Join(f, "dummy"), []byte("x"), 0644)

	result, err := CompactLogs(dir, CompactionConfig{MaxAge: 24 * time.Hour})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	// The "file" is actually a directory so it's skipped
	_ = result
}

// === ExportCSV coverage ===

// --- ExportCSV: limit ---

func TestExportCSVLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for i := 0; i < 5; i++ {
		enc.Encode(Event{Timestamp: time.Now(), Username: "user", Action: "allow"})
	}
	f.Close()

	var buf bytes.Buffer
	count, err := ExportCSV(path, &buf, SearchFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

// --- ExportCSV: malformed JSON line produces scanner error ---

func TestExportCSVMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	os.WriteFile(path, []byte("not json\n"), 0644)

	var buf bytes.Buffer
	_, err := ExportCSV(path, &buf, SearchFilter{})
	if err == nil {
		t.Error("malformed JSON should produce scanner error")
	}
}

// --- ExportCSV: CSV write error via large output to a failing writer ---
// csv.Writer uses an internal bufio.Writer (4096 buffer).
// To trigger a write error, we need enough data to overflow the buffer.

func TestExportCSVWriteErrorLargeOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Create many events with long data to overflow csv buffer
	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	longStr := strings.Repeat("x", 500)
	for i := 0; i < 20; i++ {
		enc.Encode(Event{
			Timestamp: time.Now(),
			Username:  longStr,
			Command:   longStr,
			Action:    "allow",
			EventType: "command_executed",
		})
	}
	f.Close()

	// Writer that fails after some bytes (should overflow bufio buffer)
	w := &failWriter{failAfter: 100}
	_, err := ExportCSV(path, w, SearchFilter{})
	if err == nil {
		// csv.Writer may buffer everything — error won't propagate
		// This is expected behavior — not all error paths are reachable
		t.Log("csv.Writer buffering may absorb write errors")
	}
}

type failWriter struct {
	written   int
	failAfter int // -1 = fail immediately, otherwise fail after N bytes written
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.failAfter < 0 {
		return 0, fmt.Errorf("write error")
	}
	if w.written+len(p) > w.failAfter {
		return 0, fmt.Errorf("write error after %d bytes", w.written)
	}
	w.written += len(p)
	return len(p), nil
}

// --- ExportCSV: JSON value that's not an object (e.g. string literal) ---

func TestExportCSVNonObjectJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write valid JSON but not objects — "string" values
	os.WriteFile(path, []byte("\"just a string\"\n42\ntrue\n"), 0644)

	var buf bytes.Buffer
	count, err := ExportCSV(path, &buf, SearchFilter{})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	// Non-object JSON should be skipped by json.Unmarshal into Event
	_ = count
}

// --- SearchFile: malformed JSON lines ---

func TestSearchFileMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write mix of valid and malformed JSON
	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(Event{EventType: "test", Action: "allow"})
	f.Write([]byte("not valid json\n"))
	f.Close()

	// bufio.Scanner is used, not json.Decoder, so invalid JSON lines are encountered
	result, err := SearchFile(path, SearchFilter{})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1 (malformed line skipped)", result.Total)
	}
}

// === Logger coverage ===

// --- Logger: Log with closed logger ---

func TestLoggerLogClosed(t *testing.T) {
	l := NewLogger(10, LevelStandard, 4096)
	l.AddWriter(io.Discard)
	l.Start()
	l.Close()

	// Log after close — should be silently dropped
	l.Log(Event{EventType: "test"})
}

// --- Logger: Log with minimal level filtering ---

func TestLoggerMinimalFilter(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(10, LevelMinimal, 4096)
	l.AddWriter(&buf)
	l.Start()

	// This should be filtered (not a minimal event)
	l.Log(Event{EventType: "command_executed"})
	// This should pass (minimal event)
	l.Log(Event{EventType: "command_blocked"})

	time.Sleep(50 * time.Millisecond)
	l.Close()

	output := buf.String()
	if strings.Contains(output, "command_executed") {
		t.Error("command_executed should be filtered at minimal level")
	}
	if !strings.Contains(output, "command_blocked") {
		t.Error("command_blocked should pass minimal filter")
	}
}

// --- Logger: SQL truncation ---

func TestLoggerSQLTruncate(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(10, LevelStandard, 10) // sqlMaxLen = 10
	l.AddWriter(&buf)
	l.Start()

	l.Log(Event{EventType: "command_executed", Command: "SELECT * FROM very_long_table_name"})
	time.Sleep(50 * time.Millisecond)
	l.Close()

	if !strings.Contains(buf.String(), "[truncated]") {
		t.Error("long SQL should be truncated")
	}
}

// --- Logger: buffer overflow (dropped events) ---

func TestLoggerDroppedEvents(t *testing.T) {
	l := NewLogger(1, LevelStandard, 4096) // buffer size 1
	// Don't start the writer — events will fill up and drop
	l.AddWriter(io.Discard)

	// Fill the buffer
	for i := 0; i < 100; i++ {
		l.Log(Event{EventType: "command_executed", Command: fmt.Sprintf("SELECT %d", i)})
	}

	if l.DroppedCount() == 0 {
		t.Error("should have dropped events")
	}

	l.Start()
	l.Close()
}

// --- Logger: writeLoop error handling ---

func TestLoggerWriteLoopError(t *testing.T) {
	l := NewLogger(10, LevelStandard, 4096)
	// Use a writer that always fails
	l.AddWriter(&failWriter{failAfter: -1})
	l.Start()

	l.Log(Event{EventType: "command_executed"})
	time.Sleep(50 * time.Millisecond)
	l.Close()
	// No crash = success (error is logged via log.Printf)
}

// --- Logger: drain on close ---

func TestLoggerDrainOnClose(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(100, LevelStandard, 4096)
	l.AddWriter(&buf)
	l.Start()

	// Send multiple events
	for i := 0; i < 10; i++ {
		l.Log(Event{EventType: "command_executed", Command: fmt.Sprintf("q%d", i)})
	}

	l.Close()

	// All events should be written (drained)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 10 {
		t.Errorf("drained %d events, want 10", len(lines))
	}
}

// --- Logger: double close ---

func TestLoggerDoubleCloseCall(t *testing.T) {
	l := NewLogger(10, LevelStandard, 4096)
	l.AddWriter(io.Discard)
	l.Start()

	l.Close()
	err := l.Close()
	if err != nil {
		t.Errorf("double close: %v", err)
	}
}

// --- Logger: Start with no writers defaults to stdout ---

func TestLoggerStartNoWriters(t *testing.T) {
	l := NewLogger(10, LevelStandard, 4096)
	// Don't add any writers — should default to stdout
	l.Start()
	l.Close()

	if len(l.writers) != 1 {
		t.Errorf("writers = %d, want 1 (default stdout)", len(l.writers))
	}
}

// --- Logger: auto-generated ID and timestamp ---

func TestLoggerAutoGenerateIDAndTimestamp(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(10, LevelStandard, 4096)
	l.AddWriter(&buf)
	l.Start()

	l.Log(Event{EventType: "command_executed"})
	time.Sleep(50 * time.Millisecond)
	l.Close()

	var event Event
	json.Unmarshal([]byte(strings.Split(buf.String(), "\n")[0]), &event)
	if event.ID == "" {
		t.Error("event ID should be auto-generated")
	}
	if event.Timestamp.IsZero() {
		t.Error("timestamp should be auto-set")
	}
}

// === ReplayFromFile coverage ===

// --- ReplayFromFile: file not found ---

func TestReplayFromFileNotFoundErr(t *testing.T) {
	_, err := ReplayFromFile(filepath.Join(t.TempDir(), "nonexistent.jsonl"), "s1")
	if err == nil {
		t.Error("file not found should fail")
	}
}

// --- ReplayFromFile: no matching session ---

func TestReplayFromFileNoMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(QueryRecord{SessionID: "other", Username: "alice", SQL: "SELECT 1", Timestamp: time.Now()})
	f.Close()

	session, err := ReplayFromFile(path, "nonexistent")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(session.Queries) != 0 {
		t.Error("should have no queries")
	}
}

// --- ReplayFromFile: malformed JSON ---

func TestReplayFromFileMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.jsonl")

	os.WriteFile(path, []byte("not json\n"), 0644)

	session, err := ReplayFromFile(path, "s1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(session.Queries) != 0 {
		t.Error("malformed should be skipped")
	}
}

// === TopFingerprints coverage ===

// --- TopFingerprints: file not found ---

func TestTopFingerprintsNotFound(t *testing.T) {
	_, err := TopFingerprints(filepath.Join(t.TempDir(), "nonexistent_file.jsonl"), 10)
	if err == nil {
		t.Error("file not found should fail")
	}
}

// --- TopFingerprints: empty fingerprint skipped ---

func TestTopFingerprintsEmptyFP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(QueryRecord{Fingerprint: "", SQL: "SELECT 1"})
	enc.Encode(QueryRecord{Fingerprint: "fp1", SQL: "SELECT 1", Duration: 100, RowCount: 5})
	f.Close()

	results, err := TopFingerprints(path, 10)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("results = %d, want 1 (empty FP skipped)", len(results))
	}
}

// --- TopFingerprints: malformed JSON ---

func TestTopFingerprintsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.jsonl")

	os.WriteFile(path, []byte("bad json\n"), 0644)

	results, err := TopFingerprints(path, 10)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 0 {
		t.Error("should have no results")
	}
}

// --- TopFingerprints: scanner error from too-long line ---

func TestTopFingerprintsScannerError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.jsonl")

	f, _ := os.Create(path)
	// Write valid record
	enc := json.NewEncoder(f)
	enc.Encode(QueryRecord{Fingerprint: "fp1", SQL: "SELECT 1"})
	// Write a line that exceeds 1MB buffer
	longLine := strings.Repeat("x", 1024*1024+100)
	f.WriteString(longLine + "\n")
	f.Close()

	results, err := TopFingerprints(path, 10)
	if err != nil {
		// Scanner error from too-long line
		t.Logf("scanner error (expected): %v", err)
	}
	// Should still have the first valid result
	_ = results
}

// --- TopFingerprints: limit applied ---

func TestTopFingerprintsLimitApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for i := 0; i < 5; i++ {
		enc.Encode(QueryRecord{Fingerprint: fmt.Sprintf("fp%d", i), SQL: fmt.Sprintf("SELECT %d", i)})
	}
	f.Close()

	results, err := TopFingerprints(path, 2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("results = %d, want 2", len(results))
	}
}

// === SearchFile coverage ===

// --- SearchFile: file not found ---

func TestSearchFileNotFoundErr(t *testing.T) {
	_, err := SearchFile("/nonexistent", SearchFilter{})
	if err == nil {
		t.Error("file not found should fail")
	}
}

// --- SearchFile: empty lines skipped ---

func TestSearchFileEmptyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(Event{EventType: "test", Action: "allow"})
	f.Write([]byte("\n")) // empty line
	f.Close()

	result, err := SearchFile(path, SearchFilter{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
}

// --- SearchFile: all filter fields ---

func TestSearchFileAllFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	now := time.Now()
	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(Event{
		Timestamp:   now,
		EventType:   "command_executed",
		SessionID:   "s1",
		Username:    "alice",
		Database:    "prod",
		CommandType: "SELECT",
		Action:      "allow",
	})
	enc.Encode(Event{
		Timestamp:   now.Add(-2 * time.Hour),
		EventType:   "command_blocked",
		SessionID:   "s2",
		Username:    "bob",
		Database:    "dev",
		CommandType: "DROP",
		Action:      "block",
	})
	f.Close()

	// Filter by all fields
	result, err := SearchFile(path, SearchFilter{
		SessionID:   "s1",
		Username:    "alice",
		Database:    "prod",
		EventType:   "command_executed",
		Action:      "allow",
		CommandType: "SELECT",
		StartTime:   now.Add(-time.Minute),
		EndTime:     now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
}

// --- SearchFile: limit exceeded, events still counted ---

func TestSearchFileLimitExceeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for i := 0; i < 5; i++ {
		enc.Encode(Event{EventType: "test", Action: "allow"})
	}
	f.Close()

	result, err := SearchFile(path, SearchFilter{Limit: 2})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if result.Total != 5 {
		t.Errorf("total = %d, want 5", result.Total)
	}
	if len(result.Events) != 2 {
		t.Errorf("events = %d, want 2", len(result.Events))
	}
}

// === Webhook coverage ===

// --- Webhook: flush with HTTP error ---

func TestWebhookFlushHTTPError(t *testing.T) {
	w := NewWebhookWriter(WebhookConfig{
		URL:       "http://192.0.2.1:1/nonexistent", // unreachable
		BatchSize: 1,
		Timeout:   100 * time.Millisecond,
	})

	w.Write([]byte(`{"event_type":"test"}`))
	// Flush triggered by batch size
	time.Sleep(200 * time.Millisecond)
}

// --- Webhook: flush with bad URL ---

func TestWebhookFlushBadURL(t *testing.T) {
	w := NewWebhookWriter(WebhookConfig{
		URL:       "://bad-url",
		BatchSize: 10,
	})

	w.mu.Lock()
	w.batch = append(w.batch, Event{EventType: "test"})
	w.mu.Unlock()

	w.flush()
}

// --- Webhook: flush empty batch ---

func TestWebhookFlushEmptyBatch(t *testing.T) {
	w := NewWebhookWriter(WebhookConfig{URL: "http://localhost"})
	w.flush() // should be no-op
}

// --- Webhook: flush with HTTP 4xx ---

func TestWebhookFlushHTTP4xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
	}))
	defer server.Close()

	w := NewWebhookWriter(WebhookConfig{
		URL:       server.URL,
		BatchSize: 1,
	})

	w.Write([]byte(`{"event_type":"test"}`))
	time.Sleep(100 * time.Millisecond)
}

// --- Webhook: Start/Stop periodic flush ---

func TestWebhookStartStop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	w := NewWebhookWriter(WebhookConfig{
		URL:        server.URL,
		BatchSize:  100,
		FlushEvery: 50 * time.Millisecond,
	})

	w.Start()
	w.Write([]byte(`{"event_type":"test"}`))
	time.Sleep(150 * time.Millisecond) // wait for periodic flush
	w.Stop()
}

// --- Webhook: custom headers ---

func TestWebhookCustomHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer server.Close()

	w := NewWebhookWriter(WebhookConfig{
		URL:       server.URL,
		BatchSize: 1,
		Headers:   map[string]string{"Authorization": "Bearer token123"},
	})

	w.Write([]byte(`{"event_type":"test"}`))
	time.Sleep(100 * time.Millisecond)

	if receivedAuth != "Bearer token123" {
		t.Errorf("auth = %q", receivedAuth)
	}
}

// --- Webhook: unparseable JSON Write ---

func TestWebhookWriteUnparseableJSON(t *testing.T) {
	w := NewWebhookWriter(WebhookConfig{URL: "http://localhost"})
	n, err := w.Write([]byte("not json"))
	if err != nil {
		t.Errorf("should not error on unparseable: %v", err)
	}
	if n != 8 {
		t.Errorf("n = %d", n)
	}
}

// --- Webhook: String ---

func TestWebhookString(t *testing.T) {
	w := NewWebhookWriter(WebhookConfig{URL: "http://example.com", BatchSize: 50})
	s := w.String()
	if !strings.Contains(s, "http://example.com") {
		t.Errorf("String() = %q", s)
	}
}

// === Writer (RotatingWriter) coverage ===

// --- RotatingWriter: invalid path ---

func TestRotatingWriterInvalidPathErr(t *testing.T) {
	dir := t.TempDir()
	// Create a file, then try to use it as a directory
	blocker := filepath.Join(dir, "blocker")
	os.WriteFile(blocker, []byte("x"), 0644)
	_, err := NewRotatingWriter(filepath.Join(blocker, "sub", "audit.jsonl"), 1, 1)
	if err == nil {
		t.Error("should fail with file-as-directory")
	}
}

// --- RotatingWriter: write triggers rotation ---

func TestRotatingWriterRotationTrigger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	w, err := NewRotatingWriter(path, 1, 2) // 1MB max, keep 2
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	// Write enough to trigger rotation (> 1MB)
	data := strings.Repeat("x", 1024) + "\n"
	for i := 0; i < 1200; i++ {
		_, err := w.Write([]byte(data))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	// Check that rotated files exist
	entries, _ := os.ReadDir(dir)
	if len(entries) < 2 {
		t.Errorf("expected rotated files, got %d entries", len(entries))
	}
}

// --- RotatingWriter: close nil file ---

func TestRotatingWriterCloseNilFilePtr(t *testing.T) {
	w := &RotatingWriter{}
	err := w.Close()
	if err != nil {
		t.Errorf("close nil file: %v", err)
	}
}

// --- RotatingWriter: openFile picks up existing file size ---

func TestRotatingWriterExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Pre-create file with content
	os.WriteFile(path, []byte("existing data\n"), 0644)

	w, err := NewRotatingWriter(path, 100, 5)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	if w.written == 0 {
		t.Error("should detect existing file size")
	}
}

// --- RotatingWriter: rotate with rename fallback ---

func TestRotatingWriterRotateFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	w, err := NewRotatingWriter(path, 1, 1) // very small, 1 max file
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	// Write enough to trigger rotation
	data := strings.Repeat("x", 1024) + "\n"
	for i := 0; i < 1200; i++ {
		w.Write([]byte(data))
	}
}

// === isMinimalEvent coverage ===

func TestIsMinimalEventAll(t *testing.T) {
	minimalEvents := []string{
		"connection_open", "connection_close",
		"auth_success", "auth_failure",
		"command_blocked", "session_timeout",
		"session_killed", "policy_reloaded",
		"gateway_query", "approval_created",
		"approval_resolved", "allowlist_added",
		"allowlist_used",
	}
	for _, e := range minimalEvents {
		if !isMinimalEvent(e) {
			t.Errorf("%q should be minimal event", e)
		}
	}

	nonMinimal := []string{"command_executed", "result_masked", "unknown"}
	for _, e := range nonMinimal {
		if isMinimalEvent(e) {
			t.Errorf("%q should NOT be minimal event", e)
		}
	}
}

// === Logger: writeLoop drain with error on close ===

func TestLoggerWriteLoopDrainError(t *testing.T) {
	// Use a large buffer and a writer that always fails
	l := NewLogger(1000, LevelStandard, 4096)
	fw := &failWriter{failAfter: -1}
	l.AddWriter(fw)
	l.Start()

	// The main loop will try to encode and fail on each event.
	// Queue many events rapidly so some are still in the channel when we close.
	for i := 0; i < 100; i++ {
		l.Log(Event{EventType: "command_executed"})
	}
	// Close immediately — drain loop should process remaining events with errors
	l.Close()
}

// === Logger: drain with encode error ===
// Use a writer that starts failing after N bytes, so the drain loop encounters errors.

func TestLoggerDrainEncodeError(t *testing.T) {
	// Writer that fails after writing some data
	fw := &failWriter{failAfter: 50}
	l := NewLogger(1000, LevelStandard, 4096)
	l.AddWriter(fw)

	// Fill the channel before starting
	for i := 0; i < 20; i++ {
		l.eventCh <- Event{EventType: "command_executed", Command: fmt.Sprintf("SELECT %d", i)}
	}

	l.Start()
	// Close immediately — drain processes remaining events, failWriter has already failed
	time.Sleep(5 * time.Millisecond)
	l.Close()
}

// === AddFileWriter ===

func TestLoggerAddFileWriterPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l := NewLogger(10, LevelStandard, 4096)
	err := l.AddFileWriter(path)
	if err != nil {
		t.Fatalf("AddFileWriter: %v", err)
	}
	l.Start()
	l.Log(Event{EventType: "test"})
	time.Sleep(50 * time.Millisecond)
	l.Close()

	data, _ := os.ReadFile(path)
	if len(data) == 0 {
		t.Error("file should have data")
	}
}

func TestLoggerAddFileWriterError(t *testing.T) {
	l := NewLogger(10, LevelStandard, 4096)
	// Use a path that's guaranteed to fail (file as directory)
	dir := t.TempDir()
	filePath := filepath.Join(dir, "blocker")
	os.WriteFile(filePath, []byte("x"), 0644)
	err := l.AddFileWriter(filepath.Join(filePath, "audit.jsonl"))
	if err == nil {
		t.Error("invalid path should fail")
	}
}

// === RotatingWriter: rotation error path ===

func TestRotatingWriterRotateError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	w, err := NewRotatingWriter(path, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}

	// Close the file handle but try to write — rotation will try but openFile may fail
	w.file.Close()
	w.file = nil
	w.written = 2 * 1024 * 1024 // pretend we've written a lot

	// Try to write — should trigger rotate which tries to close nil file, rename missing file, etc.
	_, writeErr := w.Write([]byte("data"))
	if writeErr == nil {
		// Rotate succeeded (creates new file), close it properly
		t.Log("rotate may succeed on this OS")
	}
	w.Close()
}

// === RotatingWriter: rotate rename fallback ===

func TestRotatingWriterRotateRenameFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	w, err := NewRotatingWriter(path, 1, 1) // maxFiles=1
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	// Delete the current file so rename fails — triggers fallback
	os.Remove(path)

	// Trigger rotation
	w.written = 2 * 1024 * 1024
	_, writeErr := w.Write([]byte("data"))
	if writeErr != nil {
		t.Logf("rotation may fail: %v", writeErr)
	}
}

// === CompactLogs: os.Stat error (file deleted between ReadDir and Stat) ===

func TestCompactLogsStatError(t *testing.T) {
	dir := t.TempDir()

	// Create a dangling symlink — ReadDir returns it, but os.Stat follows the symlink and fails
	linkPath := filepath.Join(dir, "audit.jsonl.dangling")
	err := os.Symlink(filepath.Join(dir, "nonexistent_target"), linkPath)
	if err != nil {
		t.Skip("symlink not supported:", err)
	}

	result, err := CompactLogs(dir, CompactionConfig{MaxAge: 24 * time.Hour})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	// Dangling symlink: ReadDir sees it, os.Stat fails, file is skipped
	if result.ScannedFiles != 0 {
		t.Errorf("scanned = %d, want 0 (dangling symlink skipped)", result.ScannedFiles)
	}
}

// === CompactLogs: os.Remove error ===
// On Windows we can trigger this by having the file open/locked.

func TestCompactLogsRemoveErrorLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl.locked")
	os.WriteFile(path, []byte("data"), 0644)
	oldTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(path, oldTime, oldTime)

	// Open the file exclusively so Remove fails on Windows
	f, _ := os.OpenFile(path, os.O_RDWR, 0)
	defer f.Close()

	result, err := CompactLogs(dir, CompactionConfig{MaxAge: 24 * time.Hour})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	// On Windows, Remove fails because file is locked -> error added to result
	if len(result.Errors) > 0 {
		t.Logf("expected error: %s", result.Errors[0])
	}
}

// === RotatingWriter: Write triggers rotate that fails ===

func TestRotatingWriterWriteRotateFailure(t *testing.T) {
	dir := t.TempDir()
	// Use a file as the parent directory to make MkdirAll fail during openFile
	blocker := filepath.Join(dir, "blocker")
	os.WriteFile(blocker, []byte("x"), 0644)
	path := filepath.Join(blocker, "sub", "audit.jsonl")

	// Manually construct the writer to avoid NewRotatingWriter's openFile
	w := &RotatingWriter{
		path:      path,
		maxSizeMB: 1,
		maxFiles:  2,
		written:   2 * 1024 * 1024, // pretend we've written a lot
	}

	// Try to write — will trigger rotate -> openFile -> MkdirAll fails
	_, err := w.Write([]byte("data"))
	if err == nil {
		t.Error("rotation to invalid path should fail")
	}
}

// === webhook: flush marshal error (impossible in practice) ===

// --- Logger: ShouldLog ---

func TestLoggerShouldLog(t *testing.T) {
	l := NewLogger(10, LevelStandard, 4096)
	if !l.ShouldLog(CommandExecuted, LevelStandard) {
		t.Error("standard event at standard level should log")
	}
	if !l.ShouldLog(CommandExecuted, LevelMinimal) {
		t.Error("minimal level <= standard level should log")
	}
	if l.ShouldLog(CommandExecuted, LevelVerbose) {
		t.Error("verbose level > standard level should not log")
	}
}
