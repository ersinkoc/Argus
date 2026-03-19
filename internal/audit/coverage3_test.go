package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSearchFile_LimitExceeded verifies that Total is incremented even when
// events are beyond the Limit (the line that counts but does not append).
func TestSearchFile_LimitExceeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for i := 0; i < 5; i++ {
		enc.Encode(Event{Timestamp: time.Now(), Username: "alice", Action: "allow"})
	}
	f.Close()

	// Limit=2 — 5 events match, only 2 returned but Total=5
	result, err := SearchFile(path, SearchFilter{Limit: 2})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if len(result.Events) != 2 {
		t.Errorf("events = %d, want 2", len(result.Events))
	}
	if result.Total != 5 {
		t.Errorf("total = %d, want 5", result.Total)
	}
}

// TestExportCSV_WithLimit exercises the Limit break path in ExportCSV.
func TestExportCSV_WithLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for i := 0; i < 4; i++ {
		enc.Encode(Event{Timestamp: time.Now(), Username: "alice", Action: "allow"})
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

// TestWriterRotation exercises the rotation path by writing past the max size.
func TestWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// maxSizeMB=1 (1 byte actually — use 0 which defaults to 100; use 1)
	// We need to trigger rotation: write > maxSizeMB bytes
	w, err := NewRotatingWriter(path, 1, 3) // 1MB max
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	// Write more than 1MB to trigger rotation
	data := make([]byte, 1024*1024+1)
	_, err = w.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
}

// TestRotatingWriter_NegativeSize ensures defaults kick in for invalid args.
func TestRotatingWriter_NegativeSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	w, err := NewRotatingWriter(path, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer w.Close()

	_, err = w.Write([]byte("test\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
}

// TestReplayFromFile_MultipleSessionIDs verifies non-matching sessions
// are skipped (exercises the sessionID filter branch).
func TestReplayFromFile_MultipleSessionIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queries.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(QueryRecord{SessionID: "s1", Username: "alice", Database: "db1", SQL: "SELECT 1"})
	enc.Encode(QueryRecord{SessionID: "s2", Username: "bob", Database: "db2", SQL: "SELECT 2"})
	enc.Encode(QueryRecord{SessionID: "s1", Username: "alice", Database: "db1", SQL: "SELECT 3"})
	f.Close()

	sess, err := ReplayFromFile(path, "s1")
	if err != nil {
		t.Fatalf("ReplayFromFile: %v", err)
	}
	if len(sess.Queries) != 2 {
		t.Errorf("queries = %d, want 2", len(sess.Queries))
	}
	if sess.Username != "alice" {
		t.Errorf("username = %q, want alice", sess.Username)
	}
}
