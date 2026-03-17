package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReplayFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queries.jsonl")

	// Write test query records
	f, _ := os.Create(path)
	records := []QueryRecord{
		{Timestamp: time.Now().Add(-2 * time.Minute), SessionID: "sess-1", Username: "alice", Database: "prod", SQL: "SELECT * FROM users", CommandType: "SELECT", Duration: 1500, RowCount: 42, Action: "allow", Fingerprint: "fp1"},
		{Timestamp: time.Now().Add(-1 * time.Minute), SessionID: "sess-1", Username: "alice", Database: "prod", SQL: "UPDATE users SET name = 'Bob' WHERE id = 1", CommandType: "UPDATE", Duration: 800, RowCount: 1, Action: "allow", Fingerprint: "fp2"},
		{Timestamp: time.Now(), SessionID: "sess-2", Username: "bob", Database: "staging", SQL: "SELECT 1", CommandType: "SELECT", Duration: 100, RowCount: 1, Action: "allow", Fingerprint: "fp3"},
	}
	enc := json.NewEncoder(f)
	for _, r := range records {
		enc.Encode(r)
	}
	f.Close()

	// Replay session 1
	replay, err := ReplayFromFile(path, "sess-1")
	if err != nil {
		t.Fatalf("ReplayFromFile: %v", err)
	}

	if replay.Username != "alice" {
		t.Errorf("username = %q, want alice", replay.Username)
	}
	if len(replay.Queries) != 2 {
		t.Errorf("queries = %d, want 2", len(replay.Queries))
	}
	if replay.Queries[0].SQL != "SELECT * FROM users" {
		t.Errorf("first query = %q", replay.Queries[0].SQL)
	}

	// Replay nonexistent session
	replay2, err := ReplayFromFile(path, "nonexistent")
	if err != nil {
		t.Fatalf("ReplayFromFile: %v", err)
	}
	if len(replay2.Queries) != 0 {
		t.Error("nonexistent session should have 0 queries")
	}
}

func TestTopFingerprints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queries.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	// 5 SELECTs, 2 INSERTs
	for i := 0; i < 5; i++ {
		enc.Encode(QueryRecord{Fingerprint: "fp-select", SQL: "SELECT * FROM users WHERE id = ?", CommandType: "SELECT", Duration: 100, RowCount: 1})
	}
	for i := 0; i < 2; i++ {
		enc.Encode(QueryRecord{Fingerprint: "fp-insert", SQL: "INSERT INTO logs (msg) VALUES (?)", CommandType: "INSERT", Duration: 50, RowCount: 0})
	}
	f.Close()

	top, err := TopFingerprints(path, 10)
	if err != nil {
		t.Fatalf("TopFingerprints: %v", err)
	}
	if len(top) != 2 {
		t.Fatalf("got %d fingerprints, want 2", len(top))
	}
	if top[0].Fingerprint != "fp-select" {
		t.Error("most common should be fp-select")
	}
	if top[0].Count != 5 {
		t.Errorf("count = %d, want 5", top[0].Count)
	}
	if top[0].AvgDurationUS != 100 {
		t.Errorf("avg duration = %d, want 100", top[0].AvgDurationUS)
	}
}

func TestTopFingerprintsLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queries.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	for i := 0; i < 10; i++ {
		enc.Encode(QueryRecord{Fingerprint: "fp-" + string(rune('a'+i)), SQL: "SELECT ?", CommandType: "SELECT"})
	}
	f.Close()

	top, _ := TopFingerprints(path, 3)
	if len(top) != 3 {
		t.Errorf("limited to 3, got %d", len(top))
	}
}
