package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMatchesFilterAllFields(t *testing.T) {
	event := Event{
		SessionID:   "s1",
		Username:    "alice",
		Database:    "prod",
		EventType:   "command_executed",
		Action:      "allow",
		CommandType: "SELECT",
		Timestamp:   time.Now(),
	}

	// All match
	filter := SearchFilter{
		SessionID:   "s1",
		Username:    "alice",
		Database:    "prod",
		EventType:   "command_executed",
		Action:      "allow",
		CommandType: "SELECT",
	}
	if !matchesFilter(&event, &filter) {
		t.Error("all matching should pass")
	}

	// Session ID mismatch
	filter.SessionID = "other"
	if matchesFilter(&event, &filter) {
		t.Error("session mismatch should fail")
	}
}

func TestReplayFromFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(path, []byte{}, 0644)

	replay, err := ReplayFromFile(path, "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Queries) != 0 {
		t.Error("empty file should return 0 queries")
	}
}

func TestTopFingerprintsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(path, []byte{}, 0644)

	top, err := TopFingerprints(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 0 {
		t.Error("empty file should return 0 fingerprints")
	}
}

func TestTopFingerprintsNoFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nofp.jsonl")
	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(QueryRecord{SQL: "SELECT 1"}) // no fingerprint
	f.Close()

	top, _ := TopFingerprints(path, 10)
	if len(top) != 0 {
		t.Error("records without fingerprint should be skipped")
	}
}
