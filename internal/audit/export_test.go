package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(Event{
		Timestamp: time.Now(),
		EventType: "command_executed",
		SessionID: "s1",
		Username:  "alice",
		ClientIP:  "10.0.0.1",
		Database:  "prod",
		CommandType: "SELECT",
		Action:    "allow",
		RowCount:  42,
		Duration:  150 * time.Millisecond,
	})
	enc.Encode(Event{
		Timestamp: time.Now(),
		EventType: "command_blocked",
		SessionID: "s2",
		Username:  "bob",
		Action:    "block",
		Reason:    "DDL not allowed",
	})
	f.Close()

	var buf bytes.Buffer
	count, err := ExportCSV(path, &buf, SearchFilter{})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Header + 2 data rows
	if len(lines) != 3 {
		t.Errorf("lines = %d, want 3 (header + 2 rows)", len(lines))
	}

	// Header should contain expected columns
	if !strings.Contains(lines[0], "timestamp") {
		t.Error("header should contain timestamp")
	}
	if !strings.Contains(lines[0], "username") {
		t.Error("header should contain username")
	}
}

func TestExportCSVWithFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	f, _ := os.Create(path)
	enc := json.NewEncoder(f)
	enc.Encode(Event{Timestamp: time.Now(), Username: "alice", Action: "allow"})
	enc.Encode(Event{Timestamp: time.Now(), Username: "bob", Action: "block"})
	enc.Encode(Event{Timestamp: time.Now(), Username: "alice", Action: "allow"})
	f.Close()

	var buf bytes.Buffer
	count, err := ExportCSV(path, &buf, SearchFilter{Username: "alice"})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	if count != 2 {
		t.Errorf("count = %d, want 2 (only alice)", count)
	}
}

func TestExportCSVFileNotFound(t *testing.T) {
	var buf bytes.Buffer
	_, err := ExportCSV("/nonexistent", &buf, SearchFilter{})
	if err == nil {
		t.Error("should error on missing file")
	}
}
