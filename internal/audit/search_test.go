package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSearchFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Write test events
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	events := []Event{
		{Timestamp: time.Now().Add(-1 * time.Hour), EventType: "command_executed", Username: "alice", Database: "prod", CommandType: "SELECT", Action: "allow"},
		{Timestamp: time.Now().Add(-30 * time.Minute), EventType: "command_blocked", Username: "bob", Database: "prod", CommandType: "DDL", Action: "block"},
		{Timestamp: time.Now().Add(-10 * time.Minute), EventType: "command_executed", Username: "alice", Database: "staging", CommandType: "INSERT", Action: "allow"},
		{Timestamp: time.Now(), EventType: "connection_close", Username: "bob", Database: "prod", Action: "close"},
	}

	enc := json.NewEncoder(f)
	for _, e := range events {
		enc.Encode(e)
	}
	f.Close()

	// Search by username
	result, err := SearchFile(path, SearchFilter{Username: "alice"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 2 {
		t.Errorf("alice events = %d, want 2", result.Total)
	}

	// Search by action
	result, err = SearchFile(path, SearchFilter{Action: "block"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("blocked events = %d, want 1", result.Total)
	}

	// Search by database
	result, err = SearchFile(path, SearchFilter{Database: "staging"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("staging events = %d, want 1", result.Total)
	}

	// Search with limit
	result, err = SearchFile(path, SearchFilter{Limit: 1})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if len(result.Events) != 1 {
		t.Errorf("limited events = %d, want 1", len(result.Events))
	}
	if result.Total != 4 {
		t.Errorf("total should still be 4, got %d", result.Total)
	}

	// Search by event type
	result, err = SearchFile(path, SearchFilter{EventType: "connection_close"})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("connection_close events = %d, want 1", result.Total)
	}
}

func TestSearchFileNotFound(t *testing.T) {
	_, err := SearchFile("/nonexistent/path", SearchFilter{})
	if err == nil {
		t.Error("should error on nonexistent file")
	}
}

func TestSearchFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(path, []byte{}, 0644)

	result, err := SearchFile(path, SearchFilter{})
	if err != nil {
		t.Fatalf("SearchFile: %v", err)
	}
	if result.Total != 0 {
		t.Errorf("total = %d, want 0", result.Total)
	}
}
