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

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		et   EventType
		want string
	}{
		{ConnectionOpen, "connection_open"},
		{ConnectionClose, "connection_close"},
		{AuthSuccess, "auth_success"},
		{AuthFailure, "auth_failure"},
		{CommandExecuted, "command_executed"},
		{CommandBlocked, "command_blocked"},
		{ResultMasked, "result_masked"},
		{PolicyReloaded, "policy_reloaded"},
	}
	for _, tt := range tests {
		if got := tt.et.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.et, got, tt.want)
		}
	}
}

func TestLogLevel(t *testing.T) {
	if ParseLogLevel("minimal") != LevelMinimal {
		t.Error("should parse minimal")
	}
	if ParseLogLevel("verbose") != LevelVerbose {
		t.Error("should parse verbose")
	}
	if ParseLogLevel("anything") != LevelStandard {
		t.Error("unknown should default to standard")
	}
}

func TestLoggerWritesEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(100, LevelStandard, 4096)
	logger.AddWriter(&buf)
	logger.Start()

	logger.Log(Event{
		EventType: ConnectionOpen.String(),
		SessionID: "test-session",
		Username:  "testuser",
		ClientIP:  "127.0.0.1",
		Action:    "allow",
	})

	// Give async writer time to process
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	output := buf.String()
	if output == "" {
		t.Fatal("expected output, got empty string")
	}

	var event Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &event); err != nil {
		t.Fatalf("failed to parse output as JSON: %v\noutput: %s", err, output)
	}

	if event.EventType != "connection_open" {
		t.Errorf("event_type = %q, want %q", event.EventType, "connection_open")
	}
	if event.Username != "testuser" {
		t.Errorf("username = %q, want %q", event.Username, "testuser")
	}
	if event.ID == "" {
		t.Error("event ID should be auto-generated")
	}
	if event.Hash == "" {
		t.Error("event hash should be populated")
	}
}

func TestVerifyChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger := NewLogger(10, LevelStandard, 4096)
	if err := logger.AddFileWriter(path); err != nil {
		t.Fatalf("AddFileWriter: %v", err)
	}
	logger.Start()
	logger.Log(Event{EventType: CommandExecuted.String(), Username: "alice", Action: "allow"})
	logger.Log(Event{EventType: CommandBlocked.String(), Username: "bob", Action: "block"})
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	if err := VerifyChain(path); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestVerifyChainDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger := NewLogger(10, LevelStandard, 4096)
	if err := logger.AddFileWriter(path); err != nil {
		t.Fatalf("AddFileWriter: %v", err)
	}
	logger.Start()
	logger.Log(Event{EventType: CommandExecuted.String(), Username: "alice", Action: "allow"})
	logger.Log(Event{EventType: CommandBlocked.String(), Username: "bob", Action: "block"})
	time.Sleep(50 * time.Millisecond)
	logger.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(data), "\"action\":\"block\"", "\"action\":\"allow\"", 1)
	if err := os.WriteFile(path, []byte(tampered), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := VerifyChain(path); err == nil {
		t.Fatal("VerifyChain should detect tampering")
	}
}

func TestLoggerSQLTruncation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(100, LevelStandard, 20)
	logger.AddWriter(&buf)
	logger.Start()

	logger.Log(Event{
		EventType: CommandExecuted.String(),
		Command:   "SELECT * FROM very_long_table_name_that_exceeds_limit",
		Action:    "allow",
	})

	time.Sleep(50 * time.Millisecond)
	logger.Close()

	var event Event
	json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &event)

	if !strings.HasSuffix(event.Command, "...[truncated]") {
		t.Errorf("long SQL should be truncated, got %q", event.Command)
	}
}

func TestLoggerDropsWhenFull(t *testing.T) {
	logger := NewLogger(1, LevelStandard, 4096)
	// Don't start the writer — channel will fill up

	for i := 0; i < 10; i++ {
		logger.Log(Event{
			EventType: CommandExecuted.String(),
			Action:    "allow",
		})
	}

	if logger.DroppedCount() == 0 {
		t.Error("should have dropped events when buffer is full")
	}

	logger.Close()
}
