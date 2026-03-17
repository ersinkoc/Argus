package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestWebhookWriter(t *testing.T) {
	var mu sync.Mutex
	var received []Event

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var events []Event
		json.Unmarshal(body, &events)
		mu.Lock()
		received = append(received, events...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wh := NewWebhookWriter(WebhookConfig{
		URL:        server.URL,
		BatchSize:  2,
		FlushEvery: 100 * time.Millisecond,
		Timeout:    5 * time.Second,
	})
	wh.Start()

	// Write 3 events — should trigger a flush at batch size 2
	for i := 0; i < 3; i++ {
		event := Event{
			EventType: "command_executed",
			Username:  "testuser",
			Action:    "allow",
		}
		data, _ := json.Marshal(event)
		data = append(data, '\n')
		wh.Write(data)
	}

	// Wait for periodic flush to pick up the remaining 1
	time.Sleep(300 * time.Millisecond)
	wh.Stop()

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count != 3 {
		t.Errorf("received %d events, want 3", count)
	}
}

func TestWebhookWriterInvalidJSON(t *testing.T) {
	wh := NewWebhookWriter(WebhookConfig{URL: "http://localhost:1/noop"})

	// Should not panic on invalid JSON
	n, err := wh.Write([]byte("not json"))
	if err != nil {
		t.Errorf("should not error on invalid JSON: %v", err)
	}
	if n != len("not json") {
		t.Errorf("n = %d, want %d", n, len("not json"))
	}
}

func TestWebhookWriterString(t *testing.T) {
	wh := NewWebhookWriter(WebhookConfig{URL: "http://example.com/audit"})
	s := wh.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
}
