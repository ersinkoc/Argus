package audit

import (
	"testing"
	"time"
)

func TestWebhookWriterDefaults(t *testing.T) {
	wh := NewWebhookWriter(WebhookConfig{URL: "http://example.com"})
	if wh.batchSize != 100 {
		t.Errorf("default batch = %d, want 100", wh.batchSize)
	}
	if wh.flushEvery != 5*time.Second {
		t.Errorf("default flush = %v, want 5s", wh.flushEvery)
	}
}

func TestWebhookWriterFlushEmpty(t *testing.T) {
	wh := NewWebhookWriter(WebhookConfig{URL: "http://localhost:1/noop"})
	wh.flush() // empty batch — should be no-op
}

func TestWebhookWriterStopFlushes(t *testing.T) {
	wh := NewWebhookWriter(WebhookConfig{
		URL:        "http://localhost:1/noop",
		FlushEvery: 100 * time.Millisecond,
	})
	wh.Start()
	time.Sleep(50 * time.Millisecond)
	wh.Stop() // should not hang
}
