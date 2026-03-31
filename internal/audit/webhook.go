package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// WebhookWriter sends audit events to a SIEM/webhook endpoint via HTTP POST.
// Events are batched and flushed periodically or when the batch is full.
type WebhookWriter struct {
	url        string
	client     *http.Client
	batchSize  int
	flushEvery time.Duration
	headers    map[string]string

	mu      sync.Mutex
	batch   []Event
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// WebhookConfig configures the webhook writer.
type WebhookConfig struct {
	URL        string
	BatchSize  int
	FlushEvery time.Duration
	Timeout    time.Duration
	Headers    map[string]string
}

// NewWebhookWriter creates a new webhook writer.
func NewWebhookWriter(cfg WebhookConfig) *WebhookWriter {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushEvery <= 0 {
		cfg.FlushEvery = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	w := &WebhookWriter{
		url:        cfg.URL,
		batchSize:  cfg.BatchSize,
		flushEvery: cfg.FlushEvery,
		headers:    cfg.Headers,
		batch:      make([]Event, 0, cfg.BatchSize),
		stopCh:     make(chan struct{}),
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
	}

	return w
}

// Write implements io.Writer by decoding JSON events and batching them.
func (w *WebhookWriter) Write(p []byte) (n int, err error) {
	var event Event
	if err := json.Unmarshal(bytes.TrimSpace(p), &event); err != nil {
		// If we can't parse, still count the bytes as written
		return len(p), nil
	}

	w.mu.Lock()
	w.batch = append(w.batch, event)
	shouldFlush := len(w.batch) >= w.batchSize
	w.mu.Unlock()

	if shouldFlush {
		w.flush()
	}

	return len(p), nil
}

// Start begins the periodic flush goroutine.
func (w *WebhookWriter) Start() {
	w.wg.Add(1)
	go w.flushLoop()
}

// Stop flushes remaining events and stops the writer.
func (w *WebhookWriter) Stop() {
	close(w.stopCh)
	w.wg.Wait()
	w.flush() // final flush
}

func (w *WebhookWriter) flushLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.flushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.flush()
		case <-w.stopCh:
			return
		}
	}
}

func (w *WebhookWriter) flush() {
	w.mu.Lock()
	if len(w.batch) == 0 {
		w.mu.Unlock()
		return
	}
	events := w.batch
	w.batch = make([]Event, 0, w.batchSize)
	w.mu.Unlock()

	// json.Marshal for []Event never fails since Event contains only JSON-safe types.
	payload, _ := json.Marshal(events)

	req, err := http.NewRequest("POST", w.url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("[argus] webhook request error: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Argus-Audit/1.0")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		log.Printf("[argus] webhook send error (%d events): %v", len(events), err)
		return
	}
	// Drain and close body to enable HTTP connection reuse
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("[argus] webhook returned %d (%d events)", resp.StatusCode, len(events))
	}
}

// Ensure WebhookWriter satisfies fmt.Stringer for debugging.
func (w *WebhookWriter) String() string {
	return fmt.Sprintf("WebhookWriter{url=%s, batch_size=%d}", w.url, w.batchSize)
}
