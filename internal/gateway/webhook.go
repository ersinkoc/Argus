package gateway

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// ApprovalWebhookPayload is sent when a query needs admin approval.
type ApprovalWebhookPayload struct {
	EventType   string    `json:"event_type"`
	ApprovalID  string    `json:"approval_id"`
	Fingerprint string    `json:"fingerprint"`
	SQL         string    `json:"sql"`
	Username    string    `json:"username"`
	Database    string    `json:"database"`
	RiskLevel   string    `json:"risk_level"`
	CostScore   int       `json:"cost_score"`
	RequestedAt time.Time `json:"requested_at"`
}

// WebhookNotifier sends immediate webhook notifications for approval requests.
type WebhookNotifier struct {
	url     string
	client  *http.Client
	headers map[string]string
}

// NewWebhookNotifier creates a webhook notifier.
func NewWebhookNotifier(url string, headers map[string]string) *WebhookNotifier {
	return &WebhookNotifier{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		headers: headers,
	}
}

// Notify sends an approval webhook notification asynchronously.
func (w *WebhookNotifier) Notify(payload ApprovalWebhookPayload) {
	go func() {
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[argus] gateway webhook marshal error: %v", err)
			return
		}

		req, err := http.NewRequest("POST", w.url, bytes.NewReader(body))
		if err != nil {
			log.Printf("[argus] gateway webhook request error: %v", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Argus-Gateway/1.0")
		for k, v := range w.headers {
			req.Header.Set(k, v)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			log.Printf("[argus] gateway webhook send error: %v", err)
			return
		}
		resp.Body.Close()

		if resp.StatusCode >= 400 {
			log.Printf("[argus] gateway webhook returned %d", resp.StatusCode)
		}
	}()
}
