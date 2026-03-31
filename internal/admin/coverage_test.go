package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
)

func TestHandleAuditSearchWithTimeRange(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, _ := os.Create(logPath)
	enc := json.NewEncoder(f)
	enc.Encode(audit.Event{Timestamp: time.Now(), Username: "alice", Action: "allow"})
	f.Close()

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	start := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	end := time.Now().Add(1 * time.Hour).Format(time.RFC3339)

	req := httptest.NewRequest("GET", "/api/audit/search?start="+start+"&end="+end+"&limit=10", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleCompactConfigured(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(logPath, []byte{}, 0644)

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	req := httptest.NewRequest("POST", "/api/audit/compact?dry_run=true&max_age_hours=24", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleCompactNoPath(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/audit/compact", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleApprovalActionSuccess(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&mockApproval{})

	req := httptest.NewRequest("POST", "/api/approvals/approve?id=test-1&approver=admin", nil)
	w := httptest.NewRecorder()
	s.handleApprovalAction(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleApprovalDenySuccess(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&mockApproval{})

	req := httptest.NewRequest("POST", "/api/approvals/deny?id=test-1&reason=nope", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleApprovalDenyMissingID(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&mockApproval{})

	req := httptest.NewRequest("POST", "/api/approvals/deny", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleApprovalActionNoProvider(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/approvals/approve?id=1", nil)
	w := httptest.NewRecorder()
	s.handleApprovalAction(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleReplayWithFile(t *testing.T) {
	dir := t.TempDir()
	recPath := filepath.Join(dir, "queries.jsonl")
	os.WriteFile(recPath, []byte(`{"session_id":"s1","sql":"SELECT 1"}`+"\n"), 0644)

	s := NewServer(newMockProvider(), ":0")
	s.SetRecordFile(recPath)

	req := httptest.NewRequest("GET", "/api/audit/replay?session_id=s1", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleFingerprintsWithFile(t *testing.T) {
	dir := t.TempDir()
	recPath := filepath.Join(dir, "queries.jsonl")
	os.WriteFile(recPath, []byte(`{"fingerprint":"fp1","sql":"SELECT 1"}`+"\n"), 0644)

	s := NewServer(newMockProvider(), ":0")
	s.SetRecordFile(recPath)

	req := httptest.NewRequest("GET", "/api/audit/fingerprints?limit=5", nil)
	w := httptest.NewRecorder()
	s.handleFingerprints(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleMetricsContent(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	s.handleMetrics(w, req)

	body := w.Body.String()
	checks := []string{
		"argus_active_sessions",
		"argus_connections_total",
		"argus_commands_total",
		"argus_query_duration_microseconds_count",
		"argus_protocol_commands_total",
		"argus_go_goroutines",
		"argus_pool_acquire_wait_microseconds_count",
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("metrics should contain %q", check)
		}
	}
}
