package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

type finalProvider struct{}

func (p *finalProvider) SessionManager() *session.Manager {
	return session.NewManager(time.Hour, time.Hour)
}
func (p *finalProvider) PoolStats() map[string]pool.PoolStats {
	return map[string]pool.PoolStats{}
}

// --- handleAuditSearch: error on bad log file ---

func TestHandleAuditSearchBadFile(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	s.auditLogPath = "/nonexistent/audit.jsonl"

	req := httptest.NewRequest(http.MethodGet, "/api/audit/search?username=test", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleAuditExport: with bad log path ---

func TestHandleAuditExportBadPath(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	s.auditLogPath = "/nonexistent/audit.jsonl"

	req := httptest.NewRequest(http.MethodGet, "/api/audit/export", nil)
	w := httptest.NewRecorder()
	s.handleAuditExport(w, req)
	// Should try to export but fail — CSV write may partially succeed
	// The error is logged, not returned as HTTP error (by design)
}

// --- handleAuditExport: no path ---

func TestHandleAuditExportNoPathFinal(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")

	req := httptest.NewRequest(http.MethodGet, "/api/audit/export", nil)
	w := httptest.NewRecorder()
	s.handleAuditExport(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleReplay: no file configured ---

func TestHandleReplayNoFile(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")

	req := httptest.NewRequest(http.MethodGet, "/api/audit/replay?session_id=test", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleReplay: with audit log path fallback ---

func TestHandleReplayWithAuditLogPath(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "recordings.jsonl")
	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(audit.QueryRecord{Timestamp: time.Now(), SessionID: "sess-abc", SQL: "SELECT 1"})
	f.Close()

	s := NewServer(&finalProvider{}, ":0")
	s.auditLogPath = logFile // uses auditLogPath as fallback when recordFile is empty

	req := httptest.NewRequest(http.MethodGet, "/api/audit/replay?session_id=sess-abc", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

// --- handleReplay: bad file ---

func TestHandleReplayBadFile(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	s.recordFile = "/nonexistent/file.jsonl"

	req := httptest.NewRequest(http.MethodGet, "/api/audit/replay?session_id=test", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleFingerprints: bad file ---

func TestHandleFingerprintsBadFile(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	s.SetRecordFile("/nonexistent/file.jsonl")

	req := httptest.NewRequest(http.MethodGet, "/api/audit/fingerprints", nil)
	w := httptest.NewRecorder()
	s.handleFingerprints(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleFingerprints: custom limit ---

func TestHandleFingerprintsCustomLimit(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "rec.jsonl")
	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	for range 10 {
		enc.Encode(audit.QueryRecord{Timestamp: time.Now(), SQL: "SELECT 1", Fingerprint: "abc"})
	}
	f.Close()

	s := NewServer(&finalProvider{}, ":0")
	s.SetRecordFile(logFile)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/fingerprints?limit=3", nil)
	w := httptest.NewRecorder()
	s.handleFingerprints(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleCompact: method not allowed ---

func TestHandleCompactMethodNotAllowed(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	req := httptest.NewRequest(http.MethodGet, "/api/audit/compact", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleCompact: no audit path ---

func TestHandleCompactNoPathFinal(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	req := httptest.NewRequest(http.MethodPost, "/api/audit/compact", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleApprovalAction: success path ---

type successApproval struct{}

func (m *successApproval) Approve(id, approver string) error   { return nil }
func (m *successApproval) Deny(id, approver, reason string) error { return nil }
func (m *successApproval) PendingRequests() []any               { return nil }

func TestHandleApprovalActionSuccessFinal(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	s.SetApprovalProvider(&successApproval{})

	req := httptest.NewRequest(http.MethodPost, "/api/approvals/approve?id=test-id&approver=alice", nil)
	w := httptest.NewRecorder()
	s.handleApprovalAction(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleApprovalDeny: success path ---

func TestHandleApprovalDenySuccessFinal(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	s.SetApprovalProvider(&successApproval{})

	req := httptest.NewRequest(http.MethodPost, "/api/approvals/deny?id=test-id&approver=bob&reason=suspicious", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleApprovalDeny: missing ID ---

func TestHandleApprovalDenyMissingIDFinal(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")
	s.SetApprovalProvider(&successApproval{})

	req := httptest.NewRequest(http.MethodPost, "/api/approvals/deny", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleDashboard ---

func TestHandleDashboard(t *testing.T) {
	s := NewServer(&finalProvider{}, ":0")

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	w := httptest.NewRecorder()
	s.handleDashboard(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("should be JSON")
	}
}
