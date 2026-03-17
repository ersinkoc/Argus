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
)

func TestSetAuthToken(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetAuthToken("test-token")
	if s.authToken != "test-token" {
		t.Error("auth token not set")
	}
}

func TestSetApprovalProvider(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(nil)
	// Just verify no panic
}

func TestSetAuditLogPath(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath("/tmp/audit.jsonl")
	if s.auditLogPath != "/tmp/audit.jsonl" {
		t.Error("audit log path not set")
	}
}

func TestSetRecordFile(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetRecordFile("/tmp/queries.jsonl")
	if s.recordFile != "/tmp/queries.jsonl" {
		t.Error("record file not set")
	}
}

func TestSetDryRunFunc(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetDryRunFunc(func(u, d, sql, ip string) (any, error) { return nil, nil })
	if s.dryRunFn == nil {
		t.Error("dry run func not set")
	}
}

func TestHandleApprovalsNilProvider(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/approvals", nil)
	w := httptest.NewRecorder()
	s.handleApprovals(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleApprovalActionMissingID(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&mockApproval{})

	req := httptest.NewRequest("POST", "/api/approvals/approve", nil)
	w := httptest.NewRecorder()
	s.handleApprovalAction(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleApprovalDenyMethodNotAllowed(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&mockApproval{})

	req := httptest.NewRequest("GET", "/api/approvals/deny?id=1", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleAuditSearch(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, _ := os.Create(logPath)
	enc := json.NewEncoder(f)
	enc.Encode(audit.Event{Timestamp: time.Now(), Username: "alice", Action: "allow", EventType: "command_executed"})
	f.Close()

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	req := httptest.NewRequest("GET", "/api/audit/search?username=alice", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleAuditSearchNotConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/audit/search", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleAuditExport(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, _ := os.Create(logPath)
	enc := json.NewEncoder(f)
	enc.Encode(audit.Event{Timestamp: time.Now(), Username: "bob", Action: "block"})
	f.Close()

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	req := httptest.NewRequest("GET", "/api/audit/export", nil)
	w := httptest.NewRecorder()
	s.handleAuditExport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("content type = %q, want text/csv", ct)
	}
}

func TestHandlePoolHealth(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/pool/health", nil)
	w := httptest.NewRecorder()
	s.handlePoolHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["summary"]; !ok {
		t.Error("should include summary")
	}
}

func TestHandleDryRunConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetDryRunFunc(func(u, d, sql, ip string) (any, error) {
		return map[string]string{"action": "allow"}, nil
	})

	req := httptest.NewRequest("POST", "/api/policies/dryrun?username=test&sql=SELECT+1", nil)
	w := httptest.NewRecorder()
	s.handleDryRun(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestServerStartStop(t *testing.T) {
	s := NewServer(newMockProvider(), "127.0.0.1:0")
	err := s.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}

// --- mock approval provider ---

type mockApproval struct{}

func (m *mockApproval) Approve(id, approver string) error   { return nil }
func (m *mockApproval) Deny(id, approver, reason string) error { return nil }
func (m *mockApproval) PendingRequests() []any               { return nil }
