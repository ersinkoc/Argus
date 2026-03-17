package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ersinkoc/argus/internal/session"
)

func TestHandleSessionKillDelete(t *testing.T) {
	provider := newMockProvider()
	info := &session.Info{Username: "test", Database: "db", ClientIP: nil}
	s := provider.sm.Create(info, nil)

	srv := NewServer(provider, ":0")
	req := httptest.NewRequest("DELETE", "/api/sessions/kill?id="+s.ID, nil)
	w := httptest.NewRecorder()
	srv.handleSessionKill(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("DELETE: status = %d, want 200", w.Code)
	}
}

func TestHandleApprovalDenyNoProviderFinal(t *testing.T) {
	srv := NewServer(newMockProvider(), ":0")
	req := httptest.NewRequest("POST", "/api/approvals/deny?id=test", nil)
	w := httptest.NewRecorder()
	srv.handleApprovalDeny(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleCompactWithValidPath(t *testing.T) {
	dir := t.TempDir()
	srv := NewServer(newMockProvider(), ":0")
	srv.SetAuditLogPath(dir + "/audit.jsonl")

	req := httptest.NewRequest("POST", "/api/audit/compact?dry_run=true", nil)
	w := httptest.NewRecorder()
	srv.handleCompact(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
