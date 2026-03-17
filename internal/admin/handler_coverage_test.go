package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// allUnhealthyProvider returns no healthy targets
type allUnhealthyProvider struct{ sm *session.Manager }

func (a *allUnhealthyProvider) SessionManager() *session.Manager { return a.sm }
func (a *allUnhealthyProvider) PoolStats() map[string]pool.PoolStats {
	return map[string]pool.PoolStats{
		"pg": {Healthy: false},
	}
}

func TestHandleReadyNotReadyAllDown(t *testing.T) {
	s := NewServer(&allUnhealthyProvider{sm: session.NewManager(0, 0)}, ":0")
	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	s.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("all unhealthy: status = %d, want 503", w.Code)
	}
}

func TestHandleSessionsWithData(t *testing.T) {
	provider := newMockProvider()
	info := &session.Info{Username: "alice", Database: "prod", ClientIP: nil}
	provider.sm.Create(info, nil)

	s := NewServer(provider, ":0")
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	s.handleSessions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}

	var sessions []any
	json.Unmarshal(w.Body.Bytes(), &sessions)
	if len(sessions) != 1 {
		t.Errorf("sessions = %d, want 1", len(sessions))
	}
}

func TestHandleSessionKillSuccess(t *testing.T) {
	provider := newMockProvider()
	info := &session.Info{Username: "alice", Database: "db", ClientIP: nil}
	sess := provider.sm.Create(info, nil)

	s := NewServer(provider, ":0")
	req := httptest.NewRequest("POST", "/api/sessions/kill?id="+sess.ID, nil)
	w := httptest.NewRecorder()
	s.handleSessionKill(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandlePolicyReloadError(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.OnPolicyReload(func() error { return fmt.Errorf("reload failed") })

	req := httptest.NewRequest("POST", "/api/policies/reload", nil)
	w := httptest.NewRecorder()
	s.handlePolicyReload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleConfigExportError(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetConfigExporter(func() ([]byte, error) {
		return nil, fmt.Errorf("export error")
	})

	req := httptest.NewRequest("GET", "/api/config/export", nil)
	w := httptest.NewRecorder()
	s.handleConfigExport(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleDryRunSuccess(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetDryRunFunc(func(u, d, sql, ip string) (any, error) {
		return map[string]string{"user": u, "sql": sql}, nil
	})

	req := httptest.NewRequest("POST", "/api/policies/dryrun?username=alice&sql=SELECT+1&database=prod&client_ip=10.0.0.1", nil)
	w := httptest.NewRecorder()
	s.handleDryRun(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleApprovalActionNotConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	// No approval provider set

	req := httptest.NewRequest("POST", "/api/approvals/approve?id=1", nil)
	w := httptest.NewRecorder()
	s.handleApprovalAction(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleApprovalDenyNotConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/approvals/deny?id=1", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
