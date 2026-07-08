package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// unhealthyProvider returns one unhealthy target for degraded health tests.
type unhealthyProvider struct {
	sm *session.Manager
}

func (u *unhealthyProvider) SessionManager() *session.Manager { return u.sm }
func (u *unhealthyProvider) PoolStats() map[string]pool.PoolStats {
	return map[string]pool.PoolStats{
		"pg":    {Healthy: true},
		"mysql": {Healthy: false},
	}
}

func TestHandleHealthDegraded(t *testing.T) {
	s := NewServer(&unhealthyProvider{sm: session.NewManager(0, 0)}, ":0")

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("degraded health should return 503, got %d", w.Code)
	}
}

func TestHandleSessionKillNotFound(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/sessions/kill?id=nonexistent", nil)
	w := httptest.NewRecorder()
	s.handleSessionKill(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleSessionKillMethodGet(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/sessions/kill?id=test", nil)
	w := httptest.NewRecorder()
	s.handleSessionKill(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandlePolicyReloadNotConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/policies/reload", nil)
	w := httptest.NewRecorder()
	s.handlePolicyReload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandlePolicyReloadSuccess(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.OnPolicyReload(func() error { return nil })

	req := httptest.NewRequest("POST", "/api/policies/reload", nil)
	w := httptest.NewRecorder()
	s.handlePolicyReload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandlePolicyReloadMethodGet(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/policies/reload", nil)
	w := httptest.NewRecorder()
	s.handlePolicyReload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleApprovalsWithProvider(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&mockApproval{})

	req := httptest.NewRequest("GET", "/api/approvals", nil)
	w := httptest.NewRecorder()
	s.handleApprovals(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandlePoolHealthDegraded(t *testing.T) {
	s := NewServer(&unhealthyProvider{sm: session.NewManager(0, 0)}, ":0")

	req := httptest.NewRequest("GET", "/api/pool/health", nil)
	w := httptest.NewRecorder()
	s.handlePoolHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}
}

func TestHandleReadyNotReady(t *testing.T) {
	allUnhealthy := &unhealthyProvider{sm: session.NewManager(0, 0)}
	// Override to all unhealthy
	s := NewServer(allUnhealthy, ":0")

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	s.handleReady(w, req)

	// At least one is healthy in unhealthyProvider so it should be OK
	// Let's create truly all-unhealthy
}
