package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// mockProvider implements SessionProvider for testing.
type mockProvider struct {
	sm *session.Manager
}

func (m *mockProvider) SessionManager() *session.Manager {
	return m.sm
}

func (m *mockProvider) PoolStats() map[string]pool.PoolStats {
	return map[string]pool.PoolStats{
		"test-pg": {Target: "localhost:5432", Active: 2, Idle: 3, Total: 5, Max: 100, Healthy: true},
	}
}

func newMockProvider() *mockProvider {
	return &mockProvider{
		sm: session.NewManager(0, 0),
	}
}

func TestHealthEndpoint(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", resp["status"])
	}
}

func TestMetricsEndpoint(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	server.handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if len(body) == 0 {
		t.Error("metrics body should not be empty")
	}
	// Should contain key metrics
	for _, metric := range []string{"argus_active_sessions", "argus_commands_total", "argus_go_goroutines"} {
		if !containsStr(body, metric) {
			t.Errorf("metrics should contain %q", metric)
		}
	}
}

func TestSessionsEndpoint(t *testing.T) {
	provider := newMockProvider()
	server := NewServer(provider, ":0")

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	server.handleSessions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var sessions []any
	json.Unmarshal(w.Body.Bytes(), &sessions)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestStatsEndpoint(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	server.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["uptime"]; !ok {
		t.Error("stats should include uptime")
	}
}

func TestSessionKillMissingID(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/sessions/kill", nil)
	w := httptest.NewRecorder()
	server.handleSessionKill(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestSessionKillMethodNotAllowed(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/sessions/kill?id=abc", nil)
	w := httptest.NewRecorder()
	server.handleSessionKill(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestPolicyReloadNotConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/policies/reload", nil)
	w := httptest.NewRecorder()
	server.handlePolicyReload(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPolicyReloadSuccess(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")
	server.OnPolicyReload(func() error { return nil })

	req := httptest.NewRequest("POST", "/api/policies/reload", nil)
	w := httptest.NewRecorder()
	server.handlePolicyReload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
