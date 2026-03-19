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

	// Prometheus text format checks
	required := []string{
		"# HELP argus_active_sessions",
		"# TYPE argus_active_sessions gauge",
		"# HELP argus_connections_total",
		"# TYPE argus_connections_total counter",
		"argus_connections_total{status=\"success\"}",
		"argus_connections_total{status=\"failed\"}",
		"# HELP argus_commands_total",
		"argus_commands_total{action=\"allowed\"}",
		"argus_commands_total{action=\"blocked\"}",
		"# HELP argus_policy_evaluations_total",
		"argus_policy_cache_hits_total{result=\"hit\"}",
		"argus_pool_connections{",
		"argus_pool_healthy{",
		// Proper histogram format
		"# TYPE argus_query_duration_microseconds histogram",
		"argus_query_duration_microseconds_bucket{le=",
		"argus_query_duration_microseconds_bucket{le=\"+Inf\"}",
		"argus_query_duration_microseconds_sum",
		"argus_query_duration_microseconds_count",
		// Pool wait histogram
		"# TYPE argus_pool_acquire_wait_microseconds histogram",
		"argus_pool_acquire_wait_microseconds_bucket{le=",
		// Protocol labels
		"argus_protocol_commands_total{protocol=\"postgresql\",type=\"query\"}",
		// Runtime
		"# TYPE argus_go_goroutines gauge",
		"argus_go_alloc_bytes",
		"argus_go_gc_runs_total",
	}
	for _, expected := range required {
		if !containsStr(body, expected) {
			t.Errorf("metrics missing %q", expected)
		}
	}

	// Content-Type should indicate Prometheus format
	ct := w.Header().Get("Content-Type")
	if !containsStr(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

func TestReadyzEndpoint(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	// /readyz should behave identically to /ready
	for _, path := range []string{"/ready", "/readyz"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		server.handleReady(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, w.Code)
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
