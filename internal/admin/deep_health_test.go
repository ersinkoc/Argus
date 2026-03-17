package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// healthyTargetProvider returns targets with real addresses for deep health check.
type healthyTargetProvider struct {
	sm   *session.Manager
	addr string
}

func (h *healthyTargetProvider) SessionManager() *session.Manager { return h.sm }
func (h *healthyTargetProvider) PoolStats() map[string]pool.PoolStats {
	return map[string]pool.PoolStats{
		"test": {Target: h.addr, Healthy: true},
	}
}

func TestHandleDeepHealthWithTarget(t *testing.T) {
	// Start a real TCP listener to health check
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { for { c, _ := ln.Accept(); if c != nil { c.Close() } } }()

	provider := &healthyTargetProvider{
		sm:   session.NewManager(0, 0),
		addr: ln.Addr().String(),
	}

	s := NewServer(provider, ":0")
	req := httptest.NewRequest("GET", "/api/health/deep", nil)
	w := httptest.NewRecorder()
	s.handleDeepHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var results map[string]any
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) == 0 {
		t.Error("should have health results")
	}
}

func TestHandleDeepHealthNoTargets(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	req := httptest.NewRequest("GET", "/api/health/deep", nil)
	w := httptest.NewRecorder()
	s.handleDeepHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
