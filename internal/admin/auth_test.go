package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddlewareNoToken(t *testing.T) {
	// No token = no auth required
	auth := NewAuthMiddleware("")
	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("no token: status = %d, want 200", w.Code)
	}
}

func TestAuthMiddlewarePublicPaths(t *testing.T) {
	auth := NewAuthMiddleware("secret-token")
	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	publicPaths := []string{"/healthz", "/livez", "/ready", "/metrics"}
	for _, path := range publicPaths {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200 (public)", path, w.Code)
		}
	}
}

func TestAuthMiddlewareUnauthorized(t *testing.T) {
	auth := NewAuthMiddleware("secret-token")
	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No auth header
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("no auth: status = %d, want 401", w.Code)
	}
}

func TestAuthMiddlewareWrongToken(t *testing.T) {
	auth := NewAuthMiddleware("secret-token")
	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("wrong token: status = %d, want 403", w.Code)
	}
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	auth := NewAuthMiddleware("secret-token")
	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("valid token: status = %d, want 200", w.Code)
	}
}

func TestAuthMiddlewareQueryParamRejected(t *testing.T) {
	auth := NewAuthMiddleware("secret-token")
	handler := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/events/ws?token=secret-token", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("query param token: status = %d, want 401", w.Code)
	}
}

func TestGetClientIPUsesRemoteAddrWhenNoTrustedProxies(t *testing.T) {
	auth := NewAuthMiddleware("test-token")
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	ip := auth.getClientIP(req)
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 (trusted proxy not configured), got %v", ip)
	}
}

func TestGetClientIPWithTrustedProxy(t *testing.T) {
	auth := NewAuthMiddleware("test-token")
	auth = auth.WithTrustedProxies([]string{"10.0.0.0/8"})

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	ip := auth.getClientIP(req)
	if ip == nil || ip.String() != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1 (trusted proxy forwards), got %v", ip)
	}
}

func TestGetClientIPIgnoresSpoofedXFF(t *testing.T) {
	auth := NewAuthMiddleware("test-token")
	// No trusted proxies configured
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	req.Header.Set("X-Forwarded-For", "10.0.0.2")

	ip := auth.getClientIP(req)
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("expected 203.0.113.5 (no trusted proxies), got %v", ip)
	}
}
