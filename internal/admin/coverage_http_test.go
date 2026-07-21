package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// ── auth.go ─────────────────────────────────────────────────────────────────

func TestWithAllowedSourcesParsesCIDRs(t *testing.T) {
	a := NewAuthMiddleware("tok").WithAllowedSources([]string{"10.0.0.0/8", "not-a-cidr", "192.168.1.0/24"})
	if len(a.allowedSources) != 2 {
		t.Errorf("allowedSources = %d, want 2 (invalid CIDR skipped)", len(a.allowedSources))
	}
}

func TestWrapIPAllowlist(t *testing.T) {
	a := NewAuthMiddleware("tok").WithAllowedSources([]string{"10.0.0.0/8"})
	handler := a.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		wantStatus int
	}{
		{"allowed IP", "10.1.2.3:5555", http.StatusOK},
		{"denied IP", "192.168.1.5:5555", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/stats", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("Authorization", "Bearer tok")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestWrapPublicPrefixSkipsAuth(t *testing.T) {
	a := NewAuthMiddleware("tok")
	a.publicPrefixes = append(a.publicPrefixes, "/ui")
	handler := a.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No Authorization header — public prefix must still pass.
	req := httptest.NewRequest("GET", "/ui/assets/app.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("public prefix status = %d, want 200", w.Code)
	}

	// Non-public path without a token must be rejected.
	req = httptest.NewRequest("GET", "/api/stats", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("non-public status = %d, want 401", w.Code)
	}
}

func TestGetClientIPXFFMultipleEntries(t *testing.T) {
	a := NewAuthMiddleware("tok").WithTrustedProxies([]string{"127.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.1")

	if ip := a.getClientIP(req); ip.String() != "203.0.113.7" {
		t.Errorf("client IP = %v, want 203.0.113.7 (first XFF entry)", ip)
	}
}

func TestGetClientIPFallsBackToXRealIP(t *testing.T) {
	a := NewAuthMiddleware("tok").WithTrustedProxies([]string{"127.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "garbage-not-an-ip")
	req.Header.Set("X-Real-IP", "198.51.100.42")

	if ip := a.getClientIP(req); ip.String() != "198.51.100.42" {
		t.Errorf("client IP = %v, want 198.51.100.42 (X-Real-IP fallback)", ip)
	}
}

func TestGetClientIPInvalidForwardedHeaders(t *testing.T) {
	a := NewAuthMiddleware("tok").WithTrustedProxies([]string{"127.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	req.Header.Set("X-Real-IP", "also-not-an-ip")

	if ip := a.getClientIP(req); ip.String() != "127.0.0.1" {
		t.Errorf("client IP = %v, want 127.0.0.1 (RemoteAddr fallback)", ip)
	}
}

func TestGetClientIPUntrustedRemoteIgnoresXFF(t *testing.T) {
	// Proxies are configured, but the request arrives from a non-proxy IP:
	// forwarded headers must be ignored.
	a := NewAuthMiddleware("tok").WithTrustedProxies([]string{"10.0.0.0/8"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.9:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	if ip := a.getClientIP(req); ip.String() != "192.0.2.9" {
		t.Errorf("client IP = %v, want 192.0.2.9 (XFF from untrusted peer ignored)", ip)
	}
}

func TestParseRemoteAddrWithoutPort(t *testing.T) {
	if ip := parseRemoteAddr("192.168.1.1"); ip == nil || ip.String() != "192.168.1.1" {
		t.Errorf("parseRemoteAddr = %v, want 192.168.1.1", ip)
	}
	if ip := parseRemoteAddr("not-an-address"); ip != nil {
		t.Errorf("parseRemoteAddr = %v, want nil", ip)
	}
}

// ── cors.go ─────────────────────────────────────────────────────────────────

func TestCORSAllowAll(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	c := NewCORS(next, true)

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Origin", "http://anywhere.example")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Allow-Methods should be set when origin is allowed")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestCORSMatchingOrigin(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	c := NewCORS(next, false, "http://localhost:5173")

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Allow-Origin = %q, want echoed origin", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials = %q, want true", got)
	}
}

func TestCORSWildcardEntry(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	c := NewCORS(next, false, "*")

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Origin", "http://other.example")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://other.example" {
		t.Errorf("Allow-Origin = %q, want echoed origin for wildcard entry", got)
	}
}

func TestCORSNonMatchingOrigin(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	c := NewCORS(next, false, "http://localhost:5173")

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, req)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin = %q, want empty for non-matching origin", got)
	}
	if !called {
		t.Error("next handler should still be called for non-OPTIONS requests")
	}
}

func TestCORSPreflight(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	c := NewCORS(next, true)

	req := httptest.NewRequest(http.MethodOptions, "/api/stats", nil)
	req.Header.Set("Origin", "http://anywhere.example")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", w.Code)
	}
	if called {
		t.Error("next handler must not be called for preflight requests")
	}
}

// ── server.go ───────────────────────────────────────────────────────────────

func TestServerAddrAndRouteModes(t *testing.T) {
	s := NewServer(newMockProvider(), "127.0.0.1:7777")
	if s.Addr() != "127.0.0.1:7777" {
		t.Errorf("Addr = %q, want 127.0.0.1:7777", s.Addr())
	}

	admin, metric := s.RouteModes()
	if !admin || !metric {
		t.Errorf("RouteModes = %v, %v, want true, true", admin, metric)
	}

	s.SetRouteModes(false, true)
	admin, metric = s.RouteModes()
	if admin || !metric {
		t.Errorf("RouteModes after set = %v, %v, want false, true", admin, metric)
	}
}

func TestServerSetAllowedOriginsDelegates(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetAllowedOrigins("https://admin.example.com")

	if s.EventStream.isValidOrigin("https://admin.example.com") != true {
		t.Error("configured origin should be valid")
	}
	if s.EventStream.isValidOrigin("https://evil.example.com") != false {
		t.Error("unlisted origin should be rejected")
	}
}

func TestHandlePoliciesMethodNotAllowed(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	// POST is now valid (in-memory policy install); DELETE is still not allowed.
	req := httptest.NewRequest("DELETE", "/api/policies", nil)
	w := httptest.NewRecorder()
	s.handlePolicies(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandlePoliciesNotConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/policies", nil)
	w := httptest.NewRecorder()
	s.handlePolicies(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandlePoliciesReturnsList(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetPolicyListFn(func() []map[string]any {
		return []map[string]any{{"name": "block-drop", "action": "block"}}
	})

	req := httptest.NewRequest("GET", "/api/policies", nil)
	w := httptest.NewRecorder()
	s.handlePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var policies []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &policies); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(policies) != 1 || policies[0]["name"] != "block-drop" {
		t.Errorf("policies = %v, want one entry named block-drop", policies)
	}
}

func TestStartWithSourcesAndProxies(t *testing.T) {
	s := NewServer(newMockProvider(), "127.0.0.1:0")
	s.SetAuthToken("start-secret", "10.0.0.0/8")
	s.SetTrustedProxies([]string{"127.0.0.0/8"})

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	// Start wires a constant-time token validator into the EventStream.
	if s.EventStream.validateToken == nil {
		t.Fatal("EventStream token validator should be set")
	}
	if !s.EventStream.validateToken("start-secret") {
		t.Error("validator should accept the configured token")
	}
	if s.EventStream.validateToken("wrong") {
		t.Error("validator should reject a wrong token")
	}
}

// ── audit_handlers.go: handleAuditVerify ────────────────────────────────────

func TestHandleAuditVerifyNoPath(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/audit/verify", nil)
	w := httptest.NewRecorder()
	s.handleAuditVerify(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleAuditVerifyValidChain(t *testing.T) {
	// An empty audit log is a trivially valid chain.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(path)

	req := httptest.NewRequest("GET", "/api/audit/verify", nil)
	w := httptest.NewRecorder()
	s.handleAuditVerify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["valid"] != true {
		t.Errorf("valid = %v, want true", resp["valid"])
	}
	if resp["path"] != path {
		t.Errorf("path = %v, want %q", resp["path"], path)
	}
}

func TestHandleAuditVerifyBrokenChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte("this is not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(path)

	req := httptest.NewRequest("GET", "/api/audit/verify", nil)
	w := httptest.NewRecorder()
	s.handleAuditVerify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["valid"] != false {
		t.Errorf("valid = %v, want false", resp["valid"])
	}
	if resp["error"] == nil || resp["error"] == "" {
		t.Error("error message should be present for a broken chain")
	}
}

// ── adminui_embed.go: adminUIHandler.ServeHTTP ──────────────────────────────

func newTestUIHandler() *adminUIHandler {
	mapFS := fstest.MapFS{
		"index.html":        {Data: []byte("<html><body>SPA</body></html>")},
		"assets/app.js":     {Data: []byte("console.log('app')")},
		"assets/app.css":    {Data: []byte("body{}")},
		"logo.svg":          {Data: []byte("<svg/>")},
		"manifest.json":     {Data: []byte("{}")},
		"assets/app.js.map": {Data: []byte("{}")},
	}
	return &adminUIHandler{fs: http.FS(mapFS), prefix: "/ui"}
}

func TestAdminUIHandlerContentTypes(t *testing.T) {
	h := newTestUIHandler()

	tests := []struct {
		path     string
		wantType string
		wantBody string
	}{
		{"/ui/", "text/html; charset=utf-8", "SPA"},
		{"/ui", "text/html; charset=utf-8", "SPA"},
		{"/ui/index.html", "text/html; charset=utf-8", "SPA"},
		{"/ui/assets/app.js", "application/javascript; charset=utf-8", "console.log"},
		{"/ui/assets/app.css", "text/css; charset=utf-8", "body{}"},
		{"/ui/logo.svg", "image/svg+xml", "<svg/>"},
		{"/ui/manifest.json", "application/json", "{}"},
		{"/ui/assets/app.js.map", "application/json", "{}"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if got := w.Header().Get("Content-Type"); got != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantType)
			}
			if !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want substring %q", w.Body.String(), tt.wantBody)
			}
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want DENY", got)
			}
		})
	}
}

func TestAdminUIHandlerSPAFallback(t *testing.T) {
	h := newTestUIHandler()

	req := httptest.NewRequest("GET", "/ui/sessions/detail/42", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "SPA") {
		t.Errorf("SPA fallback should serve index.html, got %q", w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
}

func TestAdminUIHandlerNoIndex(t *testing.T) {
	h := &adminUIHandler{fs: http.FS(fstest.MapFS{}), prefix: "/ui"}

	req := httptest.NewRequest("GET", "/ui/missing.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// statErrFS returns files whose Stat always fails, to exercise the
// stat-error branch of adminUIHandler.ServeHTTP.
type statErrFS struct{}

func (statErrFS) Open(name string) (http.File, error) { return statErrFile{}, nil }

type statErrFile struct{}

func (statErrFile) Close() error                                 { return nil }
func (statErrFile) Read(p []byte) (int, error)                   { return 0, io.EOF }
func (statErrFile) Seek(offset int64, whence int) (int64, error) { return 0, nil }
func (statErrFile) Readdir(count int) ([]os.FileInfo, error)     { return nil, nil }
func (statErrFile) Stat() (os.FileInfo, error)                   { return nil, errors.New("stat failed") }

func TestAdminUIHandlerStatError(t *testing.T) {
	h := &adminUIHandler{fs: statErrFS{}, prefix: "/ui"}

	req := httptest.NewRequest("GET", "/ui/index.html", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestNewAdminUIHandlerEmbedded(t *testing.T) {
	h := NewAdminUIHandler("/ui")
	if h == nil {
		t.Fatal("NewAdminUIHandler should return a handler for the embedded UI")
	}

	req := httptest.NewRequest("GET", "/ui/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("embedded UI index: status = %d, want 200", w.Code)
	}
}
