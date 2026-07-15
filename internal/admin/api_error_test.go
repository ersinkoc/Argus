package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSPMiddleware(t *testing.T) {
	policy := "default-src 'self'"
	mw := CSPMiddleware(policy)
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got := w.Header().Get(cspHeaderName)
		if got != policy {
			t.Errorf("CSP header = %q, want %q", got, policy)
		}
	})
	handler := mw(inner)
	req := httptest.NewRequest("GET", "/ui", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("inner handler should have been called")
	}
}

func TestCSPReportOnly(t *testing.T) {
	policy := "default-src 'self'"
	mw := CSPReportOnly(policy)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := w.Header().Get("Content-Security-Policy-Report-Only")
		if got != policy {
			t.Errorf("CSP-Report-Only header = %q, want %q", got, policy)
		}
	})
	handler := mw(inner)
	req := httptest.NewRequest("GET", "/ui", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

func TestWriteAPIErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()

	writeAPIError(rec, http.StatusForbidden, "FORBIDDEN", "access denied")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.Code != "FORBIDDEN" || body.Error.Message != "access denied" {
		t.Fatalf("error = %+v, want FORBIDDEN/access denied", body.Error)
	}
}
