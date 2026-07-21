package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// POST /api/policies installs a policy set in-memory via the configured policySetFn (no file on disk).
func TestHandlePoliciesPostInstallsPolicy(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	var got string
	s.SetPolicySetFn(func(b []byte) error {
		got = string(b)
		return nil
	})

	body := `{"version":"1","defaults":{"action":"allow"}}`
	req := httptest.NewRequest("POST", "/api/policies", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.handlePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got != body {
		t.Fatalf("policySetFn body = %q, want %q", got, body)
	}
}

func TestHandlePoliciesPostNotConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	req := httptest.NewRequest("POST", "/api/policies", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	s.handlePolicies(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestHandlePoliciesPostSetFnError(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetPolicySetFn(func([]byte) error { return errors.New("bad policy") })
	req := httptest.NewRequest("POST", "/api/policies", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	s.handlePolicies(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

