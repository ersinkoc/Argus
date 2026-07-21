package resolve_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/resolve"
)

func TestClient_Resolve_Success(t *testing.T) {
	// Relative future so the client's expiry check passes regardless of the wall clock; truncated to
	// seconds for a clean round-trip through RFC3339 JSON (the round-trip Equal assertion below).
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %s", r.Header.Get("Content-Type"))
		}
		var req resolve.ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Username != "jane_app" {
			t.Errorf("username = %s", req.Username)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resolve.ResolvedTarget{
			Host:                  "db-primary.internal",
			Port:                  5432,
			Protocol:              "postgresql",
			Username:              "argus_svc",
			Password:              "vault-secret-abc",
			ClientSecret:          "client-secret-xyz",
			ClientSecretExpiresAt: &expiresAt,
			AuthMethod:            "scram_sha_256",
			Roles:                 []string{"app_reader", "analyst"},
		})
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL+"/api/db/resolve", "")
	target, err := client.Resolve(context.Background(), &resolve.ResolveRequest{
		Username: "jane_app",
		Database: "production",
		ClientIP: "10.0.1.50",
		Protocol: "postgresql",
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "db-primary.internal" {
		t.Errorf("host = %s", target.Host)
	}
	if target.Port != 5432 {
		t.Errorf("port = %d", target.Port)
	}
	if target.Username != "argus_svc" {
		t.Errorf("username = %s", target.Username)
	}
	if target.Password != "vault-secret-abc" {
		t.Error("backend password was not parsed")
	}
	if target.ClientSecret != "client-secret-xyz" {
		t.Error("client secret was not parsed")
	}
	if target.ClientSecretExpiresAt == nil || !target.ClientSecretExpiresAt.Equal(expiresAt) {
		t.Errorf("client secret expiry = %v, want %v", target.ClientSecretExpiresAt, expiresAt)
	}
	if len(target.Roles) != 2 || target.Roles[0] != "app_reader" {
		t.Errorf("roles = %v", target.Roles)
	}
}

func TestClient_Resolve_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(resolve.ResolveError{
			Code:    "ACCESS_DENIED",
			Message: "user not authorized for this database",
		})
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL, "")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{
		Username: "unknown_user",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	t.Logf("got expected error: %v", err)
}

func TestClient_Resolve_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL, "")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{
		Username: "any_user",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	t.Logf("got expected error: %v", err)
}

func TestClient_Resolve_RejectsInvalidSecrets(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		password     string
		clientSecret string
		expiresAt    *time.Time
		wantError    string
	}{
		{name: "empty host", password: "backend-value", clientSecret: "client-value", wantError: "empty host"},
		{name: "empty backend password", host: "db.internal", clientSecret: "client-value", wantError: "empty backend password"},
		{name: "empty client secret", host: "db.internal", password: "backend-value", wantError: "empty client secret"},
		{name: "identical secrets", host: "db.internal", password: "do-not-echo", clientSecret: "do-not-echo", wantError: "identical client and backend secrets"},
		{name: "expired client secret", host: "db.internal", password: "backend-value", clientSecret: "client-value", expiresAt: timePointer(time.Now().Add(-time.Minute)), wantError: "expired client secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(resolve.ResolvedTarget{
					Host: tt.host, Password: tt.password, ClientSecret: tt.clientSecret,
					ClientSecretExpiresAt: tt.expiresAt,
				}); err != nil {
					t.Fatal(err)
				}
			}))
			defer srv.Close()

			client := resolve.NewClient(srv.URL, "")
			_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("error = %v, want message containing %q", err, tt.wantError)
			}
			for _, secret := range []string{tt.password, tt.clientSecret} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatal("validation error exposed a secret value")
				}
			}
		})
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func TestClient_Resolve_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(resolve.ResolveError{
			Code:    "INVALID_TOKEN",
			Message: "api key rejected",
		})
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL, "stale-token")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	var re *resolve.ResolveError
	if !errors.As(err, &re) {
		t.Fatalf("error type = %T, want *resolve.ResolveError", err)
	}
	if re.Code != "INVALID_TOKEN" {
		t.Errorf("code = %s", re.Code)
	}
	if !strings.Contains(err.Error(), "api key rejected") {
		t.Errorf("error = %v, want message containing %q", err, "api key rejected")
	}
}

func TestClient_Resolve_DeniedMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("access denied (not json)"))
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL, "")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "resolve denied (HTTP 403)") {
		t.Errorf("error = %v, want message containing %q", err, "resolve denied (HTTP 403)")
	}
}

func TestClient_Resolve_MalformedTargetJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL, "")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "parse resolved target") {
		t.Errorf("error = %v, want message containing %q", err, "parse resolved target")
	}
}

func TestClient_Resolve_InvalidEndpoint(t *testing.T) {
	client := resolve.NewClient("http://invalid host\x7f/resolve", "")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "create resolve request") {
		t.Errorf("error = %v, want message containing %q", err, "create resolve request")
	}
}

func TestClient_Resolve_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // server is down before the request is made

	client := resolve.NewClient(srv.URL, "")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "resolve call failed") {
		t.Errorf("error = %v, want message containing %q", err, "resolve call failed")
	}
}

func TestClient_Resolve_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the call

	client := resolve.NewClient(srv.URL, "")
	_, err := client.Resolve(ctx, &resolve.ResolveRequest{Username: "any_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled in chain", err)
	}
}

func TestClient_Resolve_BodyReadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Declare a longer body than is written; the server closes the
		// connection early and the client fails while reading the body.
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("short"))
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL, "")
	_, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "read resolve response") {
		t.Errorf("error = %v, want message containing %q", err, "read resolve response")
	}
}

func TestResolveError_Error(t *testing.T) {
	withMessage := &resolve.ResolveError{Code: "ACCESS_DENIED", Message: "no grant"}
	if got := withMessage.Error(); got != "[ACCESS_DENIED] no grant" {
		t.Errorf("Error() = %q", got)
	}
	codeOnly := &resolve.ResolveError{Code: "ACCESS_DENIED"}
	if got := codeOnly.Error(); got != "resolve denied: code=ACCESS_DENIED" {
		t.Errorf("Error() = %q", got)
	}
}

func TestClient_CloseIdleConnections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resolve.ResolvedTarget{
			Host: "db.internal", Password: "backend-value", ClientSecret: "client-value",
		})
	}))
	defer srv.Close()

	client := resolve.NewClient(srv.URL, "")
	if _, err := client.Resolve(context.Background(), &resolve.ResolveRequest{Username: "any_user"}); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections() // must not panic; releases the idle keep-alive conn
}

func TestClient_Resolve_AuthorizationHeader(t *testing.T) {
	var authHdr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resolve.ResolvedTarget{
			Host:         "db.internal",
			Port:         3306,
			Protocol:     "mysql",
			Username:     "proxy_user",
			Password:     "proxy_pass",
			ClientSecret: "client_pass",
		})
	}))
	defer srv.Close()

	token := "mcp-api-token-1a2b3c"
	client := resolve.NewClient(srv.URL, token)
	target, err := client.Resolve(context.Background(), &resolve.ResolveRequest{
		Username: "app_user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "db.internal" {
		t.Errorf("host = %s", target.Host)
	}
	expected := "Bearer " + token
	if authHdr != expected {
		t.Errorf("Authorization header = %q, want %q", authHdr, expected)
	}
}
