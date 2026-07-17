package resolve_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/resolve"
)

func TestClient_Resolve_Success(t *testing.T) {
	expiresAt := time.Date(2026, time.July, 17, 12, 0, 0, 0, time.UTC)
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
