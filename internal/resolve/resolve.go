// Package resolve provides identity resolution and credential injection support
// for Argus's proxy auth mode. It defines the client and contract for the
// /api/db/resolve endpoint (implemented by Monopam or any external identity provider).
//
// The resolve API decouples client identity from database credentials:
//
//	Client connects with app-level credentials
//	 → Argus calls /api/db/resolve with the client's identity
//	 → Monopam returns the real DB target, credential, and session metadata
//	 → Argus authenticates to the database using the resolved credential
//	 → Client never sees the real database password
//
// This package is in-development — the resolve endpoint is the bridge between
// Argus (Go) and Monopam (.NET).
package resolve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// defaultTimeout is the HTTP request timeout for resolve calls.
const defaultTimeout = 10 * time.Second

// --- Request / Response types for the /api/db/resolve API ---

// ResolveRequest is sent by Argus to Monopam after a protocol handshake
// to determine the real database target and credential for a session.
type ResolveRequest struct {
	// Username extracted from the protocol handshake (e.g. PG startup 'user' param).
	Username string `json:"username"`

	// Database extracted from the protocol handshake (e.g. PG startup 'database' param).
	Database string `json:"database,omitempty"`

	// ClientIP is the TCP source address of the client connection.
	ClientIP string `json:"client_ip,omitempty"`

	// Protocol is the database wire protocol (e.g. "postgresql", "mysql", "mssql").
	Protocol string `json:"protocol,omitempty"`

	// RequestID is an optional trace/correlation identifier.
	RequestID string `json:"request_id,omitempty"`
}

// ResolvedTarget is the response from Monopam specifying which database
// to connect to and which credentials to use.
type ResolvedTarget struct {
	// Host is the backend database hostname or IP.
	Host string `json:"host"`

	// Port is the backend database port.
	Port int `json:"port"`

	// Protocol is the wire protocol (must match Argus's protocol handler).
	Protocol string `json:"protocol"`

	// Username is the database user to authenticate as (injected by Argus).
	Username string `json:"username"`

	// Password is the backend database password (fetched from Vault by Monopam).
	Password string `json:"password"`

	// ClientSecret authenticates the client to Argus and must differ from Password.
	ClientSecret string `json:"client_secret"`

	// ClientSecretExpiresAt optionally identifies when ClientSecret expires.
	ClientSecretExpiresAt *time.Time `json:"client_secret_expires_at,omitempty"`

	// AuthMethod is the preferred auth method if protocol-specific.
	// Example: "scram_sha_256", "md5", "cleartext", "mysql_native_password".
	AuthMethod string `json:"auth_method,omitempty"`

	// Roles are additional policy roles to assign for this session.
	Roles []string `json:"roles,omitempty"`

	// Principal is a stable identity for the acting user (e.g. the Monopam userId or an access-key id),
	// carried onto the session for per-user rate limiting and audit. The wire username is an opaque
	// per-session handle, so it cannot serve that purpose.
	Principal string `json:"principal,omitempty"`

	// PolicyTags are free-form labels attached to the session for policy evaluation.
	PolicyTags map[string]string `json:"policy_tags,omitempty"`
}

// ResolveError is returned when the resolve endpoint denies access.
type ResolveError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ResolveError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("[%s] %s", e.Code, e.Message)
	}
	return fmt.Sprintf("resolve denied: code=%s", e.Code)
}

// --- HTTP Client ---

// Client resolves session identity to a database target and credential
// by calling an external /api/db/resolve HTTP endpoint.
type Client struct {
	endpoint   string
	httpClient *http.Client
	apiKey     string // optional bearer token for the resolve API
}

// NewClient creates a resolve client that calls the given endpoint.
// endpoint format: "http://monopam:8080/api/db/resolve"
// If apiKey is non-empty, it is sent as a Bearer token in the Authorization header.
func NewClient(endpoint, apiKey string) *Client {
	return &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		apiKey: apiKey,
	}
}

// Resolve sends the session identity to the resolve endpoint and returns
// the target database and credential to use.
func (c *Client) Resolve(ctx context.Context, req *ResolveRequest) (*ResolvedTarget, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal resolve request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create resolve request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("resolve call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read resolve response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var target ResolvedTarget
		if err := json.Unmarshal(respBody, &target); err != nil {
			return nil, fmt.Errorf("parse resolved target: %w", err)
		}
		switch {
		case target.Host == "":
			return nil, fmt.Errorf("resolve returned empty host")
		case target.Password == "":
			return nil, fmt.Errorf("resolve returned empty backend password")
		case target.ClientSecret == "":
			return nil, fmt.Errorf("resolve returned empty client secret")
		case secretsEqual(target.ClientSecret, target.Password):
			return nil, fmt.Errorf("resolve returned identical client and backend secrets")
		case target.ClientSecretExpiresAt != nil && !target.ClientSecretExpiresAt.After(time.Now()):
			return nil, fmt.Errorf("resolve returned expired client secret")
		}
		return &target, nil

	case http.StatusForbidden, http.StatusUnauthorized:
		var re ResolveError
		if err := json.Unmarshal(respBody, &re); err != nil {
			return nil, fmt.Errorf("resolve denied (HTTP %d)", resp.StatusCode)
		}
		return nil, &re

	default:
		return nil, fmt.Errorf("resolve returned HTTP %d", resp.StatusCode)
	}
}

func secretsEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// CloseIdleConnections closes idle HTTP connections in the client's transport.
func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}
