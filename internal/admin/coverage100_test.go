package admin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// ══════════════════════════════════════════════════════════════════════════════
// SetGateway (0%) and SetOnSessionKill (0%) — trivial setters
// ══════════════════════════════════════════════════════════════════════════════

type mockGatewayHandler struct{}

func (m *mockGatewayHandler) HandleQuery(w http.ResponseWriter, r *http.Request)       {}
func (m *mockGatewayHandler) HandleApprove(w http.ResponseWriter, r *http.Request)     {}
func (m *mockGatewayHandler) HandleAllowlist(w http.ResponseWriter, r *http.Request)   {}
func (m *mockGatewayHandler) HandleQueryStatus(w http.ResponseWriter, r *http.Request) {}
func (m *mockGatewayHandler) HandleDryRun(w http.ResponseWriter, r *http.Request)      {}

func TestSetGateway(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	gw := &mockGatewayHandler{}
	mw := func(h http.Handler) http.Handler { return h }
	s.SetGateway(gw, mw)
	if s.gatewayHandler == nil {
		t.Error("gateway handler not set")
	}
	if s.gatewayMiddleware == nil {
		t.Error("gateway middleware not set")
	}
}

func TestSetGatewayNilMiddleware(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	gw := &mockGatewayHandler{}
	s.SetGateway(gw, nil)
	if s.gatewayHandler == nil {
		t.Error("gateway handler not set")
	}
	if s.gatewayMiddleware != nil {
		t.Error("gateway middleware should be nil")
	}
}

func TestSetOnSessionKill(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	called := false
	s.SetOnSessionKill(func(sessionID string) {
		called = true
	})
	if s.onSessionKill == nil {
		t.Error("onSessionKill not set")
	}
	s.onSessionKill("test-id")
	if !called {
		t.Error("onSessionKill callback not invoked")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Start (76%) — gateway routes and auth token wrapping
// ══════════════════════════════════════════════════════════════════════════════

func TestStartWithGateway(t *testing.T) {
	s := NewServer(newMockProvider(), "127.0.0.1:0")
	gw := &mockGatewayHandler{}
	s.SetGateway(gw, nil)

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}

func TestStartWithGatewayAndMiddleware(t *testing.T) {
	s := NewServer(newMockProvider(), "127.0.0.1:0")
	gw := &mockGatewayHandler{}
	mw := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		})
	}
	s.SetGateway(gw, mw)

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}

func TestStartWithAuthToken(t *testing.T) {
	s := NewServer(newMockProvider(), "127.0.0.1:0")
	s.SetAuthToken("test-secret")

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}

func TestStartWithGatewayAndAuth(t *testing.T) {
	s := NewServer(newMockProvider(), "127.0.0.1:0")
	gw := &mockGatewayHandler{}
	mw := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		})
	}
	s.SetGateway(gw, mw)
	s.SetAuthToken("secret")

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	s.Stop()
}

// Fully exercise Start() including gateway routes with middleware using a real server
func TestStartFullGatewayRoutes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := NewServer(newMockProvider(), addr)
	gw := &mockGatewayHandler{}
	mwCalled := false
	mw := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mwCalled = true
			h.ServeHTTP(w, r)
		})
	}
	s.SetGateway(gw, mw)
	s.SetAuthToken("secret")

	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Timeout: 2 * time.Second}

	// Test gateway endpoint through the actual server
	req, _ := http.NewRequest("GET", "http://"+addr+"/api/gateway/query", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	resp.Body.Close()

	if !mwCalled {
		t.Error("gateway middleware was not called")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// handleSessionKill (92.9%) — onSessionKill callback branch
// ══════════════════════════════════════════════════════════════════════════════

func TestHandleSessionKillWithCallback(t *testing.T) {
	provider := newMockProvider()
	info := &session.Info{Username: "alice", Database: "db", ClientIP: nil}
	sess := provider.sm.Create(info, nil)

	s := NewServer(provider, ":0")
	var killedID string
	s.SetOnSessionKill(func(sessionID string) {
		killedID = sessionID
	})

	req := httptest.NewRequest("POST", "/api/sessions/kill?id="+sess.ID, nil)
	w := httptest.NewRecorder()
	s.handleSessionKill(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if killedID != sess.ID {
		t.Errorf("onSessionKill called with %q, want %q", killedID, sess.ID)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// handleApprovalDeny (89.5%) — Deny error path
// ══════════════════════════════════════════════════════════════════════════════

type errorDenyApproval struct{}

func (e *errorDenyApproval) Approve(id, approver string) error {
	return nil
}
func (e *errorDenyApproval) Deny(id, approver, reason string) error {
	return fmt.Errorf("deny failed: %s", id)
}
func (e *errorDenyApproval) PendingRequests() []any { return nil }

func TestHandleApprovalDenyError(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&errorDenyApproval{})

	req := httptest.NewRequest("POST", "/api/approvals/deny?id=bad-id&approver=admin&reason=test", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "deny failed") {
		t.Errorf("body should contain error message, got %q", w.Body.String())
	}
}

func TestHandleApprovalDenyDefaultApprover(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&errorDenyApproval{})

	req := httptest.NewRequest("POST", "/api/approvals/deny?id=test-id&reason=suspicious", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// handleAuditSearch (90.9%) — session_id filter and time parsing edge cases
// ══════════════════════════════════════════════════════════════════════════════

func TestHandleAuditSearchSessionIDFilter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, _ := os.Create(logPath)
	type auditEvent struct {
		Timestamp   time.Time `json:"timestamp"`
		SessionID   string    `json:"session_id"`
		Username    string    `json:"username"`
		Action      string    `json:"action"`
		EventType   string    `json:"event_type"`
		Database    string    `json:"database"`
		CommandType string    `json:"command_type"`
	}
	enc := json.NewEncoder(f)
	enc.Encode(auditEvent{Timestamp: time.Now(), SessionID: "sess-1", Username: "alice", Action: "allow", EventType: "command_executed", Database: "testdb", CommandType: "SELECT"})
	f.Close()

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	req := httptest.NewRequest("GET", "/api/audit/search?session_id=sess-1", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleAuditSearchBadTimeFormat(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(logPath, []byte(`{"timestamp":"2024-01-01T00:00:00Z","username":"test"}`+"\n"), 0644)

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	req := httptest.NewRequest("GET", "/api/audit/search?start=bad-time&end=also-bad", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleAuditSearchValidStartEndUTC(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	f, _ := os.Create(logPath)
	enc := json.NewEncoder(f)
	enc.Encode(map[string]any{
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"username":     "alice",
		"action":       "allow",
		"event_type":   "command_executed",
		"database":     "db",
		"command_type": "SELECT",
	})
	f.Close()

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	// Use UTC times (Z suffix) to avoid URL encoding issues with + in timezone offsets
	start := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	end := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)

	req := httptest.NewRequest("GET", "/api/audit/search?start="+start+"&end="+end+"&limit=10", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// handleDashboard (94.1%) — unhealthy targets counting
// ══════════════════════════════════════════════════════════════════════════════

type mixedHealthProvider struct {
	sm *session.Manager
}

func (m *mixedHealthProvider) SessionManager() *session.Manager { return m.sm }
func (m *mixedHealthProvider) PoolStats() map[string]pool.PoolStats {
	return map[string]pool.PoolStats{
		"pg":    {Target: "localhost:5432", Active: 2, Idle: 3, Total: 5, Max: 100, Healthy: true},
		"mysql": {Target: "localhost:3306", Active: 1, Idle: 0, Total: 1, Max: 50, Healthy: false},
	}
}

func TestHandleDashboardWithUnhealthyTargets(t *testing.T) {
	s := NewServer(&mixedHealthProvider{sm: session.NewManager(0, 0)}, ":0")

	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	w := httptest.NewRecorder()
	s.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	overview, ok := resp["overview"].(map[string]any)
	if !ok {
		t.Fatal("missing overview")
	}
	if overview["healthy_targets"] != float64(1) {
		t.Errorf("healthy_targets = %v, want 1", overview["healthy_targets"])
	}
	if overview["unhealthy_targets"] != float64(1) {
		t.Errorf("unhealthy_targets = %v, want 1", overview["unhealthy_targets"])
	}

	poolData, ok := resp["pool"].(map[string]any)
	if !ok {
		t.Fatal("missing pool")
	}
	if poolData["active_connections"] != float64(3) {
		t.Errorf("active_connections = %v, want 3", poolData["active_connections"])
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// handleCompact (91.7%) — max_age_hours parsing
// ══════════════════════════════════════════════════════════════════════════════

func TestHandleCompactWithMaxAgeHours(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(logPath, []byte{}, 0644)

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	req := httptest.NewRequest("POST", "/api/audit/compact?max_age_hours=48", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleCompactWithMaxAgeHoursZero(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(logPath, []byte{}, 0644)

	s := NewServer(newMockProvider(), ":0")
	s.SetAuditLogPath(logPath)

	req := httptest.NewRequest("POST", "/api/audit/compact?max_age_hours=0", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleCompactDotPath(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.auditLogPath = "audit.jsonl"

	req := httptest.NewRequest("POST", "/api/audit/compact", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// execPG and execMySQL — use fake docker binary for full coverage
// ══════════════════════════════════════════════════════════════════════════════

// buildFakeDocker creates a fake "docker" executable in a temp directory that
// outputs content based on the FAKE_DOCKER_MODE environment variable.
// Returns the temp dir path (to be prepended to PATH).
func buildFakeDocker(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	// Write a small Go program that acts as a fake docker
	src := filepath.Join(tmpDir, "fakedocker.go")
	bin := filepath.Join(tmpDir, "docker")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	goSrc := `package main

import (
	"fmt"
	"os"
)

func main() {
	mode := os.Getenv("FAKE_DOCKER_MODE")
	switch mode {
	case "pg_success":
		fmt.Println(" Alice | alice@example.com | 555-1234 | 85000")
		fmt.Println(" Bob   | bob@example.com   | 555-5678 | 92000")
		os.Exit(0)
	case "pg_masked":
		fmt.Println(" Alice | alice@***.com | ***-***-1234 | 85000")
		os.Exit(0)
	case "pg_access_denied":
		fmt.Print("ERROR:  Access denied: DDL not allowed for this user")
		os.Exit(1)
	case "pg_access_denied_multiline":
		fmt.Println("ERROR:  Access denied: DROP TABLE prohibited")
		fmt.Println("Some extra detail")
		os.Exit(1)
	case "pg_delete_no_where":
		fmt.Print("ERROR:  DELETE without WHERE clause is prohibited")
		os.Exit(1)
	case "pg_prohibited_no_access_denied":
		fmt.Print("This operation is prohibited by policy")
		os.Exit(1)
	case "pg_prohibited_with_access_denied":
		fmt.Print("something Access denied: bulk delete prohibited")
		os.Exit(1)
	case "pg_generic_error":
		fmt.Print("connection refused")
		os.Exit(1)
	case "pg_empty":
		os.Exit(0)
	case "mysql_success":
		fmt.Println("name\tprice\tstock")
		fmt.Println("Widget\t9.99\t100")
		fmt.Println("Gadget\t19.99\t50")
		os.Exit(0)
	case "mysql_error":
		fmt.Print("ERROR 2002 (HY000): Can't connect")
		os.Exit(1)
	case "mysql_empty":
		os.Exit(0)
	default:
		fmt.Print("unknown mode")
		os.Exit(1)
	}
}
`
	os.WriteFile(src, []byte(goSrc), 0644)

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build fake docker: %v\n%s", err, out)
	}

	return tmpDir
}

// withFakeDocker sets up a fake docker binary in PATH and runs the provided function.
func withFakeDocker(t *testing.T, mode string, fn func()) {
	t.Helper()
	fakeDir := buildFakeDocker(t)

	// Prepend fake dir to PATH
	origPath := os.Getenv("PATH")
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}
	os.Setenv("PATH", fakeDir+sep+origPath)
	os.Setenv("FAKE_DOCKER_MODE", mode)
	defer func() {
		os.Setenv("PATH", origPath)
		os.Unsetenv("FAKE_DOCKER_MODE")
	}()

	fn()
}

func TestExecPGSuccess(t *testing.T) {
	withFakeDocker(t, "pg_success", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "admin", SQL: "SELECT *", Database: "testdb"}
		result := execPG(cfg, "admin", "SELECT *", resp)

		if result.Action != "allow" {
			t.Errorf("action = %q, want allow", result.Action)
		}
		if result.Rows != 2 {
			t.Errorf("rows = %d, want 2", result.Rows)
		}
		if result.Masked {
			t.Error("should not be masked")
		}
	})
}

func TestExecPGMasked(t *testing.T) {
	withFakeDocker(t, "pg_masked", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "support", SQL: "SELECT *", Database: "testdb"}
		result := execPG(cfg, "support", "SELECT *", resp)

		if result.Action != "mask" {
			t.Errorf("action = %q, want mask", result.Action)
		}
		if !result.Masked {
			t.Error("should be masked")
		}
		if result.ColumnsMasked < 1 {
			t.Errorf("columns_masked = %d, want >= 1", result.ColumnsMasked)
		}
	})
}

func TestExecPGAccessDenied(t *testing.T) {
	withFakeDocker(t, "pg_access_denied", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "bob", SQL: "DROP TABLE users", Database: "testdb"}
		result := execPG(cfg, "bob", "DROP TABLE users", resp)

		if result.Action != "block" {
			t.Errorf("action = %q, want block", result.Action)
		}
		if result.Reason != "DDL not allowed for this user" {
			t.Errorf("reason = %q", result.Reason)
		}
	})
}

func TestExecPGAccessDeniedMultiline(t *testing.T) {
	withFakeDocker(t, "pg_access_denied_multiline", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "bob", SQL: "DROP TABLE users", Database: "testdb"}
		result := execPG(cfg, "bob", "DROP TABLE users", resp)

		if result.Action != "block" {
			t.Errorf("action = %q, want block", result.Action)
		}
		if result.Reason != "DROP TABLE prohibited" {
			t.Errorf("reason = %q", result.Reason)
		}
	})
}

func TestExecPGDeleteWithoutWhere(t *testing.T) {
	withFakeDocker(t, "pg_delete_no_where", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "bob", SQL: "DELETE FROM users", Database: "testdb"}
		result := execPG(cfg, "bob", "DELETE FROM users", resp)

		if result.Action != "block" {
			t.Errorf("action = %q, want block", result.Action)
		}
		// No "Access denied:" prefix, so reason is the full output
		if !strings.Contains(result.Reason, "DELETE without WHERE") {
			t.Errorf("reason = %q", result.Reason)
		}
	})
}

func TestExecPGProhibitedNoAccessDenied(t *testing.T) {
	withFakeDocker(t, "pg_prohibited_no_access_denied", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "bob", SQL: "DELETE FROM users", Database: "testdb"}
		result := execPG(cfg, "bob", "DELETE FROM users", resp)

		if result.Action != "block" {
			t.Errorf("action = %q, want block", result.Action)
		}
		// No "Access denied:" in output, so reason = full output
		if !strings.Contains(result.Reason, "prohibited") {
			t.Errorf("reason = %q", result.Reason)
		}
	})
}

func TestExecPGProhibitedWithAccessDenied(t *testing.T) {
	withFakeDocker(t, "pg_prohibited_with_access_denied", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "bob", SQL: "DELETE FROM users", Database: "testdb"}
		result := execPG(cfg, "bob", "DELETE FROM users", resp)

		if result.Action != "block" {
			t.Errorf("action = %q, want block", result.Action)
		}
		// Has both "prohibited" and "Access denied:", so reason is extracted after "Access denied: "
		if result.Reason != "bulk delete prohibited" {
			t.Errorf("reason = %q", result.Reason)
		}
	})
}

func TestExecPGGenericError(t *testing.T) {
	withFakeDocker(t, "pg_generic_error", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "admin", SQL: "SELECT 1", Database: "testdb"}
		result := execPG(cfg, "admin", "SELECT 1", resp)

		if result.Error != "connection refused" {
			t.Errorf("error = %q", result.Error)
		}
	})
}

func TestExecPGEmpty(t *testing.T) {
	withFakeDocker(t, "pg_empty", func() {
		cfg := &TestRunnerConfig{PGHost: "localhost", PGPort: 5432, PGPassword: "pass"}
		resp := TestRunResponse{User: "admin", SQL: "SELECT 1 WHERE false", Database: "testdb"}
		result := execPG(cfg, "admin", "SELECT 1 WHERE false", resp)

		if result.Action != "allow" {
			t.Errorf("action = %q, want allow", result.Action)
		}
		if result.Rows != 0 {
			t.Errorf("rows = %d, want 0", result.Rows)
		}
	})
}

func TestExecMySQLSuccess(t *testing.T) {
	withFakeDocker(t, "mysql_success", func() {
		cfg := &TestRunnerConfig{MySQLHost: "localhost", MySQLPort: 3306, MySQLUser: "test", MySQLPassword: "pass"}
		resp := TestRunResponse{User: "test", SQL: "SELECT *", Database: "testdb"}
		result := execMySQL(cfg, "SELECT *", resp)

		if result.Action != "allow" {
			t.Errorf("action = %q, want allow", result.Action)
		}
		if result.Rows != 3 {
			t.Errorf("rows = %d, want 3", result.Rows)
		}
	})
}

func TestExecMySQLError(t *testing.T) {
	withFakeDocker(t, "mysql_error", func() {
		cfg := &TestRunnerConfig{MySQLHost: "localhost", MySQLPort: 3306, MySQLUser: "test", MySQLPassword: "pass"}
		resp := TestRunResponse{User: "test", SQL: "SELECT 1", Database: "testdb"}
		result := execMySQL(cfg, "SELECT 1", resp)

		if result.Error == "" {
			t.Error("expected error")
		}
	})
}

func TestExecMySQLEmpty(t *testing.T) {
	withFakeDocker(t, "mysql_empty", func() {
		cfg := &TestRunnerConfig{MySQLHost: "localhost", MySQLPort: 3306, MySQLUser: "test", MySQLPassword: "pass"}
		resp := TestRunResponse{User: "test", SQL: "INSERT INTO x VALUES(1)", Database: "testdb"}
		result := execMySQL(cfg, "INSERT INTO x VALUES(1)", resp)

		if result.Action != "allow" {
			t.Errorf("action = %q, want allow", result.Action)
		}
		if result.Rows != 0 {
			t.Errorf("rows = %d, want 0", result.Rows)
		}
	})
}

// Test handleCompact where CompactLogs returns an error
func TestHandleCompactError(t *testing.T) {
	// Use a path whose Dir is an absolute path that doesn't exist as a directory
	s := NewServer(newMockProvider(), ":0")
	s.auditLogPath = "/nonexistent_dir_12345/subdir/audit.jsonl"

	req := httptest.NewRequest("POST", "/api/audit/compact", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// Test Start with a port that's already in use (triggers ListenAndServe error)
func TestStartListenError(t *testing.T) {
	// Bind a port first
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	// Try to start the server on the same port — ListenAndServe will fail
	s := NewServer(newMockProvider(), addr)
	err = s.Start()
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	// Give the goroutine time to fail
	time.Sleep(100 * time.Millisecond)
	s.Stop()
}

// ══════════════════════════════════════════════════════════════════════════════
// HandleWebSocket (91.3%) — Hijack error path
// ══════════════════════════════════════════════════════════════════════════════

type errorHijacker struct {
	http.ResponseWriter
}

func (e *errorHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, fmt.Errorf("hijack failed")
}

func TestHandleWebSocketHijackError(t *testing.T) {
	es := NewEventStream()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Key", "dGVzdA==")

	w := &errorHijacker{ResponseWriter: httptest.NewRecorder()}
	es.HandleWebSocket(w, r)

	if es.Count() != 0 {
		t.Errorf("clients = %d, want 0", es.Count())
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// readLoop (95.7%) — test the read error on extended header read
// ══════════════════════════════════════════════════════════════════════════════

func TestReadLoopReadErrorOnExtendedLength(t *testing.T) {
	es := NewEventStream()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &wsClient{conn: serverConn}
	es.add(client)

	go es.readLoop(client, bufio.NewReadWriter(
		bufio.NewReader(serverConn),
		bufio.NewWriter(serverConn),
	))

	// Send a frame with extended length indicator (126) but then close
	clientConn.Write([]byte{0x81, 126})
	time.Sleep(50 * time.Millisecond)
	clientConn.Close()

	time.Sleep(200 * time.Millisecond)

	if es.Count() != 0 {
		t.Errorf("clients = %d after read error, want 0", es.Count())
	}
}

func TestReadLoopPayloadWithoutMask(t *testing.T) {
	es := NewEventStream()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	client := &wsClient{conn: serverConn}
	es.add(client)

	go es.readLoop(client, bufio.NewReadWriter(
		bufio.NewReader(serverConn),
		bufio.NewWriter(serverConn),
	))

	// Send unmasked text frame with 5-byte payload
	frame := []byte{0x81, 0x05}
	frame = append(frame, []byte("hello")...)
	clientConn.Write(frame)
	time.Sleep(50 * time.Millisecond)

	// Then send close
	clientConn.Write([]byte{0x88, 0x00})
	time.Sleep(100 * time.Millisecond)
	clientConn.Close()

	time.Sleep(200 * time.Millisecond)
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{500 * time.Millisecond, "0s"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m 30s"},
		{5*time.Minute + 3*time.Second, "5m 3s"},
		{2*time.Hour + 15*time.Minute, "2h 15m"},
		{2*time.Hour + 15*time.Minute + 7*time.Second, "2h 15m 7s"},
		{25 * time.Hour, "1d 1h"},
		{48*time.Hour + 30*time.Minute + 10*time.Second, "2d 30m 10s"},
		{72*time.Hour + 2*time.Hour + 5*time.Minute + 1*time.Second, "3d 2h 5m 1s"},
		{24 * time.Hour, "1d"},
		{time.Hour, "1h"},
		{time.Minute, "1m"},
	}
	for _, tt := range tests {
		got := formatUptime(tt.d)
		if got != tt.want {
			t.Errorf("formatUptime(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
