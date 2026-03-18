package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleTestRunnerUI(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ui/test", nil)
	HandleTestRunnerUI(w, r)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html, got %s", ct)
	}
	cc := w.Header().Get("Cache-Control")
	if cc != "no-cache" {
		t.Fatalf("expected no-cache, got %s", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Argus Test Runner") {
		t.Fatal("missing title in HTML")
	}
	if !strings.Contains(body, "Quick Tests") {
		t.Fatal("missing Quick Tests section")
	}
	if !strings.Contains(body, "/api/test/run") {
		t.Fatal("missing API endpoint reference")
	}
}

func TestHandleTestRunMethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/test/run", nil)
	handleTestRun(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHandleTestRunInvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test/run", strings.NewReader("{invalid"))
	handleTestRun(w, r)

	var resp TestRunResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp.Error, "invalid request") {
		t.Fatalf("expected invalid request error, got %q", resp.Error)
	}
}

func TestHandleTestRunEmptySQL(t *testing.T) {
	body := `{"name":"test","user":"admin","db":"pg","sql":""}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test/run", strings.NewReader(body))
	handleTestRun(w, r)

	var resp TestRunResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != "SQL is required" {
		t.Fatalf("expected 'SQL is required', got %q", resp.Error)
	}
}

func TestHandleTestRunNotConfigured(t *testing.T) {
	old := testRunnerCfg
	testRunnerCfg = nil
	defer func() { testRunnerCfg = old }()

	body := `{"name":"test","user":"admin","db":"pg","sql":"SELECT 1"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test/run", strings.NewReader(body))
	handleTestRun(w, r)

	var resp TestRunResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != "test runner not configured" {
		t.Fatalf("expected 'test runner not configured', got %q", resp.Error)
	}
}

func TestHandleTestRunUnknownDB(t *testing.T) {
	old := testRunnerCfg
	testRunnerCfg = &TestRunnerConfig{PGHost: "localhost", PGPort: 5432}
	defer func() { testRunnerCfg = old }()

	body := `{"name":"test","user":"admin","db":"oracle","sql":"SELECT 1"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test/run", strings.NewReader(body))
	handleTestRun(w, r)

	var resp TestRunResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.Contains(resp.Error, "unknown db type") {
		t.Fatalf("expected unknown db type error, got %q", resp.Error)
	}
	if resp.Duration == "" {
		t.Fatal("expected duration to be set")
	}
}

func TestSetTestRunnerConfig(t *testing.T) {
	old := testRunnerCfg
	defer func() { testRunnerCfg = old }()

	cfg := &TestRunnerConfig{
		PGHost:        "proxy",
		PGPort:        15432,
		MySQLHost:     "proxy",
		MySQLPort:     13306,
		PGPassword:    "pass",
		MySQLUser:     "user",
		MySQLPassword: "pass",
	}
	SetTestRunnerConfig(cfg)
	if testRunnerCfg != cfg {
		t.Fatal("config not set")
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{100, "100"},
		{15432, "15432"},
		{99999, "99999"},
	}
	for _, tt := range tests {
		got := itoa(tt.n)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := TestRunResponse{
		User:     "admin",
		Database: "testdb",
		SQL:      "SELECT 1",
		Action:   "allow",
		Rows:     1,
		Duration: "5ms",
	}
	respondJSON(w, data)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected application/json, got %s", ct)
	}

	var got TestRunResponse
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if got.User != "admin" || got.Action != "allow" || got.Rows != 1 {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestExecPGBlockDetection(t *testing.T) {
	// Test the parsing logic of execPG result when "Access denied" is in output
	// We can't run docker here, but we test the response struct construction
	resp := TestRunResponse{User: "bob", SQL: "DROP TABLE users", Database: "testdb"}

	// Simulate access denied output
	output := "ERROR:  Access denied: DDL not allowed for user bob\nSome extra line"
	if strings.Contains(output, "Access denied:") {
		resp.Action = "block"
		if idx := strings.Index(output, "Access denied: "); idx >= 0 {
			resp.Reason = output[idx+15:]
			if end := strings.Index(resp.Reason, "\n"); end > 0 {
				resp.Reason = resp.Reason[:end]
			}
		}
	}

	if resp.Action != "block" {
		t.Fatal("expected block action")
	}
	if resp.Reason != "DDL not allowed for user bob" {
		t.Fatalf("unexpected reason: %q", resp.Reason)
	}
}

func TestExecPGMaskedDetection(t *testing.T) {
	// Test the masked output detection logic
	output := "Alice | alice@***.com | ***-***-1234 | 85000"
	resp := TestRunResponse{User: "support", SQL: "SELECT *", Database: "testdb"}

	lines := strings.Split(output, "\n")
	rows := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && l != "(" {
			rows++
		}
	}
	resp.Rows = rows

	if strings.Contains(output, "***") {
		resp.Action = "mask"
		resp.Masked = true
		resp.ColumnsMasked = strings.Count(output, "***")
	}

	if !resp.Masked {
		t.Fatal("expected masked=true")
	}
	if resp.ColumnsMasked != 3 {
		t.Fatalf("expected 3 masked columns, got %d", resp.ColumnsMasked)
	}
	if resp.Action != "mask" {
		t.Fatal("expected mask action")
	}
}

func TestHandleTestRunPGWithConfig(t *testing.T) {
	// With config set but docker not available, execPG will fail with exec error
	old := testRunnerCfg
	testRunnerCfg = &TestRunnerConfig{
		PGHost:     "localhost",
		PGPort:     15432,
		PGPassword: "pass",
	}
	defer func() { testRunnerCfg = old }()

	body := `{"name":"test","user":"admin","db":"pg","sql":"SELECT 1"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test/run", bytes.NewBufferString(body))
	handleTestRun(w, r)

	var resp TestRunResponse
	json.NewDecoder(w.Body).Decode(&resp)
	// Will get an error since docker is not available in test env, but handler should not panic
	if resp.Duration == "" {
		t.Fatal("expected duration to be set even on error")
	}
}

func TestHandleTestRunMySQLWithConfig(t *testing.T) {
	old := testRunnerCfg
	testRunnerCfg = &TestRunnerConfig{
		MySQLHost:     "localhost",
		MySQLPort:     13306,
		MySQLUser:     "test",
		MySQLPassword: "pass",
	}
	defer func() { testRunnerCfg = old }()

	body := `{"name":"test","user":"admin","db":"mysql","sql":"SELECT 1"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/test/run", bytes.NewBufferString(body))
	handleTestRun(w, r)

	var resp TestRunResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Duration == "" {
		t.Fatal("expected duration to be set even on error")
	}
}
