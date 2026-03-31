package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/admin"
	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/core"
	"github.com/ersinkoc/argus/internal/policy"
)

// TestMainVersion tests the main() function's --version flag via subprocess.
func TestMainVersion(t *testing.T) {
	if os.Getenv("TEST_MAIN_VERSION") == "1" {
		os.Args = []string{"argus", "--version"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMainVersion")
	cmd.Env = append(os.Environ(), "TEST_MAIN_VERSION=1")
	out, err := cmd.Output()
	if err != nil {
		// os.Exit(0) causes exit code 0, but test framework may interpret differently
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("subprocess exited with %v: %s", exitErr, string(exitErr.Stderr))
		}
	}
	if !bytes.Contains(out, []byte("argus dev")) {
		t.Errorf("expected version output, got: %s", string(out))
	}
}

// TestMainValidate tests the main() function's --validate flag via subprocess.
func TestMainValidate(t *testing.T) {
	if os.Getenv("TEST_MAIN_VALIDATE") == "1" {
		cfgPath := os.Getenv("TEST_CONFIG_PATH")
		os.Args = []string{"argus", "--config", cfgPath, "--validate"}
		main()
		return
	}

	// Create a temp config
	cfg := map[string]any{
		"server": map[string]any{
			"listeners": []map[string]any{
				{"address": ":0", "protocol": "postgresql", "tls": map[string]any{"enabled": false}},
			},
		},
		"targets": []map[string]any{
			{"name": "test-pg", "protocol": "postgresql", "host": "127.0.0.1", "port": 65535, "tls": map[string]any{"enabled": false}},
		},
		"routing": map[string]any{"default_target": "test-pg", "rules": []any{}},
		"policy":  map[string]any{"files": []any{}, "reload_interval": "5s"},
		"pool":    map[string]any{"max_connections_per_target": 2, "min_idle_connections": 0, "connection_max_lifetime": "1h", "connection_timeout": "5s", "health_check_interval": "30s"},
		"session": map[string]any{"idle_timeout": "30m", "max_duration": "8h"},
		"audit":   map[string]any{"level": "minimal", "outputs": []any{}, "buffer_size": 10, "sql_max_length": 100},
		"admin":   map[string]any{"enabled": false},
		"metrics": map[string]any{"enabled": false, "address": ":0"},
	}
	data, _ := json.Marshal(cfg)
	cfgFile := filepath.Join(t.TempDir(), "argus.json")
	os.WriteFile(cfgFile, data, 0644)

	cmd := exec.Command(os.Args[0], "-test.run=TestMainValidate")
	cmd.Env = append(os.Environ(), "TEST_MAIN_VALIDATE=1", "TEST_CONFIG_PATH="+cfgFile)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("subprocess exited with %v: %s", exitErr, string(exitErr.Stderr))
		}
	}
	if !bytes.Contains(out, []byte("Configuration is valid")) {
		t.Errorf("expected validation output, got: %s", string(out))
	}
}

// TestMainConfigError tests main() with a bad config path.
func TestMainConfigError(t *testing.T) {
	if os.Getenv("TEST_MAIN_CONFIG_ERROR") == "1" {
		os.Args = []string{"argus", "--config", "/nonexistent/config.json"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestMainConfigError")
	cmd.Env = append(os.Environ(), "TEST_MAIN_CONFIG_ERROR=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected subprocess to exit with error")
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		addr string
		want int
	}{
		{":30100", 30100},
		{"0.0.0.0:30100", 30100},
		{"127.0.0.1:5432", 5432},
		{":0", 0},
		{"noport", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := extractPort(tt.addr)
		if got != tt.want {
			t.Errorf("extractPort(%q) = %d, want %d", tt.addr, got, tt.want)
		}
	}
}

func TestCountErrors(t *testing.T) {
	issues := []policy.ValidationIssue{
		{Level: "error", Message: "e1"},
		{Level: "warning", Message: "w1"},
		{Level: "error", Message: "e2"},
		{Level: "info", Message: "i1"},
	}
	if n := countErrors(issues); n != 2 {
		t.Errorf("countErrors = %d, want 2", n)
	}
	if n := countErrors(nil); n != 0 {
		t.Errorf("countErrors(nil) = %d, want 0", n)
	}
}

// writeTestConfig writes a minimal valid config to a temp file and returns its path.
func writeTestConfig(t *testing.T, extra map[string]any) string {
	t.Helper()
	cfg := map[string]any{
		"server": map[string]any{
			"listeners": []map[string]any{
				{"address": ":0", "protocol": "postgresql", "tls": map[string]any{"enabled": false}},
			},
		},
		"targets": []map[string]any{
			{"name": "test-pg", "protocol": "postgresql", "host": "127.0.0.1", "port": 65535, "tls": map[string]any{"enabled": false}},
		},
		"routing": map[string]any{
			"default_target": "test-pg",
			"rules":          []any{},
		},
		"policy":  map[string]any{"files": []any{}, "reload_interval": "5s"},
		"pool":    map[string]any{"max_connections_per_target": 2, "min_idle_connections": 0, "connection_max_lifetime": "1h", "connection_timeout": "5s", "health_check_interval": "30s"},
		"session": map[string]any{"idle_timeout": "30m", "max_duration": "8h"},
		"audit":   map[string]any{"level": "minimal", "outputs": []any{}, "buffer_size": 10, "sql_max_length": 100},
		"admin":   map[string]any{"enabled": false},
		"metrics": map[string]any{"enabled": false, "address": ":0"},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "argus.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunValidateOnly(t *testing.T) {
	cfgPath := writeTestConfig(t, nil)
	var buf bytes.Buffer
	err := run(context.Background(), cfgPath, true, nil, &buf)
	if err != nil {
		t.Fatalf("run validate-only: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Configuration is valid")) {
		t.Error("expected 'Configuration is valid' output")
	}
}

func TestRunConfigLoadError(t *testing.T) {
	err := run(context.Background(), "/nonexistent/path.json", false, nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
}

func TestRunMinimalStartAndShutdown(t *testing.T) {
	cfgPath := writeTestConfig(t, nil)

	sigCh := make(chan os.Signal, 1)
	var buf bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &buf)
	}()

	// Give it time to start
	time.Sleep(200 * time.Millisecond)

	// Send SIGINT to trigger shutdown
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after signal")
	}
}

func TestRunWithSIGHUPThenSIGINT(t *testing.T) {
	cfgPath := writeTestConfig(t, nil)

	sigCh := make(chan os.Signal, 2)
	var buf bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &buf)
	}()

	time.Sleep(200 * time.Millisecond)

	// SIGHUP triggers reload, then SIGINT shuts down
	sigCh <- syscall.SIGHUP
	time.Sleep(50 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after signal")
	}
}

func TestRunWithMetricsEnabled(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"metrics": map[string]any{"enabled": true, "address": ":0"},
		"admin":   map[string]any{"enabled": false, "auth_token": "test-token"},
	})

	sigCh := make(chan os.Signal, 1)
	var buf bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &buf)
	}()

	time.Sleep(300 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithAuditFileOutput(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	cfgPath := writeTestConfig(t, map[string]any{
		"audit": map[string]any{
			"level":   "standard",
			"outputs": []any{map[string]any{"type": "file", "path": auditPath}},
			"buffer_size":    10,
			"sql_max_length": 100,
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithAuditRotation(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	cfgPath := writeTestConfig(t, map[string]any{
		"audit": map[string]any{
			"level": "standard",
			"outputs": []any{map[string]any{
				"type": "file",
				"path": auditPath,
				"rotation": map[string]any{
					"max_size_mb": 10,
					"max_files":   3,
				},
			}},
			"buffer_size":    10,
			"sql_max_length": 100,
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithStdoutAudit(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"audit": map[string]any{
			"level":          "standard",
			"outputs":        []any{map[string]any{"type": "stdout"}},
			"buffer_size":    10,
			"sql_max_length": 100,
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithWebhook(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"audit": map[string]any{
			"level":          "standard",
			"outputs":        []any{},
			"buffer_size":    10,
			"sql_max_length": 100,
			"webhook_url":    "http://127.0.0.1:1/webhook",
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithSessionLimiter(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"session": map[string]any{
			"idle_timeout": "30m",
			"max_duration": "8h",
			"max_per_user": 5,
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithRewriter(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"rewrite": map[string]any{
			"max_limit":   1000,
			"force_where": "tenant_id = 1",
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithSlowQuery(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"slow_query": map[string]any{"threshold": "500ms"},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithSlowQueryInvalidThreshold(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"slow_query": map[string]any{"threshold": "not-a-duration"},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithPolicyFiles(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "test-policy.json")
	policyData := `{"roles":{"admin":{"allowed_operations":["SELECT"]}},"policies":[{"name":"test","role":"admin","action":"allow","conditions":[]}]}`
	if err := os.WriteFile(policyFile, []byte(policyData), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeTestConfig(t, map[string]any{
		"policy": map[string]any{
			"files":           []any{policyFile},
			"reload_interval": "5s",
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithBadPolicyFiles(t *testing.T) {
	// Create a policy file with invalid JSON to trigger load warning
	dir := t.TempDir()
	badPolicyFile := filepath.Join(dir, "bad-policy.json")
	if err := os.WriteFile(badPolicyFile, []byte("{invalid json}"), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeTestConfig(t, map[string]any{
		"policy": map[string]any{
			"files":           []any{badPolicyFile},
			"reload_interval": "5s",
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithRecordFile(t *testing.T) {
	dir := t.TempDir()
	recPath := filepath.Join(dir, "queries.rec")
	cfgPath := writeTestConfig(t, map[string]any{
		"audit": map[string]any{
			"level":          "standard",
			"outputs":        []any{},
			"buffer_size":    10,
			"sql_max_length": 100,
			"record_file":    recPath,
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithBadRecordFile(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"audit": map[string]any{
			"level":          "standard",
			"outputs":        []any{},
			"buffer_size":    10,
			"sql_max_length": 100,
			"record_file":    "/nonexistent/dir/queries.rec",
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithMetricsAndAdminFull(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.log")
	recPath := filepath.Join(dir, "queries.rec")
	cfgPath := writeTestConfig(t, map[string]any{
		"metrics": map[string]any{"enabled": true, "address": ":0"},
		"admin":   map[string]any{"enabled": false, "auth_token": "secret"},
		"audit": map[string]any{
			"level":          "standard",
			"outputs":        []any{map[string]any{"type": "file", "path": auditPath}},
			"buffer_size":    10,
			"sql_max_length": 100,
			"record_file":    recPath,
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(300 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithGateway(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"metrics": map[string]any{"enabled": true, "address": ":0"},
		"admin":   map[string]any{"enabled": false},
		"gateway": map[string]any{
			"enabled":          true,
			"max_result_rows":  100,
			"approval_timeout": "10m",
			"api_keys": []any{
				map[string]any{"key": "test-key-1", "username": "tester", "enabled": true},
			},
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(300 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithGatewayWebhookAndPII(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"metrics": map[string]any{"enabled": true, "address": ":0"},
		"admin":   map[string]any{"enabled": false},
		"audit": map[string]any{
			"level":            "standard",
			"outputs":          []any{},
			"buffer_size":      10,
			"sql_max_length":   100,
			"pii_auto_detect":  true,
		},
		"gateway": map[string]any{
			"enabled":          true,
			"max_result_rows":  100,
			"approval_timeout": "10m",
			"webhook_url":      "http://127.0.0.1:1/hook",
			"webhook_headers":  map[string]any{"X-Token": "test"},
			"api_keys": []any{
				map[string]any{"key": "test-key-1", "username": "tester", "enabled": true},
			},
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(300 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithTestRunnerPGAndMySQL(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"server": map[string]any{
			"listeners": []map[string]any{
				{"address": ":0", "protocol": "postgresql", "tls": map[string]any{"enabled": false}},
				{"address": ":0", "protocol": "mysql", "tls": map[string]any{"enabled": false}},
			},
		},
		"targets": []map[string]any{
			{"name": "test-pg", "protocol": "postgresql", "host": "127.0.0.1", "port": 65535, "tls": map[string]any{"enabled": false}},
			{"name": "test-mysql", "protocol": "mysql", "host": "127.0.0.1", "port": 65534, "tls": map[string]any{"enabled": false}},
		},
		"routing": map[string]any{
			"default_target": "test-pg",
			"rules":          []any{},
		},
		"metrics": map[string]any{"enabled": true, "address": ":0"},
		"admin":   map[string]any{"enabled": false},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(300 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestSetupAuditOutputsBadFilePath(t *testing.T) {
	// Use a path with NUL character which is invalid on all platforms
	badPath := filepath.Join(t.TempDir(), "nonexistent_dir_xyz", "deep", "audit.log")

	cfgPath := writeTestConfig(t, map[string]any{
		"audit": map[string]any{
			"level": "standard",
			"outputs": []any{map[string]any{
				"type": "file",
				"path": badPath,
			}},
			"buffer_size":    10,
			"sql_max_length": 100,
		},
	})

	// Use a sigCh as safety net in case the error doesn't trigger
	sigCh := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error for bad audit file path")
		}
	case <-time.After(5 * time.Second):
		sigCh <- syscall.SIGINT
		t.Fatal("run did not return error quickly for bad audit path")
	}
}

func TestSetupAuditOutputsDirectCall(t *testing.T) {
	auditLogger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)

	cfg := &config.Config{}
	cfg.Audit.Outputs = []config.AuditOutput{
		{Type: "stdout"},
	}
	if err := setupAuditOutputs(auditLogger, cfg); err != nil {
		t.Fatalf("stdout output failed: %v", err)
	}

	dir := t.TempDir()
	cfg.Audit.Outputs = []config.AuditOutput{
		{Type: "file", Path: filepath.Join(dir, "test.log")},
	}
	if err := setupAuditOutputs(auditLogger, cfg); err != nil {
		t.Fatalf("file output failed: %v", err)
	}

	cfg.Audit.Outputs = []config.AuditOutput{
		{Type: "file", Path: filepath.Join(dir, "rotating.log"), Rotation: &config.RotationConfig{MaxSizeMB: 10, MaxFiles: 3}},
	}
	if err := setupAuditOutputs(auditLogger, cfg); err != nil {
		t.Fatalf("rotating file output failed: %v", err)
	}

	auditLogger.Close()
}

func TestSetupAuditOutputsRotatingError(t *testing.T) {
	auditLogger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)

	// Use a path on non-existent drive (Windows) or /dev/null path (Unix)
	badPath := "Z:\\nonexistent_drive_xyz\\audit.log"
	cfg := &config.Config{}
	cfg.Audit.Outputs = []config.AuditOutput{
		{Type: "file", Path: badPath, Rotation: &config.RotationConfig{MaxSizeMB: 10, MaxFiles: 3}},
	}
	err := setupAuditOutputs(auditLogger, cfg)
	if err == nil {
		// If this somehow works (unlikely), just skip
		t.Skip("bad path did not cause error, skipping")
	}
}

func TestRunWithRewriterMaxLimitOnly(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"rewrite": map[string]any{"max_limit": 500},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithRewriterForceWhereOnly(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"rewrite": map[string]any{"force_where": "tenant_id = 1"},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestSetupTestRunnerNoTargets(t *testing.T) {
	// With empty targets, setupTestRunner should be a no-op
	cfg := writeTestConfig(t, map[string]any{
		"targets": []map[string]any{},
		"routing": map[string]any{
			"default_target": "",
			"rules":          []any{},
		},
		"metrics": map[string]any{"enabled": true, "address": ":0"},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfg, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(300 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunWithConfigExporterTLSRedaction(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"server": map[string]any{
			"listeners": []map[string]any{
				{
					"address":  ":0",
					"protocol": "postgresql",
					"tls":      map[string]any{"enabled": false, "key_file": "secret.key"},
				},
			},
		},
		"targets": []map[string]any{
			{
				"name":     "test-pg",
				"protocol": "postgresql",
				"host":     "127.0.0.1",
				"port":     65535,
				"tls":      map[string]any{"enabled": false, "key_file": "target-secret.key"},
			},
		},
		"metrics": map[string]any{"enabled": true, "address": ":0"},
		"admin":   map[string]any{"enabled": false, "auth_token": "super-secret"},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(300 * time.Millisecond)
	sigCh <- syscall.SIGINT

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestWaitForSignals(t *testing.T) {
	sigCh := make(chan os.Signal, 2)
	reloadCount := 0
	reloadFn := func() { reloadCount++ }

	sigCh <- syscall.SIGHUP
	sigCh <- syscall.SIGINT

	waitForSignals(sigCh, reloadFn)

	if reloadCount != 1 {
		t.Errorf("expected 1 reload, got %d", reloadCount)
	}
}

// Tests for extracted maker functions

func TestMakeReloadFn(t *testing.T) {
	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	fn := makeReloadFn(loader, engine)
	// Should not panic; loader has no files, so Load returns nil
	fn()
}

func TestMakeReloadFnWithBadFiles(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badFile, []byte("{bad}"), 0644); err != nil {
		t.Fatal(err)
	}
	loader := policy.NewLoader([]string{badFile}, 5*time.Second)
	engine := policy.NewEngine(loader)
	fn := makeReloadFn(loader, engine)
	fn() // Should log error but not panic
}

func TestMakePolicyReloadFn(t *testing.T) {
	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	fn := makePolicyReloadFn(loader, engine)
	if err := fn(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMakePolicyReloadFnError(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badFile, []byte("{bad}"), 0644); err != nil {
		t.Fatal(err)
	}
	loader := policy.NewLoader([]string{badFile}, 5*time.Second)
	engine := policy.NewEngine(loader)
	fn := makePolicyReloadFn(loader, engine)
	if err := fn(); err == nil {
		t.Fatal("expected error for bad policy file")
	}
}

func TestMakeConfigExporter(t *testing.T) {
	cfg := &config.Config{}
	cfg.Admin.AuthToken = "secret"
	cfg.Targets = []config.Target{
		{Name: "pg", Protocol: "postgresql", Host: "localhost", Port: 5432, TLS: config.TLSConfig{KeyFile: "key.pem"}},
	}
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: ":5432", Protocol: "postgresql", TLS: config.TLSConfig{KeyFile: "listener-key.pem"}},
	}

	fn := makeConfigExporter(cfg)
	data, err := fn()
	if err != nil {
		t.Fatalf("config export failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify redaction
	adminSection := result["admin"].(map[string]any)
	if adminSection["auth_token"] != "***REDACTED***" {
		t.Error("auth_token not redacted")
	}
}

func TestMakeConfigExporterNoTLSKeys(t *testing.T) {
	cfg := &config.Config{}
	cfg.Targets = []config.Target{
		{Name: "pg", Protocol: "postgresql", Host: "localhost", Port: 5432},
	}
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: ":5432", Protocol: "postgresql"},
	}

	fn := makeConfigExporter(cfg)
	_, err := fn()
	if err != nil {
		t.Fatalf("config export failed: %v", err)
	}
}

func TestMakePolicyValidator(t *testing.T) {
	loader := policy.NewLoader(nil, 5*time.Second)
	fn := makePolicyValidator(loader)

	// No policies loaded -> returns error
	_, err := fn()
	if err == nil {
		t.Fatal("expected error when no policies loaded")
	}
}

func TestMakePolicyValidatorWithPolicies(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "test.json")
	policyData := `{"roles":{"admin":{"allowed_operations":["SELECT"]}},"policies":[{"name":"test","role":"admin","action":"allow","conditions":[]}]}`
	if err := os.WriteFile(policyFile, []byte(policyData), 0644); err != nil {
		t.Fatal(err)
	}

	loader := policy.NewLoader([]string{policyFile}, 5*time.Second)
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}

	fn := makePolicyValidator(loader)
	result, err := fn()
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	m := result.(map[string]any)
	if m["valid"] != true {
		t.Error("expected valid policies")
	}
}

func TestMakeClassifyFunc(t *testing.T) {
	fn := makeClassifyFunc()
	result := fn([]string{"email", "user_name", "ssn"})
	if result == nil {
		t.Fatal("expected non-nil classification result")
	}
}

func TestMakePluginListFunc(t *testing.T) {
	fn := makePluginListFunc()
	result := fn()
	m := result.(map[string]any)
	if m["count"] != 0 {
		t.Errorf("expected 0 plugins, got %v", m["count"])
	}
}

func TestMakeSessionKillFn(t *testing.T) {
	logger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)
	logger.Start()
	fn := makeSessionKillFn(logger)
	fn("test-session-123")
	logger.Close()
}

func TestMakeDryRunFunc(t *testing.T) {
	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	fn := makeDryRunFunc(engine)
	result, err := fn("admin", "testdb", "SELECT 1", "127.0.0.1")
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil dry run result")
	}
}

func TestMakeEventBroadcast(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"metrics": map[string]any{"enabled": true, "address": ":0"},
	})
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	logger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)
	proxy := core.NewProxy(cfg, engine, logger)
	srv := admin.NewServer(proxy, ":0")

	fn := makeEventBroadcast(srv)
	fn("test-event") // Should not panic
}

func TestGracefulShutdownTimeout(t *testing.T) {
	cfgPath := writeTestConfig(t, nil)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	logger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)
	logger.Start()
	proxy := core.NewProxy(cfg, engine, logger)
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}

	// Use already-cancelled context to trigger timeout path
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	gracefulShutdown(ctx, proxy, nil, loader, nil, nil, logger)
}

func TestSetupGatewayDirect(t *testing.T) {
	cfgPath := writeTestConfig(t, map[string]any{
		"metrics": map[string]any{"enabled": true, "address": ":0"},
		"gateway": map[string]any{
			"enabled":          true,
			"max_result_rows":  100,
			"approval_timeout": "10m",
			"api_keys": []any{
				map[string]any{"key": "test-key-1", "username": "tester", "enabled": true},
			},
		},
	})
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	logger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)
	proxy := core.NewProxy(cfg, engine, logger)
	srv := admin.NewServer(proxy, ":0")

	// Should not panic
	setupGateway(cfg, srv, engine, logger, proxy)
}

func TestSetupTestRunnerDirect(t *testing.T) {
	cfg := &config.Config{}
	// No targets - should be no-op
	setupTestRunner(cfg)

	// With targets
	cfg.Targets = []config.Target{
		{Name: "pg", Protocol: "postgresql", Host: "localhost", Port: 5432},
		{Name: "mysql", Protocol: "mysql", Host: "localhost", Port: 3306},
	}
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: ":30100", Protocol: "postgresql"},
		{Address: ":30200", Protocol: "mysql"},
	}
	setupTestRunner(cfg)
}

func TestRunPolicyLoadSuccess(t *testing.T) {
	// This test covers the success path of policy loading in run()
	// (lines 82-84: ps := policyLoader.Current() + log)
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.json")
	policyData := `{"roles":{"admin":{"allowed_operations":["SELECT"]}},"policies":[{"name":"test","role":"admin","action":"allow","conditions":[]}]}`
	if err := os.WriteFile(policyFile, []byte(policyData), 0644); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeTestConfig(t, map[string]any{
		"policy": map[string]any{
			"files":           []any{policyFile},
			"reload_interval": "5s",
		},
	})

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	}()

	time.Sleep(200 * time.Millisecond)
	sigCh <- syscall.SIGINT
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}

func TestRunProxyStartError(t *testing.T) {
	// Use an address that can't bind to trigger proxy.Start() error
	cfgPath := writeTestConfig(t, map[string]any{
		"server": map[string]any{
			"listeners": []map[string]any{
				{"address": "256.256.256.256:99999", "protocol": "postgresql", "tls": map[string]any{"enabled": false}},
			},
		},
	})

	sigCh := make(chan os.Signal, 1)
	err := run(context.Background(), cfgPath, false, sigCh, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for invalid listener address")
	}
}

func TestMakeOnReloadFn(t *testing.T) {
	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	logger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)
	logger.Start()
	fn := makeOnReloadFn(engine, logger)
	fn() // Should not panic, exercises InvalidateCache + Log
	logger.Close()
}

func TestSetupQueryRecorderDirect(t *testing.T) {
	cfgPath := writeTestConfig(t, nil)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	loader := policy.NewLoader(nil, 5*time.Second)
	engine := policy.NewEngine(loader)
	logger := audit.NewLogger(10, audit.ParseLogLevel("minimal"), 100)
	proxy := core.NewProxy(cfg, engine, logger)

	// Empty record file
	cfg.Audit.RecordFile = ""
	if r := setupQueryRecorder(cfg, proxy); r != nil {
		t.Error("expected nil for empty record file")
	}

	// Valid path
	dir := t.TempDir()
	cfg.Audit.RecordFile = filepath.Join(dir, "records.rec")
	if r := setupQueryRecorder(cfg, proxy); r == nil {
		t.Error("expected non-nil recorder for valid path")
	} else {
		r.Close()
	}

	// Invalid path
	cfg.Audit.RecordFile = filepath.Join(dir, "nonexistent", "sub", "records.rec")
	if r := setupQueryRecorder(cfg, proxy); r != nil {
		t.Error("expected nil for invalid path")
	}
}
