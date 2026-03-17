package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyConfigUnmarshalEmpty(t *testing.T) {
	// Empty JSON — should use defaults
	cfg := DefaultConfig()
	content := `{
		"server": {"listeners": [{"address": ":5432", "protocol": "postgresql"}]},
		"pool": {"max_connections_per_target": 1, "connection_max_lifetime": "1h", "connection_timeout": "1s", "health_check_interval": "1s"},
		"metrics": {"enabled": false}
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.ReloadInterval.Seconds() != 5 {
		t.Errorf("default reload = %v", cfg.Policy.ReloadInterval)
	}
}

func TestExpandEnvValueNoMatch(t *testing.T) {
	// String without $ENV{} — should pass through
	result := ExpandEnvValue("plain string without env vars")
	if result != "plain string without env vars" {
		t.Errorf("result = %q", result)
	}
}

func TestExpandEnvValueBrokenSyntax(t *testing.T) {
	// $ENV{ without closing }
	result := ExpandEnvValue("broken $ENV{NO_CLOSE")
	if result != "broken $ENV{NO_CLOSE" {
		t.Errorf("broken syntax should pass through: %q", result)
	}
}

func TestPoolConfigUnmarshalEmpty(t *testing.T) {
	content := `{
		"server": {"listeners": [{"address": ":5432", "protocol": "postgresql"}]},
		"pool": {"max_connections_per_target": 5},
		"metrics": {"enabled": false}
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Pool.MaxConnectionsPerTarget != 5 {
		t.Errorf("pool max = %d", cfg.Pool.MaxConnectionsPerTarget)
	}
}
