package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePolicyPaths(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{Files: []string{"policies/default.json"}},
	}

	ResolvePolicyPaths(cfg, "/etc/argus/argus.json")

	if cfg.Policy.Files[0] != "/etc/argus/policies/default.json" {
		t.Errorf("resolved = %q", cfg.Policy.Files[0])
	}
}

func TestResolvePolicyPathsAbsolute(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{Files: []string{"/absolute/path/policy.json"}},
	}

	ResolvePolicyPaths(cfg, "/etc/argus/argus.json")

	// Absolute paths should not be modified
	if cfg.Policy.Files[0] != "/absolute/path/policy.json" {
		t.Errorf("absolute path should not change: %q", cfg.Policy.Files[0])
	}
}

func TestResolvePolicyPathsEmptyConfig(t *testing.T) {
	cfg := &Config{}
	ResolvePolicyPaths(cfg, "") // should not panic
}

func TestLoadEmptyPath(t *testing.T) {
	// Load with empty path uses defaults
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if len(cfg.Server.Listeners) != 1 {
		t.Error("should have default listener")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not json{{{"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("should fail on invalid JSON")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/file.json")
	if err == nil {
		t.Error("should fail on nonexistent file")
	}
}

func TestPolicyConfigUnmarshal(t *testing.T) {
	content := `{
		"server": {"listeners": [{"address": ":5432", "protocol": "postgresql"}]},
		"targets": [{"name": "t", "host": "h", "port": 5432, "protocol": "postgresql"}],
		"routing": {"default_target": "t"},
		"policy": {"files": ["a.json", "b.json"], "reload_interval": "10s"},
		"pool": {"max_connections_per_target": 10, "connection_max_lifetime": "1h", "connection_timeout": "5s", "health_check_interval": "30s"},
		"metrics": {"enabled": false}
	}`

	dir := t.TempDir()

	// Create policy files so validation passes
	os.WriteFile(filepath.Join(dir, "a.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(dir, "b.json"), []byte("{}"), 0644)

	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Policy.Files) != 2 {
		t.Errorf("policy files = %d, want 2", len(cfg.Policy.Files))
	}
	if cfg.Policy.ReloadInterval.Seconds() != 10 {
		t.Errorf("reload interval = %v, want 10s", cfg.Policy.ReloadInterval)
	}
}

func TestValidateTargetInvalidPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 0}}
	err := Validate(cfg)
	if err == nil {
		t.Error("port 0 should fail validation")
	}

	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 99999}}
	err = Validate(cfg)
	if err == nil {
		t.Error("port 99999 should fail validation")
	}
}

func TestValidateTargetNoName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Targets = []Target{{Name: "", Host: "h", Port: 5432}}
	err := Validate(cfg)
	if err == nil {
		t.Error("empty target name should fail")
	}
}

func TestValidateTargetNoHost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Targets = []Target{{Name: "t", Host: "", Port: 5432}}
	err := Validate(cfg)
	if err == nil {
		t.Error("empty host should fail")
	}
}
