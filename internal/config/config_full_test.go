package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigWithNewFields(t *testing.T) {
	content := `{
		"server": {"listeners": [{"address": ":15432", "protocol": "postgresql"}]},
		"targets": [{"name": "pg", "host": "localhost", "port": 5432, "protocol": "postgresql"}],
		"routing": {"default_target": "pg"},
		"pool": {"max_connections_per_target": 10, "min_idle_connections": 2, "connection_max_lifetime": "1h", "connection_timeout": "5s", "health_check_interval": "10s"},
		"session": {"idle_timeout": "15m", "max_duration": "4h", "max_per_user": 5},
		"audit": {"level": "standard", "outputs": [{"type": "stdout"}], "buffer_size": 1000, "sql_max_length": 4096, "pii_auto_detect": true, "record_file": "/tmp/queries.jsonl"},
		"metrics": {"enabled": true, "address": ":9091"},
		"rewrite": {"max_limit": 5000, "force_where": "org_id = 1"},
		"slow_query": {"threshold": "2s"}
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Session.MaxPerUser != 5 {
		t.Errorf("max_per_user = %d, want 5", cfg.Session.MaxPerUser)
	}
	if cfg.Rewrite.MaxLimit != 5000 {
		t.Errorf("max_limit = %d, want 5000", cfg.Rewrite.MaxLimit)
	}
	if cfg.Rewrite.ForceWhere != "org_id = 1" {
		t.Errorf("force_where = %q", cfg.Rewrite.ForceWhere)
	}
	if cfg.SlowQuery.Threshold != "2s" {
		t.Errorf("threshold = %q", cfg.SlowQuery.Threshold)
	}
	if !cfg.Audit.PIIAutoDetect {
		t.Error("pii_auto_detect should be true")
	}
	if cfg.Audit.RecordFile != "/tmp/queries.jsonl" {
		t.Errorf("record_file = %q", cfg.Audit.RecordFile)
	}
}

func TestValidateListenerProtocolMismatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Listeners = []ListenerConfig{{Address: ":5432", Protocol: "mysql"}}
	cfg.Targets = []Target{{Name: "pg", Host: "localhost", Port: 5432, Protocol: "postgresql"}}

	err := Validate(cfg)
	if err == nil {
		t.Error("should fail: listener protocol mysql has no matching target")
	}
}

func TestExpandEnvValueMultiple(t *testing.T) {
	t.Setenv("A", "hello")
	t.Setenv("B", "world")

	result := ExpandEnvValue("$ENV{A} $ENV{B}")
	if result != "hello world" {
		t.Errorf("got %q, want 'hello world'", result)
	}
}

func TestExpandEnvValueNotSet(t *testing.T) {
	result := ExpandEnvValue("$ENV{NONEXISTENT_VAR_12345}")
	if result != "" {
		t.Errorf("got %q, want empty", result)
	}
}

func TestPoolConfigUnmarshal(t *testing.T) {
	content := `{
		"server": {"listeners": [{"address": ":5432", "protocol": "postgresql"}]},
		"targets": [{"name": "t", "host": "h", "port": 5432, "protocol": "postgresql"}],
		"routing": {"default_target": "t"},
		"pool": {"max_connections_per_target": 50, "connection_max_lifetime": "2h30m", "connection_timeout": "15s", "health_check_interval": "1m"},
		"metrics": {"enabled": false}
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Pool.ConnectionMaxLifetime.Hours() != 2.5 {
		t.Errorf("lifetime = %v, want 2h30m", cfg.Pool.ConnectionMaxLifetime)
	}
}
