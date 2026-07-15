package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Server.Listeners) != 1 {
		t.Errorf("default should have 1 listener, got %d", len(cfg.Server.Listeners))
	}
	if cfg.Server.Listeners[0].Address != ":15432" {
		t.Errorf("default listener address = %q, want %q", cfg.Server.Listeners[0].Address, ":15432")
	}
	if cfg.Pool.MaxConnectionsPerTarget != 100 {
		t.Errorf("default pool max = %d, want 100", cfg.Pool.MaxConnectionsPerTarget)
	}
	if cfg.Audit.Level != "standard" {
		t.Errorf("default audit level = %q, want %q", cfg.Audit.Level, "standard")
	}
}

func TestLoadConfig(t *testing.T) {
	content := `{
		"server": {
			"listeners": [{"address": ":25432", "protocol": "postgresql"}]
		},
		"targets": [
			{"name": "test-pg", "host": "localhost", "port": 5432, "protocol": "postgresql"}
		],
		"routing": {"default_target": "test-pg"},
		"pool": {
			"max_connections_per_target": 50,
			"min_idle_connections": 2,
			"connection_max_lifetime": "30m",
			"connection_timeout": "5s",
			"health_check_interval": "10s"
		},
		"session": {
			"idle_timeout": "15m",
			"max_duration": "4h"
		},
		"audit": {
			"level": "verbose",
			"outputs": [{"type": "stdout"}],
			"buffer_size": 5000,
			"sql_max_length": 2048
		},
		"metrics": {"enabled": true, "address": ":9091"}
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "argus.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Listeners[0].Address != ":25432" {
		t.Errorf("listener address = %q, want %q", cfg.Server.Listeners[0].Address, ":25432")
	}
	if cfg.Pool.MaxConnectionsPerTarget != 50 {
		t.Errorf("pool max = %d, want 50", cfg.Pool.MaxConnectionsPerTarget)
	}
	if cfg.Audit.Level != "verbose" {
		t.Errorf("audit level = %q, want %q", cfg.Audit.Level, "verbose")
	}
	if cfg.Session.IdleTimeout.Minutes() != 15 {
		t.Errorf("idle timeout = %v, want 15m", cfg.Session.IdleTimeout)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{"valid default", func(c *Config) {}, false},
		{"no listeners", func(c *Config) { c.Server.Listeners = nil }, true},
		{"empty address", func(c *Config) { c.Server.Listeners[0].Address = "" }, true},
		{"bad protocol", func(c *Config) { c.Server.Listeners[0].Protocol = "oracle" }, true},
		{"mongodb protocol allowed", func(c *Config) {
			c.Server.Listeners[0].Protocol = "mongodb"
			c.Targets = []Target{{Name: "mongo", Host: "localhost", Port: 27017, Protocol: "mongodb"}}
			c.Routing.DefaultTarget = "mongo"
		}, false},
		{"tls without cert", func(c *Config) {
			c.Server.Listeners[0].TLS.Enabled = true
		}, true},
		{"bad audit level", func(c *Config) { c.Audit.Level = "debug" }, true},
		{"bad overflow policy", func(c *Config) { c.Audit.OverflowPolicy = "backpressure" }, true},
		{"valid overflow policy", func(c *Config) { c.Audit.OverflowPolicy = "block" }, false},
		{"bad pool max", func(c *Config) { c.Pool.MaxConnectionsPerTarget = 0 }, true},
		{"mtls without client_ca_file", func(c *Config) {
			c.Server.Listeners[0].TLS = TLSConfig{
				Enabled: true, CertFile: "c.crt", KeyFile: "c.key", ClientAuth: true,
			}
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := Validate(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestResolveTarget(t *testing.T) {
	cfg := &Config{
		Targets: []Target{
			{Name: "prod-pg", Host: "db-prod", Port: 5432},
			{Name: "staging-pg", Host: "db-staging", Port: 5432},
		},
		Routing: RoutingConfig{
			DefaultTarget: "prod-pg",
			Rules: []RoutingRule{
				{Database: "staging_*", Target: "staging-pg"},
			},
		},
	}

	target := cfg.ResolveTarget("staging_app")
	if target == nil || target.Name != "staging-pg" {
		t.Errorf("staging_app should route to staging-pg, got %v", target)
	}

	target = cfg.ResolveTarget("production")
	if target == nil || target.Name != "prod-pg" {
		t.Errorf("production should route to prod-pg (default), got %v", target)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("ARGUS_AUDIT_LEVEL", "verbose")
	t.Setenv("ARGUS_METRICS_ADDRESS", ":8080")

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	if cfg.Audit.Level != "verbose" {
		t.Errorf("audit level = %q, want %q", cfg.Audit.Level, "verbose")
	}
	if cfg.Metrics.Address != ":8080" {
		t.Errorf("metrics address = %q, want %q", cfg.Metrics.Address, ":8080")
	}
}

func TestTLSConfigDefaultsToVerifyWhenOmitted(t *testing.T) {
	var tlsCfg TLSConfig
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &tlsCfg); err != nil {
		t.Fatal(err)
	}
	if !tlsCfg.BackendVerifyEnabled() {
		t.Fatal("expected backend verify to default to enabled when verify is omitted")
	}
}

func TestTLSConfigExplicitVerifyFalseRemainsInsecure(t *testing.T) {
	var tlsCfg TLSConfig
	if err := json.Unmarshal([]byte(`{"enabled":true,"verify":false}`), &tlsCfg); err != nil {
		t.Fatal(err)
	}
	if tlsCfg.BackendVerifyEnabled() {
		t.Fatal("expected explicit verify=false to disable backend verification for compatibility")
	}
}

func TestTLSConfigSkipVerifyOverridesVerify(t *testing.T) {
	var tlsCfg TLSConfig
	if err := json.Unmarshal([]byte(`{"enabled":true,"verify":true,"skip_verify":true}`), &tlsCfg); err != nil {
		t.Fatal(err)
	}
	if tlsCfg.BackendVerifyEnabled() {
		t.Fatal("expected skip_verify=true to disable backend verification")
	}
}

func TestExpandEnvValue(t *testing.T) {
	t.Setenv("DB_HOST", "myhost.local")
	result := ExpandEnvValue("$ENV{DB_HOST}")
	if result != "myhost.local" {
		t.Errorf("got %q, want %q", result, "myhost.local")
	}

	result = ExpandEnvValue("prefix_$ENV{DB_HOST}_suffix")
	if result != "prefix_myhost.local_suffix" {
		t.Errorf("got %q, want %q", result, "prefix_myhost.local_suffix")
	}
}

func TestExpandFileValue(t *testing.T) {
	td := t.TempDir()
	secretPath := td + "/db_password"
	if err := os.WriteFile(secretPath, []byte("supersecret\n"), 0644); err != nil {
		t.Fatal(err)
	}

	result := ExpandEnvValue("$FILE{" + secretPath + "}")
	if result != "supersecret" {
		t.Errorf("got %q, want %q", result, "supersecret")
	}

	result = ExpandEnvValue("prefix_$FILE{" + secretPath + "}_suffix")
	if result != "prefix_supersecret_suffix" {
		t.Errorf("got %q, want %q", result, "prefix_supersecret_suffix")
	}
}

func TestExpandFileValueNonexistent(t *testing.T) {
	result := ExpandEnvValue("$FILE{/nonexistent/secret/key}")
	if result != "" {
		t.Errorf("got %q, want empty string for non-existent file", result)
	}
}

func TestExpandFileValueNoTrailingNewline(t *testing.T) {
	td := t.TempDir()
	path := td + "/token"
	if err := os.WriteFile(path, []byte("my-api-token"), 0644); err != nil {
		t.Fatal(err)
	}

	result := ExpandEnvValue("$FILE{" + path + "}")
	if result != "my-api-token" {
		t.Errorf("got %q, want %q", result, "my-api-token")
	}
}

func TestExpandMixedEnvAndFile(t *testing.T) {
	t.Setenv("DB_USER", "admin")
	td := t.TempDir()
	path := td + "/secret"
	if err := os.WriteFile(path, []byte("fileval"), 0644); err != nil {
		t.Fatal(err)
	}

	result := ExpandEnvValue("user=$ENV{DB_USER};password=$FILE{" + path + "}")
	if result != "user=admin;password=fileval" {
		t.Errorf("got %q, want %q", result, "user=admin;password=fileval")
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"prod_*", "prod_db", true},
		{"prod_*", "staging_db", false},
		{"*_log", "audit_log", true},
		{"exact", "exact", true},
		{"exact", "other", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}
