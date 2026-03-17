package config

import "testing"

func TestApplyEnvOverridesFull(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 5432}}

	t.Setenv("ARGUS_AUDIT_LEVEL", "verbose")
	t.Setenv("ARGUS_AUDIT_BUFFER_SIZE", "99999")
	t.Setenv("ARGUS_METRICS_ENABLED", "true")
	t.Setenv("ARGUS_METRICS_ADDRESS", ":8888")
	t.Setenv("ARGUS_ADMIN_ENABLED", "1")
	t.Setenv("ARGUS_ADMIN_ADDRESS", ":7777")
	t.Setenv("ARGUS_ADMIN_AUTH_TOKEN", "secret123")
	t.Setenv("ARGUS_POOL_MAX_CONNECTIONS_PER_TARGET", "999")
	t.Setenv("ARGUS_SESSION_IDLE_TIMEOUT", "45m")
	t.Setenv("ARGUS_SESSION_MAX_DURATION", "12h")
	t.Setenv("ARGUS_ROUTING_DEFAULT_TARGET", "custom-target")
	t.Setenv("ARGUS_TARGETS_0_HOST", "overridden-host")
	t.Setenv("ARGUS_TARGETS_0_PORT", "9999")
	t.Setenv("ARGUS_SERVER_LISTENERS_0_ADDRESS", ":55555")

	applyEnvOverrides(cfg)

	if cfg.Audit.Level != "verbose" { t.Errorf("audit level = %q", cfg.Audit.Level) }
	if cfg.Audit.BufferSize != 99999 { t.Errorf("buffer = %d", cfg.Audit.BufferSize) }
	if !cfg.Metrics.Enabled { t.Error("metrics should be enabled") }
	if cfg.Metrics.Address != ":8888" { t.Errorf("metrics addr = %q", cfg.Metrics.Address) }
	if !cfg.Admin.Enabled { t.Error("admin should be enabled") }
	if cfg.Admin.Address != ":7777" { t.Errorf("admin addr = %q", cfg.Admin.Address) }
	if cfg.Admin.AuthToken != "secret123" { t.Errorf("auth token = %q", cfg.Admin.AuthToken) }
	if cfg.Pool.MaxConnectionsPerTarget != 999 { t.Errorf("pool max = %d", cfg.Pool.MaxConnectionsPerTarget) }
	if cfg.Routing.DefaultTarget != "custom-target" { t.Errorf("default = %q", cfg.Routing.DefaultTarget) }
	if cfg.Targets[0].Host != "overridden-host" { t.Errorf("host = %q", cfg.Targets[0].Host) }
	if cfg.Targets[0].Port != 9999 { t.Errorf("port = %d", cfg.Targets[0].Port) }
	if cfg.Server.Listeners[0].Address != ":55555" { t.Errorf("addr = %q", cfg.Server.Listeners[0].Address) }
}
