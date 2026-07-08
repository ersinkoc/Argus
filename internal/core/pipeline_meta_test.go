package core

import (
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/policy"
)

func TestProxyStartStop(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: "127.0.0.1:0", Protocol: "postgresql"},
	}
	cfg.Pool.MinIdleConnections = 0

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)

	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	err := proxy.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Verify listener is active
	if len(proxy.listeners) != 1 {
		t.Errorf("listeners = %d, want 1", len(proxy.listeners))
	}

	// PoolStats should return targets (0 since no targets configured)
	stats := proxy.PoolStats()
	if stats == nil {
		t.Error("PoolStats should not be nil")
	}

	// Stop should be graceful
	proxy.Stop()
}

func TestProxyStartWithTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: "127.0.0.1:0", Protocol: "postgresql"},
	}
	cfg.Targets = []config.Target{
		{Name: "test-pg", Protocol: "postgresql", Host: "127.0.0.1", Port: 1},
	}
	cfg.Routing.DefaultTarget = "test-pg"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)

	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	err := proxy.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	stats := proxy.PoolStats()
	if len(stats) != 1 {
		t.Errorf("pool stats = %d, want 1 target", len(stats))
	}

	time.Sleep(50 * time.Millisecond)
	proxy.Stop()
}

func TestListenerStartTLS(t *testing.T) {
	// TLS without cert should fail
	l := NewListener(config.ListenerConfig{
		Address:  "127.0.0.1:0",
		Protocol: "postgresql",
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	})
	err := l.Start()
	if err == nil {
		t.Error("TLS with missing cert should fail")
		l.Stop()
	}
}
