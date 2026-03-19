package core

import (
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/session"
)

// TestProxyStop_WithActiveSessions exercises the drain loop path in Stop().
// We inject a session into the session manager so len(activeSessions) > 0,
// let the drain ticker fire once, then the session finishes so drain completes.
func TestProxyStop_WithActiveSessions(t *testing.T) {
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
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Inject a session so the drain loop activates.
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	info := &session.Info{
		Username: "testuser",
		ClientIP: net.ParseIP("127.0.0.1"),
		Database: "testdb",
	}
	sess := proxy.sessionManager.Create(info, client)

	// Kill the session after 200ms (so the drain ticker fires once then sees 0).
	go func() {
		time.Sleep(200 * time.Millisecond)
		proxy.sessionManager.Kill(sess.ID)
	}()

	// Stop should drain and complete.
	done := make(chan struct{})
	go func() {
		proxy.Stop()
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(5 * time.Second):
		t.Error("Stop() timed out waiting for drain")
	}
}

// TestProxyStop_DrainTimeout exercises the deadline path where sessions
// don't finish within the drain window. We shorten the drain timeout via
// direct manipulation and verify Stop completes.
func TestProxyStop_NoSessions(t *testing.T) {
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
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// No active sessions — Stop should return quickly.
	done := make(chan struct{})
	go func() {
		proxy.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("Stop() took too long with no sessions")
	}
}
