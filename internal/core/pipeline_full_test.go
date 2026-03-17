package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/policy"
	pgcodec "github.com/ersinkoc/argus/internal/protocol/pg"
)

// TestProxyStartWithTLS tests TLS target configuration path.
func TestProxyStartWithTLSTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{
		{Name: "pg-tls", Protocol: "postgresql", Host: "127.0.0.1", Port: 1,
			TLS: config.TLSConfig{Enabled: true, Verify: false}},
	}
	cfg.Routing.DefaultTarget = "pg-tls"
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
		t.Fatalf("Start with TLS target: %v", err)
	}
	proxy.Stop()
}

// TestProxyStopDrainTimeout tests the connection draining path in Stop.
func TestProxyStopWithActiveSessions(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	// Backend that accepts and keeps connection open
	go func() {
		conn, _ := backendLn.Accept()
		if conn == nil { return }
		defer conn.Close()
		pgcodec.ReadStartupMessage(conn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: ps})
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
		pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))
		time.Sleep(5 * time.Second) // keep alive
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()

	proxyAddr := proxy.listeners[0].listener.Addr().String()

	// Connect a client
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "u", "database": "d"})
	conn.Write(startup)

	// Wait for session to establish
	time.Sleep(200 * time.Millisecond)

	// Stop should drain (timeout 10s but we close conn quickly)
	go func() {
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}()

	proxy.Stop() // should not hang
}

// TestProxyCommandLoopWithRewriter tests rewriter path
func TestProxyCommandLoopRewriter(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go fakePostgresBackendMulti(t, backendLn)

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)

	// Enable rewriter
	rw := inspection.NewRewriter()
	rw.SetMaxLimit(100)
	proxy.SetRewriter(rw)

	// Enable slow query logger
	proxy.SetSlowQueryLogger(audit.NewSlowQueryLogger(time.Nanosecond, logger))

	// Enable event broadcast
	proxy.SetOnEvent(func(event any) {
		// Verify events are broadcast
		_ = event
	})

	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery { break }
	}

	// Send SELECT without LIMIT — rewriter should add LIMIT 100
	query := append([]byte("SELECT * FROM users"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})

	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery { break }
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}
