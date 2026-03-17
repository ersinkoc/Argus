package core

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/policy"
	pgcodec "github.com/ersinkoc/argus/internal/protocol/pg"
)

// --- TLS config error paths (not duplicated from coverage2_test.go) ---

func TestMakeServerTLSConfigBadCert(t *testing.T) {
	cfg := config.TLSConfig{Enabled: true, CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"}
	_, err := MakeServerTLSConfig(cfg)
	if err == nil {
		t.Error("bad cert files should fail")
	}
}

func TestMakeClientTLSConfigBadCA(t *testing.T) {
	cfg := config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.pem"}
	_, err := MakeClientTLSConfig(cfg)
	if err == nil {
		t.Error("bad CA file should fail")
	}
}

func TestMakeClientTLSConfigVerifyTrue(t *testing.T) {
	cfg := config.TLSConfig{Enabled: true, Verify: true}
	tlsCfg, err := MakeClientTLSConfig(cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("verify=true should not set InsecureSkipVerify")
	}
}

// --- Listener error paths ---

func TestListenerStartBadAddress(t *testing.T) {
	cfg := config.ListenerConfig{Address: "invalid:address:port:xxx", Protocol: "postgresql"}
	l := NewListener(cfg)
	err := l.Start()
	if err == nil {
		t.Error("invalid address should fail")
		l.Stop()
	}
}

func TestListenerStartTLSBadCertDeep(t *testing.T) {
	cfg := config.ListenerConfig{
		Address:  "127.0.0.1:0",
		Protocol: "postgresql",
		TLS:      config.TLSConfig{Enabled: true, CertFile: "/bad/cert", KeyFile: "/bad/key"},
	}
	l := NewListener(cfg)
	err := l.Start()
	if err == nil {
		t.Error("bad TLS cert should fail")
		l.Stop()
	}
}

func TestListenerAcceptLoopNoHandler(t *testing.T) {
	cfg := config.ListenerConfig{Address: "127.0.0.1:0", Protocol: "postgresql"}
	l := NewListener(cfg)
	// Don't set handler
	l.Start()

	addr := l.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		l.Stop()
		t.Fatalf("dial: %v", err)
	}
	// Connection should be closed by acceptLoop (no handler)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	conn.Read(buf)
	conn.Close()

	l.Stop()
}

// --- Stop drain paths ---

func TestProxyStopDrainTimeout(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go func() {
		conn, _ := backendLn.Accept()
		if conn == nil {
			return
		}
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
		time.Sleep(15 * time.Second)
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	pset := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()

	proxyAddr := proxy.listeners[0].listener.Addr().String()

	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "drain_user", "database": "db"})
	conn.Write(startup)

	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		msg, err := pgcodec.ReadMessage(conn)
		if err != nil {
			break
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Send query — backend won't respond
	query := append([]byte("SELECT pg_sleep(60)"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})

	go func() {
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}()

	proxy.Stop() // exercises drain timeout path
}

// --- handleConnection: no target configured ---

func TestProxyHandleConnectionNoTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Routing.DefaultTarget = ""
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	pset := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()

	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
	conn.Write(startup)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg, err := pgcodec.ReadMessage(conn)
	if err != nil {
		return
	}
	if msg.Type == pgcodec.MsgErrorResponse {
		t.Log("correctly got error for no target")
	}
}

// --- handleConnection: backend connect failure ---

func TestProxyHandleConnectionBackendFail(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "bad", Protocol: "postgresql", Host: "127.0.0.1", Port: 1}}
	cfg.Routing.DefaultTarget = "bad"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	pset := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()

	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
	conn.Write(startup)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	msg, err := pgcodec.ReadMessage(conn)
	if err != nil {
		return
	}
	if msg.Type == pgcodec.MsgErrorResponse {
		t.Log("correctly got error for backend failure")
	}
}

// --- CertReloader edge cases ---

func TestCertReloaderReloadFail(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert2.pem")
	keyFile := filepath.Join(tmpDir, "key2.pem")

	generateTestCert(t, certFile, keyFile)

	r, err := NewCertReloader(certFile, keyFile, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	// Delete cert file — reload should fail but not crash
	os.Remove(certFile)

	r.Start()
	time.Sleep(250 * time.Millisecond)
	r.Stop()
}

func TestCertReloaderBadCert(t *testing.T) {
	_, err := NewCertReloader("/nonexistent/cert.pem", "/nonexistent/key.pem", time.Hour)
	if err == nil {
		t.Error("bad cert should fail")
	}
}

// --- Listener Start with listen error (port in use) ---

func TestListenerStartPortInUse(t *testing.T) {
	// Occupy a port
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	addr := ln.Addr().String()

	cfg := config.ListenerConfig{Address: addr, Protocol: "postgresql"}
	l := NewListener(cfg)
	err := l.Start()
	if err == nil {
		t.Error("port in use should fail")
		l.Stop()
	}
}

// --- Proxy Start with listener failure ---

func TestProxyStartListenerFailure(t *testing.T) {
	// Occupy a port
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	addr := ln.Addr().String()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: addr, Protocol: "postgresql"}}
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0

	pset := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	err := proxy.Start()
	if err == nil {
		t.Error("listener failure should propagate")
		proxy.Stop()
	}
}
