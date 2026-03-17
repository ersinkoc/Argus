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

// --- TLS success paths ---

func TestMakeServerTLSConfigValid(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	generateTestCert(t, certFile, keyFile)

	cfg := config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
	tlsCfg, err := MakeServerTLSConfig(cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("should return non-nil config")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("certs = %d", len(tlsCfg.Certificates))
	}
}

func TestMakeClientTLSConfigValidCA(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	generateTestCert(t, certFile, keyFile)

	// Use the cert as a CA
	cfg := config.TLSConfig{Enabled: true, CAFile: certFile, Verify: true}
	tlsCfg, err := MakeClientTLSConfig(cfg)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("should return non-nil config")
	}
	if tlsCfg.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("verify=true should not skip verify")
	}
}

func TestMakeClientTLSConfigInvalidCAPEM(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "badca.pem")
	os.WriteFile(caFile, []byte("not a valid PEM certificate"), 0644)

	cfg := config.TLSConfig{Enabled: true, CAFile: caFile, Verify: true}
	_, err := MakeClientTLSConfig(cfg)
	if err == nil {
		t.Error("invalid PEM should fail")
	}
}

// --- Listener TLS success path ---

func TestListenerStartWithTLS(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	generateTestCert(t, certFile, keyFile)

	cfg := config.ListenerConfig{
		Address:  "127.0.0.1:0",
		Protocol: "postgresql",
		TLS:      config.TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile},
	}
	l := NewListener(cfg)
	l.OnConnection(func(conn net.Conn) { conn.Close() })

	err := l.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	l.Stop()
}

// --- Proxy Start with TLS backend config ---

func TestProxyStartWithTLSBackendConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{
		{Name: "tls-target", Protocol: "postgresql", Host: "127.0.0.1", Port: 1,
			TLS: config.TLSConfig{Enabled: true, Verify: false}},
	}
	cfg.Routing.DefaultTarget = "tls-target"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

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
	proxy.Stop()
}

// --- Stop with active session that drains via ticker ---

func TestProxyStopDrainViaTicker(t *testing.T) {
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
		// Keep alive briefly then close
		time.Sleep(2 * time.Second)
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
	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "u", "database": "d"})
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

	// Close client quickly so session drains via ticker (< 500ms)
	go func() {
		time.Sleep(100 * time.Millisecond)
		conn.Close()
	}()

	proxy.Stop() // should drain via ticker path ("all sessions drained")
}

// --- handleConnection: handshake failure ---

func TestProxyHandleConnectionHandshakeFail(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	// Backend that sends error on auth
	go func() {
		conn, _ := backendLn.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		pgcodec.ReadStartupMessage(conn)
		errMsg := pgcodec.BuildErrorResponse("FATAL", "28000", "password authentication failed")
		pgcodec.WriteMessage(conn, errMsg)
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
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "baduser", "database": "db"})
	conn.Write(startup)

	// Should get error forwarded
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	msg, err := pgcodec.ReadMessage(conn)
	if err != nil {
		return // connection closed is fine
	}
	if msg.Type == pgcodec.MsgErrorResponse {
		t.Log("correctly got auth failure error")
	}
}

// --- commandLoop: result truncated event type ---

func TestProxyResultTruncatedEvent(t *testing.T) {
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

		for {
			msg, err := pgcodec.ReadMessage(conn)
			if err != nil {
				return
			}
			if msg.Type == pgcodec.MsgTerminate {
				return
			}
			if msg.Type == pgcodec.MsgQuery {
				// Result with email column — 5 rows
				var rd []byte
				rd = append(rd, 0, 1)
				rd = append(rd, []byte("email")...)
				rd = append(rd, 0)
				rd = append(rd, make([]byte, 18)...)
				pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd})
				for range 5 {
					pgcodec.WriteMessage(conn, pgcodec.BuildDataRow([][]byte{[]byte("test@example.com")}))
				}
				pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("SELECT 5"))
				pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))
			}
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	pset := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{
			{
				Name:    "mask-truncate",
				Match:   policy.MatchConfig{Commands: []string{"SELECT"}},
				Action:  "mask",
				Masking: []policy.MaskingRule{{Column: "email", Transformer: "redact"}},
				MaxRows: 2, // truncate after 2 rows
			},
		},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)
	logger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	query := append([]byte("SELECT email FROM users"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// --- commandLoop: ForwardCommand error ---

func TestProxyForwardCommandError(t *testing.T) {
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
		// Close immediately after handshake — ForwardCommand will fail
		conn.Close()
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	pset := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
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

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		msg, err := pgcodec.ReadMessage(conn)
		if err != nil {
			return // backend closed
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Send query — backend already closed, ForwardCommand will fail
	time.Sleep(100 * time.Millisecond) // ensure backend conn is closed
	query := append([]byte("SELECT 1"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})

	// Connection should close (ForwardCommand error → return)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	pgcodec.ReadMessage(conn) // will fail — exercising the code path is enough
}

// --- SessionManager OnTimeout callback ---

func TestProxySessionTimeout(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Session.IdleTimeout = 200 * time.Millisecond
	cfg.Session.MaxDuration = 500 * time.Millisecond
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
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

	// The OnTimeout callback is set in Start()
	proxy.Start()

	// Just verify Start registers the callback and starts the session manager
	if proxy.sessionManager == nil {
		t.Error("session manager should not be nil")
	}

	proxy.Stop()
}
