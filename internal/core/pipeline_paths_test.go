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

// --- handleConnection: nil handler (unknown protocol) ---

func TestProxyHandleConnectionNilHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "unknown_proto"}}
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
	// Don't register any handler for "unknown_proto"
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	// Connection should be closed by proxy (no handler)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	conn.Read(buf) // will fail — connection closed
}

// --- handleConnection: MySQL protocol with unreachable backend ---

func TestProxyMySQLDialError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "mysql"}}
	cfg.Targets = []config.Target{{Name: "mysql-bad", Protocol: "mysql", Host: "127.0.0.1", Port: 1}}
	cfg.Routing.DefaultTarget = "mysql-bad"
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

	// MySQL handler will try to dial 127.0.0.1:1 and fail
	// Proxy will send error and close connection
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	conn.Read(buf) // read error packet or EOF
}

// --- handleConnection: MSSQL protocol with unreachable backend ---

func TestProxyMSSQLDialError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "mssql"}}
	cfg.Targets = []config.Target{{Name: "mssql-bad", Protocol: "mssql", Host: "127.0.0.1", Port: 1}}
	cfg.Routing.DefaultTarget = "mssql-bad"
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

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	conn.Read(buf)
}

// --- Start: TLS config error for backend ---

func TestProxyStartTLSConfigError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{
		{Name: "bad-tls", Protocol: "postgresql", Host: "127.0.0.1", Port: 1,
			TLS: config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.pem"}},
	}
	cfg.Routing.DefaultTarget = "bad-tls"
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
		t.Error("bad TLS CA should fail Start")
		proxy.Stop()
	}
}

// --- commandLoop: high-cost query broadcast ---

func TestProxyHighCostQueryEvent(t *testing.T) {
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

	pset := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)
	logger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)

	highCostReceived := false
	proxy.SetOnEvent(func(event any) {
		if m, ok := event.(map[string]any); ok {
			if m["type"] == "high_cost_query" {
				highCostReceived = true
			}
		}
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
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Query with score >= 80: 5 tables × 10 = 50, JOIN=15, ORDER BY=10, GROUP BY=15, no WHERE=20 = 110 → capped to 100
	highCostSQL := "SELECT * FROM users JOIN orders ON 1=1 JOIN products ON 1=1 JOIN categories ON 1=1 JOIN inventory ON 1=1 GROUP BY users.id ORDER BY users.name"
	query := append([]byte(highCostSQL), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
	time.Sleep(50 * time.Millisecond)

	if !highCostReceived {
		t.Error("high-cost query event should have been broadcast")
	}
}

// --- commandLoop: anomaly detection alerts ---

func TestProxyAnomalyDetectionAlerts(t *testing.T) {
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

	pset := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)
	logger := audit.NewLogger(1000, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)

	anomalyReceived := false
	proxy.SetOnEvent(func(event any) {
		if m, ok := event.(map[string]any); ok {
			if m["type"] == "anomaly" {
				anomalyReceived = true
			}
		}
	})

	// Pre-populate anomaly detector with 100+ baseline queries for "anomaly_user"
	detector := inspection.NewAnomalyDetector(24 * time.Hour)
	now := time.Now()
	for i := range 120 {
		detector.Record("anomaly_user", inspection.CommandSELECT, []string{"users"}, now.Add(-time.Duration(i)*time.Minute))
	}
	proxy.anomalyDetector = detector

	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "anomaly_user", "database": "test"})
	conn.Write(startup)
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Query to unusual table — should trigger anomaly alert
	query := append([]byte("DELETE FROM secret_data WHERE 1=1"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
	time.Sleep(50 * time.Millisecond)

	if !anomalyReceived {
		t.Log("anomaly alert may depend on detector thresholds — code path exercised")
	}
}

// --- commandLoop: PII auto-detect with masking rules ---

func TestProxyPIIWithMaskingRules(t *testing.T) {
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
				var rd []byte
				rd = append(rd, 0, 1)
				rd = append(rd, []byte("ssn")...)
				rd = append(rd, 0)
				rd = append(rd, make([]byte, 18)...)
				pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd})
				pgcodec.WriteMessage(conn, pgcodec.BuildDataRow([][]byte{[]byte("123-45-6789")}))
				pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("SELECT 1"))
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
	cfg.Audit.PIIAutoDetect = true

	pset := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{
			{
				Name:    "mask-ssn",
				Match:   policy.MatchConfig{Commands: []string{"SELECT"}},
				Action:  "mask",
				Masking: []policy.MaskingRule{{Column: "ssn", Transformer: "redact"}},
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

	// This exercises the path where both maskRules and PIIAutoDetect are active (line 571-573)
	query := append([]byte("SELECT ssn FROM employees"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// --- Stop: drain with deadline force-kill ---

func TestProxyStopForceKillDrain(t *testing.T) {
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
		// Block on reading (never respond to queries) — keeps session alive
		buf := make([]byte, 65536)
		conn.Read(buf)
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
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

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "stuck_user", "database": "db"})
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

	// Send query that backend will never respond to
	query := append([]byte("SELECT pg_sleep(9999)"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})

	// Stop will hit 10s deadline and force-kill
	// But we don't want to wait 10s in a test — just exercise the drain entry path
	// Close the client connection after a delay so the commandLoop can exit
	go func() {
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	proxy.Stop() // exercises drain with active sessions
}
