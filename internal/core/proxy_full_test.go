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
	"github.com/ersinkoc/argus/internal/session"
	pgcodec "github.com/ersinkoc/argus/internal/protocol/pg"
)

// TestProxyBlockedCommand starts proxy, sends a DDL command that should be blocked by policy.
func TestProxyBlockedCommand(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()

	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go fakePostgresBackendMulti(t, backendLn)

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "test", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "test"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Version:  "1",
		Defaults: policy.DefaultsConfig{Action: "allow", LogLevel: "minimal"},
		Roles:    map[string]policy.Role{"dba": {Users: []string{"admin"}}},
		Policies: []policy.PolicyRule{
			{
				Name:      "block-ddl",
				Match:     policy.MatchConfig{Roles: []string{"!dba"}, Commands: []string{"DDL"}},
				Condition: &policy.ConditionConfig{SQLContains: []string{"DROP"}},
				Action:    "block",
				Reason:    "DDL blocked",
			},
			{Name: "allow-all", Match: policy.MatchConfig{}, Action: "allow"},
		},
	}
	policyLoader := policy.NewLoader(nil, 0)
	policyLoader.SetCurrent(ps)
	policyEngine := policy.NewEngine(policyLoader)

	auditLogger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	auditLogger.Start()
	defer auditLogger.Close()

	proxy := NewProxy(cfg, policyEngine, auditLogger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()

	conn, _ := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	defer conn.Close()

	// Startup
	startupMsg := pgcodec.BuildStartupMessage(map[string]string{"user": "testuser", "database": "testdb"})
	conn.Write(startupMsg)

	// Read until ReadyForQuery
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery { break }
	}

	// Send DDL command that should be BLOCKED
	queryPayload := append([]byte("DROP TABLE users"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: queryPayload})

	// Should get ErrorResponse (blocked by policy)
	msg := readPgMsg(t, conn)
	if msg.Type != pgcodec.MsgErrorResponse {
		t.Errorf("blocked DDL should return ErrorResponse, got %c", msg.Type)
	} else {
		fields := pgcodec.ParseErrorResponse(msg.Payload)
		if fields['C'] != "42501" {
			t.Errorf("error code = %q, want 42501", fields['C'])
		}
	}

	// ReadyForQuery after error
	msg = readPgMsg(t, conn)
	if msg.Type != pgcodec.MsgReadyForQuery {
		t.Errorf("expected ReadyForQuery after block, got %c", msg.Type)
	}

	// Send allowed SELECT
	selectPayload := append([]byte("SELECT 1 AS num"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: selectPayload})

	// Should get RowDescription
	msg = readPgMsg(t, conn)
	if msg.Type != pgcodec.MsgRowDescription {
		t.Errorf("SELECT should get RowDescription, got %c", msg.Type)
	}

	// DataRow
	msg = readPgMsg(t, conn)
	if msg.Type != pgcodec.MsgDataRow {
		t.Errorf("expected DataRow, got %c", msg.Type)
	}

	// CommandComplete + ReadyForQuery
	readPgMsg(t, conn) // CommandComplete
	readPgMsg(t, conn) // ReadyForQuery

	// Terminate
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// TestProxySessionLimit tests concurrent session limiter
func TestProxySessionLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)

	proxy := NewProxy(cfg, policy.NewEngine(loader), audit.NewLogger(10, audit.LevelMinimal, 4096))
	proxy.SetSessionLimiter(session.NewConcurrencyLimiter(2))

	if proxy.sessionLimiter == nil {
		t.Error("limiter should be set")
	}
}

// TestProxyRewriter tests rewriter setter
func TestProxyRewriter(t *testing.T) {
	cfg := config.DefaultConfig()
	proxy := NewProxy(cfg, nil, nil)

	rw := inspection.NewRewriter()
	rw.SetMaxLimit(1000)
	proxy.SetRewriter(rw)

	if proxy.rewriter == nil {
		t.Error("rewriter should be set")
	}
}

func fakePostgresBackendMulti(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil { return }
	defer conn.Close()

	pgcodec.ReadStartupMessage(conn)

	authOk := make([]byte, 4)
	binary.BigEndian.PutUint32(authOk, 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})

	psPayload := append([]byte("server_version"), 0)
	psPayload = append(psPayload, []byte("16.0")...)
	psPayload = append(psPayload, 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: psPayload})
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
	pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))

	// Handle multiple commands
	for {
		msg, err := pgcodec.ReadMessage(conn)
		if err != nil { return }

		if msg.Type == pgcodec.MsgTerminate { return }

		if msg.Type == pgcodec.MsgQuery {
			// Send result: RowDescription + DataRow + CommandComplete + ReadyForQuery
			var rdPayload []byte
			rdPayload = append(rdPayload, 0, 1)
			rdPayload = append(rdPayload, []byte("num")...)
			rdPayload = append(rdPayload, 0)
			rdPayload = append(rdPayload, make([]byte, 18)...)
			pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rdPayload})
			pgcodec.WriteMessage(conn, pgcodec.BuildDataRow([][]byte{[]byte("1")}))
			pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("SELECT 1"))
			pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))
		}
	}
}

func readPgMsg(t *testing.T, conn net.Conn) *pgcodec.Message {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	msg, err := pgcodec.ReadMessage(conn)
	if err != nil { t.Fatalf("readPgMsg: %v", err) }
	return msg
}

func parsePort(s string) int {
	n := 0
	for _, c := range s { n = n*10 + int(c-'0') }
	return n
}
