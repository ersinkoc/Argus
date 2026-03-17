package core

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/policy"
	pgcodec "github.com/ersinkoc/argus/internal/protocol/pg"
)

// TestProxyEndToEnd starts a real proxy listening on a random port,
// connects a fake backend, and verifies the full flow.
func TestProxyEndToEnd(t *testing.T) {
	// Start a fake PostgreSQL backend
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backendLn.Close()

	backendAddr := backendLn.Addr().String()
	backendHost, backendPort, _ := net.SplitHostPort(backendAddr)
	port := 0
	for _, c := range backendPort {
		port = port*10 + int(c-'0')
	}

	// Handle one backend connection
	go fakePostgresBackend(t, backendLn)

	// Configure proxy
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: "127.0.0.1:0", Protocol: "postgresql"},
	}
	cfg.Targets = []config.Target{
		{Name: "test", Protocol: "postgresql", Host: backendHost, Port: port},
	}
	cfg.Routing.DefaultTarget = "test"
	cfg.Pool.MinIdleConnections = 0 // don't warmup in tests (fake backend handles 1 conn)
	cfg.Audit.Outputs = nil // suppress stdout in tests

	// Set up policy
	ps := &policy.PolicySet{
		Version:  "1",
		Defaults: policy.DefaultsConfig{Action: "allow", LogLevel: "minimal"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{
			{
				Name:   "allow-all",
				Match:  policy.MatchConfig{},
				Action: "allow",
			},
		},
	}
	policyLoader := policy.NewLoader(nil, 0)
	policyLoader.SetCurrent(ps)
	policyEngine := policy.NewEngine(policyLoader)

	auditLogger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	auditLogger.Start()
	defer auditLogger.Close()

	proxy := NewProxy(cfg, policyEngine, auditLogger)

	// Override the listener address to use a random port
	if err := proxy.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer proxy.Stop()

	// Get actual proxy port
	proxyAddr := proxy.listeners[0].listener.Addr().String()

	// Connect as a client
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer conn.Close()

	// Send startup message
	params := map[string]string{
		"user":     "testuser",
		"database": "testdb",
	}
	startupMsg := pgcodec.BuildStartupMessage(params)
	conn.Write(startupMsg)

	// Read AuthOk
	msg := readPgMessage(t, conn)
	if msg.Type != pgcodec.MsgAuth {
		t.Fatalf("expected Auth message, got %c", msg.Type)
	}

	// Read until ReadyForQuery
	for {
		msg = readPgMessage(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Send a query
	queryPayload := append([]byte("SELECT 1 AS num"), 0)
	queryMsg := &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: queryPayload}
	pgcodec.WriteMessage(conn, queryMsg)

	// Read RowDescription
	msg = readPgMessage(t, conn)
	if msg.Type != pgcodec.MsgRowDescription {
		t.Fatalf("expected RowDescription, got %c", msg.Type)
	}

	// Read DataRow
	msg = readPgMessage(t, conn)
	if msg.Type != pgcodec.MsgDataRow {
		t.Fatalf("expected DataRow, got %c", msg.Type)
	}

	fields, err := pgcodec.ParseDataRow(msg.Payload)
	if err != nil {
		t.Fatalf("ParseDataRow: %v", err)
	}
	if string(fields[0]) != "1" {
		t.Errorf("expected value '1', got %q", fields[0])
	}

	// Read CommandComplete
	msg = readPgMessage(t, conn)
	if msg.Type != pgcodec.MsgCommandComplete {
		t.Fatalf("expected CommandComplete, got %c", msg.Type)
	}

	// Read ReadyForQuery
	msg = readPgMessage(t, conn)
	if msg.Type != pgcodec.MsgReadyForQuery {
		t.Fatalf("expected ReadyForQuery, got %c", msg.Type)
	}

	// Send Terminate
	termMsg := &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil}
	pgcodec.WriteMessage(conn, termMsg)
}

func fakePostgresBackend(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Read startup message
	_, err = pgcodec.ReadStartupMessage(conn)
	if err != nil {
		t.Logf("backend: read startup: %v", err)
		return
	}

	// Send AuthOk
	authOk := make([]byte, 4)
	binary.BigEndian.PutUint32(authOk, 0) // AuthOk
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})

	// Send ParameterStatus
	psPayload := append([]byte("server_version"), 0)
	psPayload = append(psPayload, []byte("16.0")...)
	psPayload = append(psPayload, 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: psPayload})

	// Send BackendKeyData
	bkd := make([]byte, 8)
	binary.BigEndian.PutUint32(bkd[0:4], 1234) // process ID
	binary.BigEndian.PutUint32(bkd[4:8], 5678) // secret key
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: bkd})

	// Send ReadyForQuery
	pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))

	// Wait for query
	msg, err := pgcodec.ReadMessage(conn)
	if err != nil {
		return
	}

	if msg.Type == pgcodec.MsgQuery {
		// Send RowDescription (1 column: num)
		rowDesc := buildRowDesc([]string{"num"})
		pgcodec.WriteMessage(conn, rowDesc)

		// Send DataRow
		dataRow := pgcodec.BuildDataRow([][]byte{[]byte("1")})
		pgcodec.WriteMessage(conn, dataRow)

		// Send CommandComplete
		pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("SELECT 1"))

		// Send ReadyForQuery
		pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))
	}

	// Wait for terminate
	pgcodec.ReadMessage(conn)
}

func buildRowDesc(columns []string) *pgcodec.Message {
	var payload []byte
	numCols := make([]byte, 2)
	binary.BigEndian.PutUint16(numCols, uint16(len(columns)))
	payload = append(payload, numCols...)

	for i, name := range columns {
		payload = append(payload, []byte(name)...)
		payload = append(payload, 0)
		meta := make([]byte, 18)
		binary.BigEndian.PutUint16(meta[4:6], uint16(i+1))
		binary.BigEndian.PutUint32(meta[6:10], 25)
		binary.BigEndian.PutUint16(meta[10:12], 0xFFFF)
		binary.BigEndian.PutUint32(meta[12:16], 0xFFFFFFFF)
		payload = append(payload, meta...)
	}

	return &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: payload}
}

func readPgMessage(t *testing.T, conn net.Conn) *pgcodec.Message {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	msg, err := pgcodec.ReadMessage(conn)
	if err != nil {
		t.Fatalf("readPgMessage: %v", err)
	}
	return msg
}

// Ensure context is used
var _ = context.Background
