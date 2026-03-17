package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/policy"
	pgcodec "github.com/ersinkoc/argus/internal/protocol/pg"
)

// TestProxyMultiStatement verifies multi-statement queries work through proxy.
// This was a critical bug: approval workflow blocked multi-statement queries forever.
func TestProxyMultiStatement(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()

	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	// Backend handles multi-statement: returns 2 result sets + 1 ReadyForQuery
	go func() {
		conn, err := backendLn.Accept()
		if err != nil { return }
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

		// Read multi-statement query
		msg, _ := pgcodec.ReadMessage(conn)
		if msg.Type == pgcodec.MsgQuery {
			// First result set: SELECT 1
			var rd1 []byte
			rd1 = append(rd1, 0, 1)
			rd1 = append(rd1, []byte("a")...)
			rd1 = append(rd1, 0)
			rd1 = append(rd1, make([]byte, 18)...)
			pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd1})
			pgcodec.WriteMessage(conn, pgcodec.BuildDataRow([][]byte{[]byte("1")}))
			pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("SELECT 1"))

			// Second result set: SELECT 2
			var rd2 []byte
			rd2 = append(rd2, 0, 1)
			rd2 = append(rd2, []byte("b")...)
			rd2 = append(rd2, 0)
			rd2 = append(rd2, make([]byte, 18)...)
			pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd2})
			pgcodec.WriteMessage(conn, pgcodec.BuildDataRow([][]byte{[]byte("2")}))
			pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("SELECT 1"))

			// Single ReadyForQuery at the end
			pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))
		}

		// Read terminate
		pgcodec.ReadMessage(conn)
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "test", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "test"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow-all", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)

	logger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()

	conn, _ := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)

	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery { break }
	}

	// Send multi-statement: "SELECT 1; SELECT 2"
	queryPayload := append([]byte("SELECT 1; SELECT 2"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: queryPayload})

	// Should get: RowDesc + DataRow + Complete + RowDesc + DataRow + Complete + ReadyForQuery
	results := 0
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgDataRow {
			results++
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	if results != 2 {
		t.Errorf("multi-statement should return 2 data rows, got %d", results)
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}
