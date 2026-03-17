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

// TestProxyCommandLoopMaskPath tests the masking path through commandLoop
func TestProxyCommandLoopMaskPath(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()

	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go fakePostgresBackendWithMask(t, backendLn)

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "test", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "test"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{"support": {Users: []string{"support_*"}}},
		Policies: []policy.PolicyRule{
			{
				Name:    "mask-support",
				Match:   policy.MatchConfig{Roles: []string{"support"}, Commands: []string{"SELECT"}},
				Masking: []policy.MaskingRule{{Column: "email", Transformer: "partial_email"}},
			},
			{Name: "allow-all", Match: policy.MatchConfig{}, Action: "allow"},
		},
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

	// Startup as support user
	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "support_jane", "database": "testdb"})
	conn.Write(startup)

	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// SELECT with email column — should be masked
	queryPayload := append([]byte("SELECT email FROM users"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: queryPayload})

	// Read results
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgDataRow {
			fields, _ := pgcodec.ParseDataRow(msg.Payload)
			if len(fields) > 0 {
				email := string(fields[0])
				if email == "alice@example.com" {
					t.Error("email should be masked, got original")
				}
			}
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

func fakePostgresBackendWithMask(t *testing.T, ln net.Listener) {
	t.Helper()
	conn, _ := ln.Accept()
	if conn == nil {
		return
	}
	defer conn.Close()

	pgcodec.ReadStartupMessage(conn)

	authOk := make([]byte, 4)
	binary.BigEndian.PutUint32(authOk, 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})

	ps := append([]byte("server_version"), 0)
	ps = append(ps, []byte("16.0")...)
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
			// Result with email column
			var rd []byte
			rd = append(rd, 0, 1)
			rd = append(rd, []byte("email")...)
			rd = append(rd, 0)
			rd = append(rd, make([]byte, 18)...)
			pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd})
			pgcodec.WriteMessage(conn, pgcodec.BuildDataRow([][]byte{[]byte("alice@example.com")}))
			pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("SELECT 1"))
			pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))
		}
	}
}
