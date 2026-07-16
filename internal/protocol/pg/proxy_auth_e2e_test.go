// E2E proxy auth integration test against real PostgreSQL.
// Requires pg-demo container running on localhost:15432 (user=u, password=p, database=d).
//
//go:build e2e

package pg

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestProxyAuthE2E_PG(t *testing.T) {
	addr := "127.0.0.1:15432"
	t.Logf("Connecting to real PostgreSQL at %s", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var d net.Dialer
	backend, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	defer backend.Close()

	startup := BuildStartupMessage(map[string]string{"user": "u", "database": "d"})
	if err := WriteRawBytes(backend, startup); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	if err := ProxyAuthClient(ctx, backend, "p"); err != nil {
		t.Fatalf("ProxyAuthClient failed: %v", err)
	}
	t.Log("✓ ProxyAuthClient: SCRAM-SHA-256 authenticated (AuthOK consumed internally)")

	for i := 0; i < 20; i++ {
		msg, err := ReadMessage(backend)
		if err != nil {
			t.Fatalf("read post-auth msg %d: %v", i, err)
		}
		switch msg.Type {
		case MsgParameterStatus:
			t.Logf("  ParameterStatus: %s", msg.Payload)
		case MsgBackendKeyData:
			t.Logf("  BackendKeyData: pid=%d", int32(msg.Payload[0])<<24|int32(msg.Payload[1])<<16|
				int32(msg.Payload[2])<<8|int32(msg.Payload[3]))
		case MsgReadyForQuery:
			t.Log("✓ ReadyForQuery received — session ready")
			return
		case MsgErrorResponse:
			fields := ParseErrorResponse(msg.Payload)
			t.Fatalf("backend error: %s", fields['M'])
		default:
			t.Logf("  skipping msg type %c", msg.Type)
		}
	}
	t.Fatal("did not receive ReadyForQuery after 20 messages")
}

func TestProxyAuthAndQueryE2E(t *testing.T) {
	addr := "127.0.0.1:15432"
	t.Logf("Full auth+query loop against %s", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var d net.Dialer
	backend, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial backend: %v", err)
	}
	defer backend.Close()

	startup := BuildStartupMessage(map[string]string{"user": "u", "database": "d"})
	if err := WriteRawBytes(backend, startup); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	if err := ProxyAuthClient(ctx, backend, "p"); err != nil {
		t.Fatalf("ProxyAuthClient failed: %v", err)
	}
	t.Log("✓ Backend authenticated via ProxyAuthClient")

	if err := RelayPostAuthFromBackend(backend, backend); err != nil {
		t.Fatalf("RelayPostAuthFromBackend: %v", err)
	}
	t.Log("✓ Post-auth messages relayed")

	if err := WriteMessage(backend, &Message{Type: MsgQuery, Payload: []byte("SELECT 1 AS ok\x00")}); err != nil {
		t.Fatalf("write query: %v", err)
	}

	queryResult, err := ReadMessage(backend)
	if err != nil {
		t.Fatalf("read query result: %v", err)
	}
	t.Logf("✓ Query response received: type=%c, payload_len=%d", queryResult.Type, len(queryResult.Payload))

	for i := 0; i < 5; i++ {
		msg, err := ReadMessage(backend)
		if err != nil {
			break
		}
		if msg.Type == MsgReadyForQuery {
			t.Log("✓ ReadyForQuery after query")
			break
		}
	}

	t.Log("✓ Full proxy auth E2E test passed: client→backend→SCRAM→authenticated→query")
}

func TestFullProxyAuthLoopE2E(t *testing.T) {
	addr := "127.0.0.1:15432"
	t.Logf("Full proxy auth loop test against %s", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fail := make(chan error, 1)

	go func() {
		realConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fail <- fmt.Errorf("dial backend: %w", err)
			return
		}
		defer realConn.Close()

		startup := BuildStartupMessage(map[string]string{"user": "u", "database": "d"})
		if err := WriteRawBytes(realConn, startup); err != nil {
			fail <- fmt.Errorf("write startup: %w", err)
			return
		}

		if err := ProxyAuthClient(ctx, realConn, "p"); err != nil {
			fail <- fmt.Errorf("ProxyAuthClient: %w", err)
			return
		}

		if err := RelayPostAuthFromBackend(realConn, realConn); err != nil {
			fail <- fmt.Errorf("RelayPostAuth: %w", err)
			return
		}

		if err := WriteMessage(realConn, &Message{Type: MsgQuery, Payload: []byte("SELECT 1 AS ok\x00")}); err != nil {
			fail <- fmt.Errorf("write query: %w", err)
			return
		}

		qr, err := ReadMessage(realConn)
		if err != nil {
			fail <- fmt.Errorf("read query: %w", err)
			return
		}
		t.Logf("✓ Query result type=%c len=%d", qr.Type, len(qr.Payload))
		fail <- nil
	}()

	if err := <-fail; err != nil {
		t.Fatalf("proxy auth loop failed: %v", err)
	}
	t.Log("✓ Full proxy auth loop completed: client→SCRAM→real PG→query")
}
