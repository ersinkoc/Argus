package pg

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- WriteError: write failure on ErrorResponse ---

func TestWriteErrorErrorResponseFail(t *testing.T) {
	h := New()
	clientConn, _ := net.Pipe()
	clientConn.Close() // close immediately

	err := h.WriteError(context.Background(), clientConn, "42000", "test")
	if err == nil {
		t.Error("write to closed conn should fail")
	}
}

// --- WriteError: write failure on ReadyForQuery ---

func TestWriteErrorReadyForQueryFail(t *testing.T) {
	h := New()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		// Read ErrorResponse then close
		serverConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(serverConn)
		serverConn.Close() // close before ReadyForQuery
	}()

	clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	err := h.WriteError(context.Background(), clientConn, "42000", "test")
	clientConn.Close()
	if err == nil {
		t.Error("write RFQ to closed conn should fail")
	}
}

// --- DoHandshakeWithOpts: forward startup write error ---

func TestDoHandshakeWithOptsForwardError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
	}()

	proxyBackend.Close() // backend closed

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	clientConn.Close()
	proxyClient.Close()
	if err == nil {
		t.Error("forward to closed backend should fail")
	}
}

// --- relayPostAuth: context cancellation ---

func TestRelayPostAuthContextCancel(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		// Read messages
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)
		// Send AuthOK
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})
		// Don't send ParameterStatus — let context cancel during relayPostAuth
		time.Sleep(3 * time.Second)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	proxyClient.SetDeadline(time.Now().Add(5 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := DoHandshakeWithOpts(ctx, proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("context cancel during post-auth should fail")
	}
}

// --- relayAuth: write error forwarding auth request ---

func TestRelayAuthWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		clientConn.Close() // close before auth message arrives
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)
		// Send cleartext password request
		authPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(authPayload, uint32(AuthCleartextPwd))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authPayload})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("write to closed client should fail")
	}
}

// --- ParseStartupMessage: various version formats ---

func TestParseStartupMessageV3Params(t *testing.T) {
	data := BuildStartupMessage(map[string]string{
		"user":     "test",
		"database": "mydb",
		"options":  "-c search_path=public",
	})
	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}
	if startup.Parameters["user"] != "test" {
		t.Errorf("user = %q", startup.Parameters["user"])
	}
	if startup.Parameters["options"] != "-c search_path=public" {
		t.Errorf("options = %q", startup.Parameters["options"])
	}
}

// --- DecodeParse: edge cases ---

func TestDecodeParseShortPayload(t *testing.T) {
	// Just null terminator for name — no query
	_, err := DecodeParse([]byte{0})
	if err == nil {
		t.Error("too short should fail")
	}
}

// --- DecodeBind: edge cases ---

func TestDecodeBindShortPayload(t *testing.T) {
	_, err := DecodeBind([]byte{0})
	if err == nil {
		t.Error("too short should fail")
	}
}
