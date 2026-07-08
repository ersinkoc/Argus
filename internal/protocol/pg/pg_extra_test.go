package pg

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestReadCommandExtendedQuery(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	// Send Parse + Sync (minimal extended query batch)
	go func() {
		// Parse: empty name + "SELECT 1" + 0 params
		var parsePayload []byte
		parsePayload = append(parsePayload, 0)          // empty stmt name
		parsePayload = append(parsePayload, []byte("SELECT 1")...)
		parsePayload = append(parsePayload, 0)          // null term
		parsePayload = append(parsePayload, 0, 0)       // 0 params
		WriteMessage(clientConn, &Message{Type: MsgParse, Payload: parsePayload})

		// Sync
		WriteMessage(clientConn, &Message{Type: 'S', Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "SELECT 1" {
		t.Errorf("SQL = %q", cmd.Raw)
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg empty")
	}
}

func TestReadCommandUnknownMessage(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WriteMessage(clientConn, &Message{Type: 'Z', Payload: []byte("unknown")})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Type.String() != "UNKNOWN" {
		t.Errorf("type = %v", cmd.Type)
	}
}

func TestReadCommandBindWithoutParse(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	// Send Bind (without Parse) + Sync — uses cached statement
	go func() {
		// Bind with named statement
		var bindPayload []byte
		bindPayload = append(bindPayload, 0)                    // portal ""
		bindPayload = append(bindPayload, []byte("my_stmt")...) // stmt name
		bindPayload = append(bindPayload, 0)
		bindPayload = append(bindPayload, 0, 0) // format codes
		bindPayload = append(bindPayload, 0, 0) // params
		bindPayload = append(bindPayload, 0, 0) // result formats
		WriteMessage(clientConn, &Message{Type: 'B', Payload: bindPayload})

		// Sync
		WriteMessage(clientConn, &Message{Type: 'S', Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	// Should reference the named statement
	if cmd == nil {
		t.Error("cmd should not be nil")
	}
}

func TestHandlerDetectProtocolAllCases(t *testing.T) {
	h := New()

	// PG v3.0
	pg := []byte{0, 0, 0, 8, 0, 3, 0, 0}
	if !h.DetectProtocol(pg) {
		t.Error("should detect PG v3.0")
	}

	// SSL request
	ssl := []byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}
	if !h.DetectProtocol(ssl) {
		t.Error("should detect SSL request")
	}

	// Not PG
	other := []byte{0, 0, 0, 8, 0, 2, 0, 0}
	if h.DetectProtocol(other) {
		t.Error("should not detect v2.0")
	}

	// Too short
	if h.DetectProtocol([]byte{1, 2}) {
		t.Error("too short")
	}
}
