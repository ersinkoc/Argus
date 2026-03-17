package mongodb

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHandlerHandshake(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	// Client sends hello
	go func() {
		msg := &Message{
			Header:  MsgHeader{RequestID: 1, OpCode: OpMsg},
			Payload: []byte{0, 0, 0, 0, 0, 5, 0, 0, 0, 0}, // flags + kind0 + empty doc
		}
		WriteMessage(clientConn, msg)
		ReadMessage(clientConn) // read response
	}()

	// Backend reads and responds
	go func() {
		ReadMessage(backendConn) // hello
		resp := &Message{
			Header:  MsgHeader{RequestID: 1, ResponseTo: 1, OpCode: OpMsg},
			Payload: []byte{0, 0, 0, 0, 0, 5, 0, 0, 0, 0},
		}
		WriteMessage(backendConn, resp)
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if info.AuthMethod != "mongodb" {
		t.Errorf("auth = %q", info.AuthMethod)
	}
}

func TestHandlerReadAndForwardResult(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		WriteMessage(backendConn, &Message{
			Header:  MsgHeader{RequestID: 2, OpCode: OpMsg},
			Payload: []byte("result data"),
		})
	}()

	go func() { ReadMessage(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.ByteCount == 0 {
		t.Error("bytes should be > 0")
	}
}

func TestHandlerWriteError(t *testing.T) {
	h := New()
	// WriteError currently returns nil (no-op)
	err := h.WriteError(context.Background(), nil, "ERR", "test error")
	if err != nil {
		t.Errorf("err: %v", err)
	}
}

func TestReadCommandLegacyOpCode(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WriteMessage(clientConn, &Message{
			Header:  MsgHeader{RequestID: 1, OpCode: OpQuery},
			Payload: []byte("legacy query"),
		})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy OP_QUERY should be classified as UNKNOWN
	if cmd.Type.String() != "UNKNOWN" {
		t.Errorf("legacy type = %v", cmd.Type)
	}
}

func TestEncodeHeader(t *testing.T) {
	msg := &Message{
		Header: MsgHeader{
			RequestID:  42,
			ResponseTo: 10,
			OpCode:     OpMsg,
		},
		Payload: []byte("test"),
	}
	header := encodeHeader(msg)
	if len(header) != 16 {
		t.Errorf("header len = %d", len(header))
	}
}
