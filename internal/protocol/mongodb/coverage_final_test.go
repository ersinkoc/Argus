package mongodb

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- Handshake error paths ---

func TestHandshakeReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	clientConn.Close()

	h := New()
	proxyClient.SetReadDeadline(time.Now().Add(time.Second))
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	proxyClient.Close()
	if err == nil {
		t.Error("read error should fail")
	}
}

func TestHandshakeForwardError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()

	go func() {
		msg := &Message{Header: MsgHeader{RequestID: 1, OpCode: OpMsg}, Payload: []byte("hello")}
		WriteMessage(clientConn, msg)
	}()

	proxyBackend.Close()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	clientConn.Close()
	proxyClient.Close()
	if err == nil {
		t.Error("forward error should fail")
	}
}

func TestHandshakeBackendReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		msg := &Message{Header: MsgHeader{RequestID: 1, OpCode: OpMsg}, Payload: []byte("hello")}
		WriteMessage(clientConn, msg)
	}()

	go func() {
		ReadMessage(backendConn)
		backendConn.Close() // close after reading, before sending response
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("backend read error should fail")
	}
}

func TestHandshakeForwardResponseError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		msg := &Message{Header: MsgHeader{RequestID: 1, OpCode: OpMsg}, Payload: []byte("hello")}
		WriteMessage(clientConn, msg)
		clientConn.Close() // close client before response forwarding
	}()

	go func() {
		ReadMessage(backendConn)
		resp := &Message{Header: MsgHeader{RequestID: 2, ResponseTo: 1, OpCode: OpMsg}, Payload: []byte("ok")}
		WriteMessage(backendConn, resp)
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward response error should fail")
	}
}

// --- ReadAndForwardResult error paths ---

func TestReadAndForwardResultBackendError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer proxyClient.Close()

	backendConn.Close()

	h := New()
	proxyBackend.SetDeadline(time.Now().Add(time.Second))
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	proxyBackend.Close()
	if err == nil {
		t.Error("read error should fail")
	}
}

func TestReadAndForwardResultWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	go func() {
		msg := &Message{Header: MsgHeader{RequestID: 1, OpCode: OpMsg}, Payload: []byte("result")}
		WriteMessage(backendConn, msg)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("write error should fail")
	}
}
