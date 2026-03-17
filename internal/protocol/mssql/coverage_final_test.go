package mssql

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- Handshake error paths ---

func TestHandshakeReadPreLoginError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	clientConn.Close() // close immediately

	h := New()
	proxyClient.SetReadDeadline(time.Now().Add(time.Second))
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	proxyClient.Close()
	if err == nil {
		t.Error("read error should fail")
	}
}

func TestHandshakeForwardPreLoginError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()

	go func() {
		pkt := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("prelogin")}
		WritePacket(clientConn, pkt)
	}()

	proxyBackend.Close() // close backend

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	clientConn.Close()
	proxyClient.Close()
	if err == nil {
		t.Error("forward error should fail")
	}
}

func TestHandshakeWrongLoginType(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()

	go func() {
		// Client: send PreLogin then wrong packet type (not TDS7Login)
		WritePacket(clientConn, &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("pl")})
		// Read PreLogin response
		ReadPacket(clientConn)
		// Send non-Login7 packet
		WritePacket(clientConn, &Packet{Type: PacketSQLBatch, Status: StatusEOM, Data: []byte("bad")})
	}()

	go func() {
		// Backend: read PreLogin, send response
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildPreLoginResponse())
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("wrong login type should fail")
	}
}

// --- ReadAndForwardResult: read error ---

func TestReadAndForwardResultReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer proxyClient.Close()

	backendConn.Close() // close backend

	h := New()
	proxyBackend.SetDeadline(time.Now().Add(time.Second))
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	proxyBackend.Close()
	if err == nil {
		t.Error("read error should fail")
	}
}

// --- ReadAndForwardResult: write error ---

func TestReadAndForwardResultWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close() // close client

	go func() {
		pkt := &Packet{Type: PacketReply, Status: StatusEOM, Data: []byte{TokenDone, 0, 0, 0, 0, 0, 0, 0, 0}}
		WritePacket(backendConn, pkt)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("write error should fail")
	}
}

// --- decodeUTF16LE odd length ---

func TestDecodeUTF16LEOddLength(t *testing.T) {
	// Odd length should be truncated to even
	result := decodeUTF16LE([]byte{'H', 0, 'i', 0, 'x'})
	if result != "Hi" {
		t.Errorf("got %q, want 'Hi'", result)
	}
}
