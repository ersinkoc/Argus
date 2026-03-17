package mysql

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMySQLHandshakeAndQuery(t *testing.T) {
	// client ↔ proxy (clientConn/proxyClientSide)
	clientConn, proxyClientSide := net.Pipe()
	// proxy ↔ backend (proxyBackendSide/backendConn)
	proxyBackendSide, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClientSide.Close()
	defer proxyBackendSide.Close()
	defer backendConn.Close()

	handler := New()

	// Simulate backend: send greeting, read response, send OK
	go func() {
		// Send greeting
		greeting := BuildHandshakeV10(1, "8.0.35-argus")
		WritePacket(backendConn, greeting)

		// Read client handshake response (forwarded by proxy)
		ReadPacket(backendConn)

		// Send OK
		ok := BuildOKPacket(2, 0, 0)
		WritePacket(backendConn, ok)
	}()

	// Simulate client: read greeting, send handshake response
	go func() {
		// Read greeting (forwarded by proxy)
		ReadPacket(clientConn)

		// Send handshake response
		var payload []byte
		// Capability flags (4 bytes) with CONNECT_WITH_DB
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		// Max packet size
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		// Character set
		payload = append(payload, 45)
		// Reserved (23 bytes)
		payload = append(payload, make([]byte, 23)...)
		// Username
		payload = append(payload, []byte("testuser")...)
		payload = append(payload, 0)
		// Auth length + data
		payload = append(payload, 0)
		// Database
		payload = append(payload, []byte("testdb")...)
		payload = append(payload, 0)

		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})

		// Read OK (forwarded by proxy)
		ReadPacket(clientConn)
	}()

	// Perform handshake through proxy
	proxyClientSide.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackendSide.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := handler.Handshake(context.Background(), proxyClientSide, proxyBackendSide)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	if info.Username != "testuser" {
		t.Errorf("username = %q, want %q", info.Username, "testuser")
	}
	if info.Database != "testdb" {
		t.Errorf("database = %q, want %q", info.Database, "testdb")
	}
}

func TestMySQLReadCommand(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	handler := New()

	// Send COM_QUERY
	go func() {
		payload := append([]byte{ComQuery}, []byte("SELECT * FROM users")...)
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := handler.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}

	if cmd.Raw != "SELECT * FROM users" {
		t.Errorf("SQL = %q, want %q", cmd.Raw, "SELECT * FROM users")
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg should not be empty")
	}
	if len(cmd.Tables) == 0 || cmd.Tables[0] != "users" {
		t.Errorf("tables = %v, want [users]", cmd.Tables)
	}
}

func TestMySQLReadCommandQuit(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	handler := New()

	go func() {
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: []byte{ComQuit}})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := handler.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd != nil {
		t.Error("COM_QUIT should return nil command")
	}
}

func TestMySQLReadCommandPing(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	handler := New()

	go func() {
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: []byte{ComPing}})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := handler.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "[PING]" {
		t.Errorf("Raw = %q, want [PING]", cmd.Raw)
	}
}
