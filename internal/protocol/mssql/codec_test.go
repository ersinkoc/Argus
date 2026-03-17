package mssql

import (
	"net"
	"testing"
)

func TestTDSPacketRoundtrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	pkt := &Packet{
		Type:   PacketSQLBatch,
		Status: StatusEOM,
		Data:   []byte("SELECT 1"),
	}

	go func() {
		WritePacket(clientConn, pkt)
	}()

	got, err := ReadPacket(serverConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}

	if got.Type != PacketSQLBatch {
		t.Errorf("type = 0x%02x, want 0x%02x", got.Type, PacketSQLBatch)
	}
	if got.Status != StatusEOM {
		t.Errorf("status = 0x%02x, want 0x%02x", got.Status, StatusEOM)
	}
	if string(got.Data) != "SELECT 1" {
		t.Errorf("data = %q, want %q", got.Data, "SELECT 1")
	}
}

func TestBuildPreLoginResponse(t *testing.T) {
	pkt := BuildPreLoginResponse()
	if pkt.Type != PacketReply {
		t.Errorf("type = 0x%02x, want 0x%02x (Reply)", pkt.Type, PacketReply)
	}
	if pkt.Status != StatusEOM {
		t.Errorf("status should include EOM")
	}
	if len(pkt.Data) == 0 {
		t.Error("data should not be empty")
	}
}

func TestBuildErrorToken(t *testing.T) {
	token := BuildErrorToken(50000, 1, 16, "Access denied", "Argus", "", 0)
	if len(token) == 0 {
		t.Fatal("error token should not be empty")
	}
	if token[0] != TokenError {
		t.Errorf("first byte = 0x%02x, want 0x%02x (Error token)", token[0], TokenError)
	}
}

func TestDetectProtocol(t *testing.T) {
	handler := New()

	// Pre-login packet type = 0x12
	preLogin := []byte{PacketPreLogin, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00}
	if !handler.DetectProtocol(preLogin) {
		t.Error("should detect TDS pre-login")
	}

	// PostgreSQL startup
	pgStartup := []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00}
	if handler.DetectProtocol(pgStartup) {
		t.Error("should not detect PostgreSQL as MSSQL")
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	// "Hello" in UTF-16LE
	data := []byte{'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0}
	got := decodeUTF16LE(data)
	if got != "Hello" {
		t.Errorf("decodeUTF16LE = %q, want %q", got, "Hello")
	}
}

func TestToUTF16LE(t *testing.T) {
	data := toUTF16LE("Hi")
	if len(data) != 4 {
		t.Errorf("length = %d, want 4", len(data))
	}
	if data[0] != 'H' || data[1] != 0 || data[2] != 'i' || data[3] != 0 {
		t.Errorf("encoding wrong: %v", data)
	}
}

func TestContainsToken(t *testing.T) {
	data := []byte{0xE3, 0xAD, 0x00, 0xFD}
	if !containsToken(data, TokenLoginAck) {
		t.Error("should find LoginAck token")
	}
	if containsToken(data, TokenRow) {
		t.Error("should not find Row token")
	}
}

func TestHandlerName(t *testing.T) {
	h := New()
	if h.Name() != "mssql" {
		t.Errorf("name = %q, want %q", h.Name(), "mssql")
	}
}
