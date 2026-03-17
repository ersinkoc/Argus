package mssql

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMSSQLHandlerName(t *testing.T) {
	h := New()
	if h.Name() != "mssql" {
		t.Errorf("name = %q", h.Name())
	}
}

func TestMSSQLWriteError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		h.WriteError(context.Background(), proxyConn, "50000", "Access denied")
	}()

	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(clientConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if pkt.Type != PacketReply {
		t.Errorf("type = 0x%02x, want Reply", pkt.Type)
	}
	if pkt.Status&StatusEOM == 0 {
		t.Error("should have EOM status")
	}
}

func TestMSSQLForwardCommand(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	h := New()
	raw := encodePacketBytes(&Packet{Type: PacketSQLBatch, Status: StatusEOM, Data: []byte("SELECT 1")})

	go func() {
		h.ForwardCommand(context.Background(), raw, proxyConn)
	}()

	backendConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(backendConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if pkt.Type != PacketSQLBatch {
		t.Errorf("type = 0x%02x", pkt.Type)
	}
}

func TestMSSQLRebuildQuery(t *testing.T) {
	h := New()
	raw := h.RebuildQuery(nil, "SELECT 42")
	if len(raw) == 0 {
		t.Fatal("should produce non-empty output")
	}
	// Parse packet
	pkt, err := ReadPacketFromBytes(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pkt.Type != PacketSQLBatch {
		t.Errorf("type = 0x%02x, want SQLBatch", pkt.Type)
	}
}

func TestMSSQLClose(t *testing.T) {
	h := New()
	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestEncodePacketBytes(t *testing.T) {
	pkt := &Packet{Type: PacketSQLBatch, Status: StatusEOM, Data: []byte("test")}
	raw := encodePacketBytes(pkt)
	if len(raw) != headerSize+4 {
		t.Errorf("length = %d, want %d", len(raw), headerSize+4)
	}
	if raw[0] != PacketSQLBatch {
		t.Errorf("type = 0x%02x", raw[0])
	}
}

func TestCountTokens(t *testing.T) {
	data := []byte{TokenRow, 0x00, TokenRow, 0x00, TokenDone}
	if countTokens(data, TokenRow) != 2 {
		t.Error("should count 2 Row tokens")
	}
	if countTokens(data, TokenDone) != 1 {
		t.Error("should count 1 Done token")
	}
}

func TestExtractSQLBatch(t *testing.T) {
	// Build: ALL_HEADERS(4 bytes = 4) + UTF-16LE "Hi"
	data := []byte{4, 0, 0, 0, 'H', 0, 'i', 0}
	got := extractSQLBatch(data)
	if got != "Hi" {
		t.Errorf("extractSQLBatch = %q, want 'Hi'", got)
	}
}

// ReadPacketFromBytes is a test helper.
func ReadPacketFromBytes(data []byte) (*Packet, error) {
	if len(data) < headerSize {
		return nil, nil
	}
	pktType := data[0]
	status := data[1]
	totalLen := int(data[2])<<8 | int(data[3])
	pktData := data[headerSize:]
	if totalLen-headerSize < len(pktData) {
		pktData = pktData[:totalLen-headerSize]
	}
	return &Packet{Type: pktType, Status: status, Data: pktData}, nil
}
