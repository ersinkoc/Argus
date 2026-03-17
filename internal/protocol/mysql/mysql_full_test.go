package mysql

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMySQLHandlerName(t *testing.T) {
	h := New()
	if h.Name() != "mysql" {
		t.Errorf("name = %q, want mysql", h.Name())
	}
}

func TestMySQLDetectProtocol(t *testing.T) {
	h := New()
	// MySQL is server-speaks-first, so detection always returns false
	if h.DetectProtocol([]byte{0x01, 0x02, 0x03, 0x04}) {
		t.Error("MySQL should not detect from client bytes")
	}
}

func TestMySQLWriteError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		h.WriteError(context.Background(), proxyConn, "1045", "Access denied")
	}()

	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(clientConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if pkt.Payload[0] != 0xFF {
		t.Errorf("expected ERR packet, got 0x%02x", pkt.Payload[0])
	}
}

func TestMySQLForwardCommand(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	h := New()

	rawMsg := EncodePacket(&Packet{SequenceID: 0, Payload: []byte{ComQuery, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}})

	go func() {
		h.ForwardCommand(context.Background(), rawMsg, proxyConn)
	}()

	backendConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(backendConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if pkt.Payload[0] != ComQuery {
		t.Errorf("expected COM_QUERY, got 0x%02x", pkt.Payload[0])
	}
}

func TestMySQLRebuildQuery(t *testing.T) {
	h := New()
	raw := h.RebuildQuery(nil, "SELECT 42")

	pkt, err := ReadPacketFromBytes(raw)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if pkt.Payload[0] != ComQuery {
		t.Errorf("expected COM_QUERY")
	}
	if string(pkt.Payload[1:]) != "SELECT 42" {
		t.Errorf("sql = %q", string(pkt.Payload[1:]))
	}
}

func TestMySQLReadCommandInitDB(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: append([]byte{ComInitDB}, []byte("mydb")...)})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "USE mydb" {
		t.Errorf("raw = %q, want 'USE mydb'", cmd.Raw)
	}
}

func TestMySQLReadCommandStmtPrepare(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: append([]byte{ComStmtPrepare}, []byte("SELECT * FROM users WHERE id = ?")...)})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Confidence != 0.8 {
		t.Errorf("confidence = %v, want 0.8", cmd.Confidence)
	}
}

func TestMySQLReadCommandStmtClose(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()
	h.stmtStore.Add(&PreparedStatement{ID: 1, SQL: "SELECT 1"})

	go func() {
		payload := []byte{ComStmtClose, 1, 0, 0, 0}
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "[STMT_CLOSE]" {
		t.Errorf("raw = %q", cmd.Raw)
	}
	if h.stmtStore.Get(1) != nil {
		t.Error("statement should be removed")
	}
}

// ReadPacketFromBytes parses a packet from raw bytes (for testing RebuildQuery).
func ReadPacketFromBytes(data []byte) (*Packet, error) {
	if len(data) < headerSize {
		return nil, nil
	}
	length := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
	return &Packet{
		SequenceID: data[3],
		Payload:    data[headerSize : headerSize+length],
	}, nil
}
