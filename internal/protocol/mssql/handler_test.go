package mssql

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMSSQLReadCommandSQLBatch(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		// Build SQL Batch: ALL_HEADERS(4 bytes) + UTF-16LE SQL
		allHeaders := []byte{4, 0, 0, 0}
		sql := toUTF16LE("SELECT 1")
		data := append(allHeaders, sql...)
		pkt := &Packet{Type: PacketSQLBatch, Status: StatusEOM, Data: data}
		WritePacket(clientConn, pkt)
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "SELECT 1" {
		t.Errorf("SQL = %q, want 'SELECT 1'", cmd.Raw)
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg should not be empty")
	}
}

func TestMSSQLReadCommandAttention(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		pkt := &Packet{Type: PacketAttention, Status: StatusEOM, Data: nil}
		WritePacket(clientConn, pkt)
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "[ATTENTION/CANCEL]" {
		t.Errorf("Raw = %q", cmd.Raw)
	}
}

func TestMSSQLReadAndForwardResult(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	// Backend: send reply with Row token + Done token
	go func() {
		var data []byte
		data = append(data, TokenRow)      // row token
		data = append(data, 0x00, 0x00)    // some row data
		data = append(data, TokenDone)     // done token
		data = append(data, make([]byte, 8)...) // done status

		pkt := &Packet{Type: PacketReply, Status: StatusEOM, Data: data}
		WritePacket(backendConn, pkt)
	}()

	// Client reads
	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("ReadAndForwardResult: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d, want 1", stats.RowCount)
	}
}

func TestMSSQLReadAllPackets(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// Send packet with EOM
		pkt := &Packet{Type: PacketSQLBatch, Status: StatusEOM, Data: []byte("test")}
		WritePacket(clientConn, pkt)
	}()

	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, pktType, err := ReadAllPackets(serverConn)
	if err != nil {
		t.Fatalf("ReadAllPackets: %v", err)
	}
	if pktType != PacketSQLBatch {
		t.Errorf("type = 0x%02x", pktType)
	}
	if string(data) != "test" {
		t.Errorf("data = %q", data)
	}
}

func TestMSSQLReadCommandUnknownType(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		pkt := &Packet{Type: 0x99, Status: StatusEOM, Data: []byte{1, 2, 3}}
		WritePacket(clientConn, pkt)
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "[tds_type=0x99]" {
		t.Errorf("Raw = %q", cmd.Raw)
	}
}
