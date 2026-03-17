package mssql

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

func TestReadAndForwardResultWithColMetadata(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	// Backend: send COLMETADATA + ROW + DONE in one packet
	go func() {
		var data []byte

		// COLMETADATA token with 1 NVARCHAR column "email"
		data = append(data, TokenColMetadata)
		data = append(data, 1, 0) // count=1
		// user type(4) + flags(2) = 6 bytes
		data = append(data, 0, 0, 0, 0, 0, 0)
		// Type: NVARCHAR = 0xE7
		data = append(data, 0xE7)
		// Max length
		data = append(data, 0x00, 0x01)
		// Collation (5 bytes)
		data = append(data, 0, 0, 0, 0, 0)
		// Column name: "email" (length=5, UTF-16LE)
		data = append(data, 5)
		data = append(data, 'e', 0, 'm', 0, 'a', 0, 'i', 0, 'l', 0)

		// ROW token
		data = append(data, TokenRow)
		// Some row data
		data = append(data, 0x10, 0x00) // 16 bytes text
		data = append(data, []byte("john@example.c")...) // truncated for simplicity

		// DONE token
		data = append(data, TokenDone)
		data = append(data, make([]byte, 8)...)

		pkt := &Packet{Type: PacketReply, Status: StatusEOM, Data: data}
		WritePacket(backendConn, pkt)
	}()

	// Client reads
	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "email", Transformer: "partial_email"}}
	pipeline := masking.NewPipeline(rules, nil, 0)

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if stats.RowCount != 1 {
		t.Errorf("rows = %d, want 1", stats.RowCount)
	}
}

func TestReadAndForwardResultNoPipeline(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		var data []byte
		data = append(data, TokenDone)
		data = append(data, make([]byte, 8)...)
		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusEOM, Data: data})
	}()

	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 0 {
		t.Errorf("rows = %d, want 0 (no row tokens)", stats.RowCount)
	}
}

func TestMSSQLRebuildQueryContent(t *testing.T) {
	h := New()
	raw := h.RebuildQuery(nil, "SELECT 42")

	pkt, _ := ReadPacketFromBytes(raw)
	if pkt == nil {
		t.Fatal("should parse packet")
	}
	if pkt.Type != PacketSQLBatch {
		t.Errorf("type = 0x%02x", pkt.Type)
	}

	// Data should start with ALL_HEADERS (4 bytes) + UTF-16LE
	if len(pkt.Data) < 4 {
		t.Fatal("data too short")
	}
	allHeadersLen := binary.LittleEndian.Uint32(pkt.Data[:4])
	if allHeadersLen != 4 {
		t.Errorf("all_headers len = %d, want 4", allHeadersLen)
	}

	sql := decodeUTF16LESlice(pkt.Data[4:])
	if sql != "SELECT 42" {
		t.Errorf("sql = %q", sql)
	}
}
