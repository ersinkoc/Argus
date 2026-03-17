package mssql

import (
	"net"
	"testing"
	"time"
)

func TestReadPacketTooLarge(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Send packet with huge length
	go func() {
		header := make([]byte, headerSize)
		header[0] = PacketSQLBatch
		header[1] = StatusEOM
		header[2] = 0xFF // length high byte = 65280+ > 32768
		header[3] = 0x00
		clientConn.Write(header)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	if err == nil {
		t.Error("should fail on too-large packet")
	}
}

func TestReadPacketShortLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		header := make([]byte, headerSize)
		header[0] = PacketSQLBatch
		header[1] = StatusEOM
		header[2] = 0 // length < headerSize
		header[3] = 2
		clientConn.Write(header)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	if err == nil {
		t.Error("should fail on short length")
	}
}

func TestDetectProtocolEmpty(t *testing.T) {
	h := New()
	if h.DetectProtocol(nil) {
		t.Error("nil should not detect")
	}
	if h.DetectProtocol([]byte{}) {
		t.Error("empty should not detect")
	}
	if !h.DetectProtocol([]byte{PacketPreLogin}) {
		t.Error("0x12 should detect")
	}
}

func TestParseColMetadataMultipleTypes(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 2, 0) // 2 columns

	// Column 1: INT (fixed, type 0x38)
	data = append(data, 0, 0, 0, 0, 0, 0) // user type + flags
	data = append(data, 0x38)               // INT
	data = append(data, 2)                   // name length
	data = append(data, 'i', 0, 'd', 0)     // "id"

	// Column 2: NVARCHAR (variable, type 0xE7)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0xE7)
	data = append(data, 0x00, 0x01) // max length
	data = append(data, 0, 0, 0, 0, 0) // collation
	data = append(data, 4)               // name length
	data = append(data, 'n', 0, 'a', 0, 'm', 0, 'e', 0) // "name"

	cols, consumed := ParseColMetadata(data)
	if consumed == 0 {
		t.Fatal("should consume bytes")
	}
	if len(cols) != 2 {
		t.Fatalf("cols = %d, want 2", len(cols))
	}
	if cols[0].Name != "id" {
		t.Errorf("col 0 = %q", cols[0].Name)
	}
	if cols[0].IsText {
		t.Error("INT should not be text")
	}
	if cols[1].Name != "name" {
		t.Errorf("col 1 = %q", cols[1].Name)
	}
	if !cols[1].IsText {
		t.Error("NVARCHAR should be text")
	}
}

func TestExtractLogin7UsernameOffset(t *testing.T) {
	// Test with offset pointing past data
	data := make([]byte, 94)
	data[48] = 0xFF // offset high
	data[49] = 0x00
	data[50] = 5 // length
	data[51] = 0

	username := extractLogin7Username(data)
	if username != "" {
		t.Errorf("out-of-bounds should return empty, got %q", username)
	}
}

func TestDecodeUTF16LEEmpty(t *testing.T) {
	result := decodeUTF16LE(nil)
	if result != "" {
		t.Error("nil should return empty")
	}
	result = decodeUTF16LE([]byte{})
	if result != "" {
		t.Error("empty should return empty")
	}
}

func TestExtractSQLBatchEmpty(t *testing.T) {
	result := extractSQLBatch(nil)
	if result != "" {
		t.Error("nil should return empty")
	}
	result = extractSQLBatch([]byte{1, 2})
	if result != "" {
		t.Error("short should return empty")
	}
}
