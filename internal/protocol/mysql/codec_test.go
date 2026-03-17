package mysql

import (
	"net"
	"testing"
)

func TestPacketRoundtrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	pkt := &Packet{
		SequenceID: 3,
		Payload:    []byte("SELECT 1"),
	}

	go func() {
		WritePacket(clientConn, pkt)
	}()

	got, err := ReadPacket(serverConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}

	if got.SequenceID != 3 {
		t.Errorf("seq = %d, want 3", got.SequenceID)
	}
	if string(got.Payload) != "SELECT 1" {
		t.Errorf("payload = %q, want %q", got.Payload, "SELECT 1")
	}
}

func TestBuildHandshakeV10(t *testing.T) {
	pkt := BuildHandshakeV10(42, "8.0.35-argus")

	if pkt.SequenceID != 0 {
		t.Errorf("seq = %d, want 0", pkt.SequenceID)
	}
	if len(pkt.Payload) == 0 {
		t.Fatal("payload should not be empty")
	}
	// First byte: protocol version 10
	if pkt.Payload[0] != 10 {
		t.Errorf("protocol version = %d, want 10", pkt.Payload[0])
	}
}

func TestParseHandshakeResponse41(t *testing.T) {
	// Build a minimal handshake response
	var payload []byte
	// Capability flags (4 bytes) — with CLIENT_CONNECT_WITH_DB (0x0008)
	payload = append(payload, 0x0F, 0x00, 0x00, 0x00) // caps with CONNECT_WITH_DB
	// Max packet size (4 bytes)
	payload = append(payload, 0x00, 0x00, 0x00, 0x01)
	// Character set
	payload = append(payload, 45)
	// Reserved (23 bytes)
	payload = append(payload, make([]byte, 23)...)
	// Username
	payload = append(payload, []byte("testuser")...)
	payload = append(payload, 0)
	// Auth response length + data
	payload = append(payload, 4) // length
	payload = append(payload, 0x01, 0x02, 0x03, 0x04)
	// Database
	payload = append(payload, []byte("testdb")...)
	payload = append(payload, 0)

	resp, err := ParseHandshakeResponse41(payload)
	if err != nil {
		t.Fatalf("ParseHandshakeResponse41: %v", err)
	}

	if resp.Username != "testuser" {
		t.Errorf("username = %q, want %q", resp.Username, "testuser")
	}
	if resp.Database != "testdb" {
		t.Errorf("database = %q, want %q", resp.Database, "testdb")
	}
	if len(resp.AuthResponse) != 4 {
		t.Errorf("auth response len = %d, want 4", len(resp.AuthResponse))
	}
}

func TestBuildOKPacket(t *testing.T) {
	pkt := BuildOKPacket(1, 0, 0)
	if pkt.Payload[0] != 0x00 {
		t.Errorf("first byte = 0x%02x, want 0x00 (OK)", pkt.Payload[0])
	}
}

func TestBuildErrPacket(t *testing.T) {
	pkt := BuildErrPacket(1, 1045, "Access denied")
	if pkt.Payload[0] != 0xFF {
		t.Errorf("first byte = 0x%02x, want 0xFF (ERR)", pkt.Payload[0])
	}
}

func TestBuildEOFPacket(t *testing.T) {
	pkt := BuildEOFPacket(5)
	if pkt.Payload[0] != 0xFE {
		t.Errorf("first byte = 0x%02x, want 0xFE (EOF)", pkt.Payload[0])
	}
	if pkt.SequenceID != 5 {
		t.Errorf("seq = %d, want 5", pkt.SequenceID)
	}
}

func TestExtractColumnName(t *testing.T) {
	// Build a simplified column definition:
	// 4 length-encoded strings (catalog, schema, table, org_table) then name
	var payload []byte
	// catalog = "def"
	payload = append(payload, 3)
	payload = append(payload, []byte("def")...)
	// schema = "mydb"
	payload = append(payload, 4)
	payload = append(payload, []byte("mydb")...)
	// table = "users"
	payload = append(payload, 5)
	payload = append(payload, []byte("users")...)
	// org_table = "users"
	payload = append(payload, 5)
	payload = append(payload, []byte("users")...)
	// name = "email"
	payload = append(payload, 5)
	payload = append(payload, []byte("email")...)

	name := extractColumnName(payload)
	if name != "email" {
		t.Errorf("column name = %q, want %q", name, "email")
	}
}

func TestParseMySQLTextRow(t *testing.T) {
	// Build a text row: "hello" + NULL + "world"
	var payload []byte
	payload = append(payload, 5) // length
	payload = append(payload, []byte("hello")...)
	payload = append(payload, 0xFB) // NULL
	payload = append(payload, 5)    // length
	payload = append(payload, []byte("world")...)

	fields := parseMySQLTextRow(payload, 3)

	if string(fields[0]) != "hello" {
		t.Errorf("field 0 = %q, want %q", fields[0], "hello")
	}
	if fields[1] != nil {
		t.Errorf("field 1 should be nil (NULL)")
	}
	if string(fields[2]) != "world" {
		t.Errorf("field 2 = %q, want %q", fields[2], "world")
	}
}
