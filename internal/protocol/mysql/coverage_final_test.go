package mysql

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- HandleClose edge cases ---

func TestHandleCloseShortPayload(t *testing.T) {
	store := NewStmtStore()
	store.Add(&PreparedStatement{ID: 1, SQL: "SELECT 1"})

	// Short payload — should not panic
	HandleClose(&Packet{Payload: []byte{ComStmtClose, 1, 0}}, store)

	// Statement should still exist (payload too short)
	if store.Get(1) == nil {
		t.Error("short payload should not remove stmt")
	}
}

func TestHandleCloseNonexistent(t *testing.T) {
	store := NewStmtStore()
	payload := make([]byte, 5)
	payload[0] = ComStmtClose
	binary.LittleEndian.PutUint32(payload[1:5], 999)
	// Should not panic
	HandleClose(&Packet{Payload: payload}, store)
}

// --- HandleExecute edge cases ---

func TestHandleExecuteShortPayload(t *testing.T) {
	store := NewStmtStore()
	id, sql := HandleExecute(&Packet{Payload: []byte{ComStmtExecute, 1}}, store)
	if id != 0 || sql != "" {
		t.Error("short payload should return empty")
	}
}

func TestHandleExecuteUnknownStmt(t *testing.T) {
	store := NewStmtStore()
	payload := make([]byte, 5)
	payload[0] = ComStmtExecute
	binary.LittleEndian.PutUint32(payload[1:5], 999)
	id, sql := HandleExecute(&Packet{Payload: payload}, store)
	if id != 999 {
		t.Errorf("id = %d", id)
	}
	if sql != "" {
		t.Errorf("sql = %q", sql)
	}
}

// --- ReadPacket edge cases ---

func TestReadPacketHeaderError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		clientConn.Write([]byte{1, 2}) // only 2 bytes, need 4
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("short header should fail")
	}
}

func TestReadPacketTooLarge(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		header := make([]byte, 4)
		header[0] = 0xFF
		header[1] = 0xFF
		header[2] = 0xFF // > 16MB
		header[3] = 0
		clientConn.Write(header)
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("oversized packet should fail")
	}
}

func TestReadPacketPayloadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		header := make([]byte, 4)
		header[0] = 100 // length 100
		header[3] = 0
		clientConn.Write(header)
		clientConn.Write([]byte("short")) // only 5 bytes
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("truncated payload should fail")
	}
}

func TestReadPacketZeroLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		header := make([]byte, 4)
		header[0] = 0 // length 0
		header[3] = 1 // seq 1
		clientConn.Write(header)
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(serverConn)
	clientConn.Close()
	serverConn.Close()
	if err != nil {
		t.Fatalf("zero-length: %v", err)
	}
	if len(pkt.Payload) != 0 {
		t.Error("should have empty payload")
	}
}

// --- extractColumnName edge cases ---

func TestExtractColumnNameValidMultiSkip(t *testing.T) {
	// Build a proper column def: catalog(3)+schema(4)+table(5)+org_table(5)+name(4)+org_name(4)
	var payload []byte
	for _, s := range []string{"def", "mydb", "users", "users"} {
		payload = append(payload, byte(len(s)))
		payload = append(payload, []byte(s)...)
	}
	payload = append(payload, 2) // name len
	payload = append(payload, []byte("id")...)
	payload = append(payload, 2) // org_name len
	payload = append(payload, []byte("id")...)

	name := extractColumnName(payload)
	if name != "id" {
		t.Errorf("name = %q, want 'id'", name)
	}
}

func TestExtractColumnNameLongName(t *testing.T) {
	var payload []byte
	for _, s := range []string{"def", "db", "t", "t"} {
		payload = append(payload, byte(len(s)))
		payload = append(payload, []byte(s)...)
	}
	longName := "very_long_column_name_that_exceeds_normal"
	payload = append(payload, byte(len(longName)))
	payload = append(payload, []byte(longName)...)

	name := extractColumnName(payload)
	if name != longName {
		t.Errorf("name = %q", name)
	}
}

// --- MySQL Handshake fast auth (0x01 + 0x04) already tested ---
// --- Focus on the 0x00 OK path directly from first auth result ---

func TestHandshakeDirectOK(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn) // client response
		// Send direct OK (0x00 first byte — no auth switch needed)
		WritePacket(backendConn, BuildOKPacket(2, 0, 0))
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // OK
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if info.Username != "user" {
		t.Errorf("username = %q", info.Username)
	}
}
