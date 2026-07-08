package pg

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestHandlerName(t *testing.T) {
	h := New()
	if h.Name() != "postgresql" {
		t.Errorf("name = %q", h.Name())
	}
}

func TestHandlerClose(t *testing.T) {
	h := New()
	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestRebuildQuery(t *testing.T) {
	h := New()
	rebuilt := h.RebuildQuery(nil, "SELECT 42")
	if len(rebuilt) == 0 {
		t.Fatal("should not be empty")
	}
	// Parse: type(1) + len(4) + payload
	if rebuilt[0] != MsgQuery {
		t.Errorf("type = %c, want Q", rebuilt[0])
	}
	// Payload should end with null
	if rebuilt[len(rebuilt)-1] != 0 {
		t.Error("should be null-terminated")
	}
}

func TestWriteRawBytes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		WriteRawBytes(clientConn, []byte("hello"))
	}()

	buf := make([]byte, 5)
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q", buf[:n])
	}
}

func TestReadStartupMessageParsed(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Build and send startup message
	go func() {
		msg := BuildStartupMessage(map[string]string{"user": "testuser", "database": "testdb"})
		clientConn.Write(msg)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	data, err := ReadStartupMessage(serverConn)
	if err != nil {
		t.Fatalf("ReadStartupMessage: %v", err)
	}

	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}
	if startup.Parameters["user"] != "testuser" {
		t.Errorf("user = %q", startup.Parameters["user"])
	}
}

func TestParseAuthType(t *testing.T) {
	// AuthOK = 0
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, 0)
	authType, err := parseAuthType(payload)
	if err != nil {
		t.Fatal(err)
	}
	if authType != AuthOK {
		t.Errorf("auth type = %d, want 0", authType)
	}

	// Too short
	_, err = parseAuthType([]byte{1, 2})
	if err == nil {
		t.Error("should fail on short payload")
	}
}

func TestIsExtendedQueryBackendMsg(t *testing.T) {
	if !IsExtendedQueryBackendMsg(MsgParseComplete) {
		t.Error("ParseComplete should be backend extended msg")
	}
	if !IsExtendedQueryBackendMsg(MsgBindComplete) {
		t.Error("BindComplete should be backend extended msg")
	}
	if IsExtendedQueryBackendMsg(MsgQuery) {
		t.Error("Query should not be backend extended msg")
	}
}

func TestBuildCommandComplete(t *testing.T) {
	msg := BuildCommandComplete("SELECT 5")
	if msg.Type != MsgCommandComplete {
		t.Error("wrong type")
	}
	// Payload should contain tag + null
	found := false
	for i, b := range msg.Payload {
		if b == 0 {
			if string(msg.Payload[:i]) == "SELECT 5" {
				found = true
			}
			break
		}
	}
	if !found {
		t.Error("should contain tag")
	}
}

func TestEncodeMessage(t *testing.T) {
	msg := &Message{Type: 'Q', Payload: []byte("SELECT 1\x00")}
	encoded := EncodeMessage(msg)

	if encoded[0] != 'Q' {
		t.Error("first byte should be type")
	}
	length := binary.BigEndian.Uint32(encoded[1:5])
	if int(length) != len(msg.Payload)+4 {
		t.Errorf("length = %d, want %d", length, len(msg.Payload)+4)
	}
}

func TestParseStartupMessageSSL(t *testing.T) {
	// Build SSL request
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 8)
	binary.BigEndian.PutUint32(data[4:8], SSLRequestCode)

	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if !startup.IsSSLRequest {
		t.Error("should be SSL request")
	}
}

func TestExtractSQL(t *testing.T) {
	sql := extractSQL([]byte("SELECT 1\x00extra"))
	if sql != "SELECT 1" {
		t.Errorf("sql = %q", sql)
	}

	// No null terminator
	sql = extractSQL([]byte("SELECT 2"))
	if sql != "SELECT 2" {
		t.Errorf("sql = %q", sql)
	}
}

func TestWriteMessageAndRead(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	msg := &Message{Type: MsgNoticeResponse, Payload: []byte("test notice")}

	go func() {
		WriteMessage(clientConn, msg)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	got, err := ReadMessage(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != MsgNoticeResponse {
		t.Errorf("type = %c", got.Type)
	}
	if string(got.Payload) != "test notice" {
		t.Errorf("payload = %q", got.Payload)
	}
}
