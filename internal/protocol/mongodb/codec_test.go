package mongodb

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestReadWriteMessage(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	msg := &Message{
		Header: MsgHeader{
			RequestID:  42,
			ResponseTo: 0,
			OpCode:     OpMsg,
		},
		Payload: []byte("test payload"),
	}

	go func() {
		WriteMessage(clientConn, msg)
	}()

	got, err := ReadMessage(serverConn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if got.Header.RequestID != 42 {
		t.Errorf("reqID = %d", got.Header.RequestID)
	}
	if got.Header.OpCode != OpMsg {
		t.Errorf("opcode = %d", got.Header.OpCode)
	}
	if string(got.Payload) != "test payload" {
		t.Errorf("payload = %q", got.Payload)
	}
}

func TestOpCodeName(t *testing.T) {
	if OpCodeName(OpMsg) != "OP_MSG" {
		t.Error("OpMsg")
	}
	if OpCodeName(OpQuery) != "OP_QUERY" {
		t.Error("OpQuery")
	}
	if OpCodeName(9999) != "UNKNOWN(9999)" {
		t.Error("unknown")
	}
}

func TestExtractCommandName(t *testing.T) {
	// Build minimal BSON: { "find": "users" }
	// BSON: len(4) + type(1) + key\0 + value + \0
	var doc []byte
	doc = append(doc, 0, 0, 0, 0) // placeholder for length

	// Element: type=2 (string), key="find", value="users"
	doc = append(doc, 0x02)            // string type
	doc = append(doc, []byte("find")...)
	doc = append(doc, 0)               // null terminator for key
	valBytes := []byte("users")
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(valBytes)+1))
	doc = append(doc, lenBuf...)       // string length (including null)
	doc = append(doc, valBytes...)
	doc = append(doc, 0)               // null terminator for value
	doc = append(doc, 0)               // document terminator

	// Set document length
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))

	cmd := ExtractCommandName(doc)
	if cmd != "find" {
		t.Errorf("command = %q, want 'find'", cmd)
	}
}

func TestExtractCommandNameEmpty(t *testing.T) {
	if ExtractCommandName(nil) != "" {
		t.Error("nil should return empty")
	}
	if ExtractCommandName([]byte{5, 0, 0, 0, 0}) != "" {
		t.Error("empty doc should return empty")
	}
}

func TestParseOpMsgBody(t *testing.T) {
	// Build OP_MSG: flagBits(4) + section(kind=0, BSON doc)
	var payload []byte

	// FlagBits
	flags := make([]byte, 4)
	payload = append(payload, flags...)

	// Section kind=0 (body)
	payload = append(payload, 0)

	// Minimal BSON doc: { "ping": 1 }
	doc := []byte{13, 0, 0, 0, 0x10, 'p', 'i', 'n', 'g', 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
	payload = append(payload, doc...)

	flagBits, sections, err := ParseOpMsg(payload)
	if err != nil {
		t.Fatalf("ParseOpMsg: %v", err)
	}
	if flagBits != 0 {
		t.Errorf("flags = %d", flagBits)
	}
	if len(sections) != 1 {
		t.Fatalf("sections = %d", len(sections))
	}
	if sections[0].Kind != 0 {
		t.Errorf("kind = %d", sections[0].Kind)
	}
}

func TestParseOpMsgTooShort(t *testing.T) {
	_, _, err := ParseOpMsg([]byte{1, 2})
	if err == nil {
		t.Error("too short should fail")
	}
}
