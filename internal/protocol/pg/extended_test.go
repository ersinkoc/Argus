package pg

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestDecodeParse(t *testing.T) {
	var payload []byte
	payload = append(payload, []byte("stmt1")...)
	payload = append(payload, 0)
	payload = append(payload, []byte("SELECT $1::int, $2::text FROM users WHERE id = $1")...)
	payload = append(payload, 0)
	numParams := make([]byte, 2)
	binary.BigEndian.PutUint16(numParams, 2)
	payload = append(payload, numParams...)
	oid1 := make([]byte, 4)
	binary.BigEndian.PutUint32(oid1, 23)
	payload = append(payload, oid1...)
	oid2 := make([]byte, 4)
	binary.BigEndian.PutUint32(oid2, 25)
	payload = append(payload, oid2...)

	parsed, err := DecodeParse(payload)
	if err != nil {
		t.Fatalf("DecodeParse: %v", err)
	}

	if parsed.StatementName != "stmt1" {
		t.Errorf("stmt name = %q, want %q", parsed.StatementName, "stmt1")
	}
	if parsed.Query != "SELECT $1::int, $2::text FROM users WHERE id = $1" {
		t.Errorf("query = %q", parsed.Query)
	}
	if len(parsed.ParamOIDs) != 2 {
		t.Errorf("param count = %d, want 2", len(parsed.ParamOIDs))
	}
}

func TestDecodeParseUnnamed(t *testing.T) {
	var payload []byte
	payload = append(payload, 0) // empty name
	payload = append(payload, []byte("SELECT 1")...)
	payload = append(payload, 0)
	numParams := make([]byte, 2)
	binary.BigEndian.PutUint16(numParams, 0)
	payload = append(payload, numParams...)

	parsed, err := DecodeParse(payload)
	if err != nil {
		t.Fatalf("DecodeParse: %v", err)
	}

	if parsed.StatementName != "" {
		t.Errorf("stmt name = %q, want empty", parsed.StatementName)
	}
	if parsed.Query != "SELECT 1" {
		t.Errorf("query = %q, want %q", parsed.Query, "SELECT 1")
	}
}

func TestDecodeBind(t *testing.T) {
	var payload []byte
	payload = append(payload, []byte("portal1")...)
	payload = append(payload, 0)
	payload = append(payload, []byte("stmt1")...)
	payload = append(payload, 0)
	payload = append(payload, 0, 0) // num formats
	payload = append(payload, 0, 0) // num params
	payload = append(payload, 0, 0) // num result formats

	bind, err := DecodeBind(payload)
	if err != nil {
		t.Fatalf("DecodeBind: %v", err)
	}

	if bind.Portal != "portal1" {
		t.Errorf("portal = %q, want %q", bind.Portal, "portal1")
	}
	if bind.StatementName != "stmt1" {
		t.Errorf("stmt = %q, want %q", bind.StatementName, "stmt1")
	}
}

func TestReadExtendedQueryBatch(t *testing.T) {
	// client ↔ proxy: client writes, proxy reads from proxyEnd
	clientEnd, proxyEnd := net.Pipe()
	defer clientEnd.Close()
	defer proxyEnd.Close()

	// Client sends: Parse + Bind + Execute + Sync
	go func() {
		// Parse
		parsePayload := buildParsePayload("", "SELECT id FROM users WHERE id = $1", []int32{23})
		WriteMessage(clientEnd, &Message{Type: MsgParse, Payload: parsePayload})

		// Bind
		bindPayload := buildSimpleBind("", "", []byte("42"))
		WriteMessage(clientEnd, &Message{Type: 'B', Payload: bindPayload})

		// Execute
		execPayload := []byte{0, 0, 0, 0, 0}
		WriteMessage(clientEnd, &Message{Type: 'E', Payload: execPayload})

		// Sync
		WriteMessage(clientEnd, &Message{Type: 'S', Payload: nil})
	}()

	// Read from proxy end
	proxyEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawBatch, err := ReadQueryCommand(context.Background(), proxyEnd)
	if err != nil {
		t.Fatalf("ReadQueryCommand: %v", err)
	}

	if cmd.Raw != "SELECT id FROM users WHERE id = $1" {
		t.Errorf("SQL = %q, want %q", cmd.Raw, "SELECT id FROM users WHERE id = $1")
	}

	// rawBatch should contain all 4 messages
	if len(rawBatch) == 0 {
		t.Fatal("rawBatch should not be empty")
	}

	// Verify tables extracted
	if len(cmd.Tables) == 0 || cmd.Tables[0] != "users" {
		t.Errorf("tables = %v, want [users]", cmd.Tables)
	}

	// Confidence should be 0.8 for extended query
	if cmd.Confidence != 0.8 {
		t.Errorf("confidence = %v, want 0.8", cmd.Confidence)
	}
}

func TestIsExtendedQueryMsg(t *testing.T) {
	if !IsExtendedQueryMsg(MsgParse) {
		t.Error("Parse should be extended query")
	}
	if !IsExtendedQueryMsg('B') {
		t.Error("Bind should be extended query")
	}
	if !IsExtendedQueryMsg('S') {
		t.Error("Sync should be extended query")
	}
	if IsExtendedQueryMsg(MsgQuery) {
		t.Error("Query should NOT be extended query")
	}
	if IsExtendedQueryMsg(MsgTerminate) {
		t.Error("Terminate should NOT be extended query")
	}
}

// --- helpers ---

func buildParsePayload(stmtName, query string, paramOIDs []int32) []byte {
	var p []byte
	p = append(p, []byte(stmtName)...)
	p = append(p, 0)
	p = append(p, []byte(query)...)
	p = append(p, 0)
	num := make([]byte, 2)
	binary.BigEndian.PutUint16(num, uint16(len(paramOIDs)))
	p = append(p, num...)
	for _, oid := range paramOIDs {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(oid))
		p = append(p, b...)
	}
	return p
}

func buildSimpleBind(portal, stmt string, paramValues ...[]byte) []byte {
	var p []byte
	p = append(p, []byte(portal)...)
	p = append(p, 0)
	p = append(p, []byte(stmt)...)
	p = append(p, 0)
	// Format codes: 0 (all text)
	p = append(p, 0, 0)
	// Num params
	num := make([]byte, 2)
	binary.BigEndian.PutUint16(num, uint16(len(paramValues)))
	p = append(p, num...)
	for _, v := range paramValues {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(v)))
		p = append(p, lenBuf...)
		p = append(p, v...)
	}
	// Result format codes: 0 (all text)
	p = append(p, 0, 0)
	return p
}
