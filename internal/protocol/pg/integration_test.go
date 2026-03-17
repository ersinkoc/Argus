package pg

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

// TestFullQueryCycle simulates a full Simple Query cycle through the proxy:
// client sends Query → backend responds with RowDescription + DataRow(s) + CommandComplete + ReadyForQuery
func TestFullQueryCycle(t *testing.T) {
	// Create connected pair: backendClient ↔ backendServer
	backendClient, backendServer := net.Pipe()
	defer backendClient.Close()
	defer backendServer.Close()

	// Create connected pair: proxyClient ↔ proxyServer (client side)
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	// Simulate backend: respond with RowDescription + DataRow + CommandComplete + ReadyForQuery
	go func() {
		// Read the forwarded query from "backend"
		msg, err := ReadMessage(backendClient)
		if err != nil {
			return
		}
		_ = msg // it's the Query message

		// Send RowDescription (2 columns: id, email)
		rowDesc := buildTestRowDescription([]string{"id", "email"})
		WriteMessage(backendClient, rowDesc)

		// Send DataRow
		dataRow := BuildDataRow([][]byte{[]byte("1"), []byte("john@example.com")})
		WriteMessage(backendClient, dataRow)

		// Send CommandComplete
		complete := BuildCommandComplete("SELECT 1")
		WriteMessage(backendClient, complete)

		// Send ReadyForQuery
		ready := BuildReadyForQuery('I')
		WriteMessage(backendClient, ready)
	}()

	// Build a Query message from "client" and forward it
	queryPayload := append([]byte("SELECT id, email FROM users"), 0)
	queryMsg := &Message{Type: MsgQuery, Payload: queryPayload}

	// Forward query to backend
	err := WriteMessage(backendServer, queryMsg)
	if err != nil {
		t.Fatalf("forward query: %v", err)
	}

	// Set up masking pipeline
	rules := []policy.MaskingRule{
		{Column: "email", Transformer: "partial_email"},
	}
	pipeline := masking.NewPipeline(rules, nil, 0) // columns will be set during ForwardResult

	// Read result from backend and write to proxy client
	go func() {
		ForwardResult(
			context.Background(),
			backendServer,
			proxyConn,
			pipeline,
		)
	}()

	// Read from client side and verify
	results := readAllMessages(t, clientConn, 4)

	// First message should be RowDescription
	if results[0].Type != MsgRowDescription {
		t.Errorf("message 0 type = %c, want %c (RowDescription)", results[0].Type, MsgRowDescription)
	}

	// Second should be DataRow (with masked email)
	if results[1].Type != MsgDataRow {
		t.Errorf("message 1 type = %c, want %c (DataRow)", results[1].Type, MsgDataRow)
	}
	fields, err := ParseDataRow(results[1].Payload)
	if err != nil {
		t.Fatalf("ParseDataRow: %v", err)
	}
	if string(fields[0]) != "1" {
		t.Errorf("id = %q, want %q", fields[0], "1")
	}
	if string(fields[1]) != "j***@example.com" {
		t.Errorf("email should be masked, got %q, want %q", fields[1], "j***@example.com")
	}

	// Third: CommandComplete
	if results[2].Type != MsgCommandComplete {
		t.Errorf("message 2 type = %c, want %c", results[2].Type, MsgCommandComplete)
	}

	// Fourth: ReadyForQuery
	if results[3].Type != MsgReadyForQuery {
		t.Errorf("message 3 type = %c, want %c", results[3].Type, MsgReadyForQuery)
	}
}

func TestWriteError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	handler := New()

	go func() {
		handler.WriteError(context.Background(), proxyConn, "42501", "Access denied")
	}()

	// Read error response
	msg, err := ReadMessage(clientConn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msg.Type != MsgErrorResponse {
		t.Errorf("type = %c, want %c", msg.Type, MsgErrorResponse)
	}
	fields := ParseErrorResponse(msg.Payload)
	if fields['M'] != "Access denied" {
		t.Errorf("message = %q, want %q", fields['M'], "Access denied")
	}

	// Read ReadyForQuery
	msg, err = ReadMessage(clientConn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msg.Type != MsgReadyForQuery {
		t.Errorf("type = %c, want %c", msg.Type, MsgReadyForQuery)
	}
}

func TestProtocolDetection(t *testing.T) {
	handler := New()

	// PostgreSQL v3.0 startup
	pg3 := make([]byte, 8)
	binary.BigEndian.PutUint32(pg3[0:4], 8)
	binary.BigEndian.PutUint32(pg3[4:8], 0x00030000)
	if !handler.DetectProtocol(pg3) {
		t.Error("should detect PostgreSQL v3.0")
	}

	// SSLRequest
	ssl := make([]byte, 8)
	binary.BigEndian.PutUint32(ssl[0:4], 8)
	ssl[4] = 0x04
	ssl[5] = 0xd2
	ssl[6] = 0x16
	ssl[7] = 0x2f
	if !handler.DetectProtocol(ssl) {
		t.Error("should detect SSLRequest")
	}

	// Random bytes
	random := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if handler.DetectProtocol(random) {
		t.Error("should not detect random bytes as PostgreSQL")
	}
}

// --- helpers ---

func buildTestRowDescription(columns []string) *Message {
	var payload []byte
	numCols := make([]byte, 2)
	binary.BigEndian.PutUint16(numCols, uint16(len(columns)))
	payload = append(payload, numCols...)

	for i, name := range columns {
		payload = append(payload, []byte(name)...)
		payload = append(payload, 0) // null terminator
		// table OID (4), column index (2), type OID (4), type size (2), type modifier (4), format (2) = 18 bytes
		meta := make([]byte, 18)
		binary.BigEndian.PutUint16(meta[4:6], uint16(i+1))           // column index
		binary.BigEndian.PutUint32(meta[6:10], 25)                    // text type OID
		binary.BigEndian.PutUint16(meta[10:12], 0xFFFF)               // type size -1
		binary.BigEndian.PutUint32(meta[12:16], 0xFFFFFFFF)           // type modifier -1
		payload = append(payload, meta...)
	}

	return &Message{Type: MsgRowDescription, Payload: payload}
}

func readAllMessages(t *testing.T, conn net.Conn, count int) []*Message {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msgs []*Message
	for i := 0; i < count; i++ {
		msg, err := ReadMessage(conn)
		if err != nil {
			if err == io.EOF && i > 0 {
				break
			}
			t.Fatalf("ReadMessage %d: %v", i, err)
		}
		msgs = append(msgs, msg)
	}
	return msgs
}
