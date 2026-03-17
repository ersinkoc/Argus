package mysql

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

// --- Handshake edge cases ---

func TestHandshakeAuthFailed(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	go func() {
		// Backend: greeting then ERR
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn) // client response
		WritePacket(backendConn, BuildErrPacket(2, 1045, "Access denied"))
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		// Send minimal handshake
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("bad")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // ERR forwarded
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth failure should return error")
	}
}

func TestHandshakeAuthContinuation(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn) // client handshake response

		// Send auth switch request (0xFE)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0xFE, 'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', 0}})

		// Read client auth continuation
		ReadPacket(backendConn)

		// Send OK
		WritePacket(backendConn, BuildOKPacket(4, 0, 0))
	}()

	go func() {
		ReadPacket(clientConn)
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})

		// Read auth switch
		ReadPacket(clientConn)

		// Send auth data
		WritePacket(clientConn, &Packet{SequenceID: 3, Payload: []byte("auth_data")})

		// Read final OK
		ReadPacket(clientConn)
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

// --- ReadAndForwardResult with masking and row truncation ---

func TestReadAndForwardResultWithRowLimit(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		// Column count = 1
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})

		// Column def
		var colDef []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 4)
		colDef = append(colDef, []byte("name")...)
		colDef = append(colDef, 4)
		colDef = append(colDef, []byte("name")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})

		// EOF
		WritePacket(backendConn, BuildEOFPacket(3))

		// 5 rows
		for i := range 5 {
			row := []byte{5}
			row = append(row, []byte("Alice")...)
			WritePacket(backendConn, &Packet{SequenceID: byte(4 + i), Payload: row})
		}

		// EOF
		WritePacket(backendConn, BuildEOFPacket(9))
	}()

	// Client reads all forwarded packets
	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	// Pipeline with row limit of 2
	rules := []policy.MaskingRule{{Column: "name", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, nil, 2)

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if stats.RowCount == 0 {
		t.Error("should have processed rows")
	}
	// Truncation should occur since we have 5 rows but limit is 2
	t.Logf("rows=%d truncated=%v maskedCols=%v", stats.RowCount, stats.Truncated, stats.MaskedCols)
}

func TestReadAndForwardResultNullInRow(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})

		// Column def for "email"
		var colDef []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 5)
		colDef = append(colDef, []byte("email")...)
		colDef = append(colDef, 5)
		colDef = append(colDef, []byte("email")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})

		WritePacket(backendConn, BuildEOFPacket(3))

		// Row with NULL value (0xFB)
		WritePacket(backendConn, &Packet{SequenceID: 4, Payload: []byte{0xFB}})

		WritePacket(backendConn, BuildEOFPacket(5))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "email", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, nil, 0)

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d", stats.RowCount)
	}
}

func TestReadAndForwardResultERREndOfRows(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		// Column count
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		// Column def
		var colDef []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 1, 'x', 1, 'x', 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
		WritePacket(backendConn, BuildEOFPacket(3))

		// Row
		WritePacket(backendConn, &Packet{SequenceID: 4, Payload: []byte{1, 'a'}})

		// ERR instead of EOF to end rows (0xFF)
		WritePacket(backendConn, BuildErrPacket(5, 1234, "query interrupted"))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d, want 1", stats.RowCount)
	}
}

// --- ReadCommand edge cases ---

func TestReadCommandComInitDB(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		payload := append([]byte{ComInitDB}, []byte("newdb")...)
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "USE newdb" {
		t.Errorf("Raw = %q", cmd.Raw)
	}
}

func TestReadCommandComStmtClose(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()
	h.stmtStore.Add(&PreparedStatement{ID: 42, SQL: "SELECT 1"})

	go func() {
		payload := make([]byte, 5)
		payload[0] = ComStmtClose
		binary.LittleEndian.PutUint32(payload[1:5], 42)
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "[STMT_CLOSE]" {
		t.Errorf("Raw = %q", cmd.Raw)
	}

	// Statement should be removed
	if h.stmtStore.Get(42) != nil {
		t.Error("stmt 42 should be removed")
	}
}

func TestReadCommandComStmtPrepare(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		payload := append([]byte{ComStmtPrepare}, []byte("SELECT * FROM orders WHERE id = ?")...)
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Confidence != 0.8 {
		t.Errorf("confidence = %f, want 0.8", cmd.Confidence)
	}
	if h.lastCmdByte != ComStmtPrepare {
		t.Error("lastCmdByte should be ComStmtPrepare")
	}
}

func TestReadCommandUnknownCmd(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: []byte{0x99, 'x'}})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Type.String() != "UNKNOWN" {
		t.Errorf("type = %v", cmd.Type)
	}
}

// --- extractColumnName edge cases ---

func TestExtractColumnNameTruncated(t *testing.T) {
	// Too short to reach name field
	got := extractColumnName([]byte{3, 'd', 'e', 'f'})
	if got != "" {
		t.Errorf("truncated payload should return empty, got %q", got)
	}
}

func TestExtractColumnNameEmpty(t *testing.T) {
	got := extractColumnName(nil)
	if got != "" {
		t.Errorf("nil payload should return empty, got %q", got)
	}
	got = extractColumnName([]byte{})
	if got != "" {
		t.Errorf("empty payload should return empty, got %q", got)
	}
}

// --- parseMySQLTextRow edge cases ---

func TestParseMySQLTextRowAllNull(t *testing.T) {
	fields := parseMySQLTextRow([]byte{0xFB, 0xFB, 0xFB}, 3)
	if len(fields) != 3 {
		t.Fatalf("fields = %d", len(fields))
	}
	for i, f := range fields {
		if f != nil {
			t.Errorf("field %d should be nil", i)
		}
	}
}

func TestParseMySQLTextRowMixed(t *testing.T) {
	// "hi" + NULL + "ok"
	data := []byte{2, 'h', 'i', 0xFB, 2, 'o', 'k'}
	fields := parseMySQLTextRow(data, 3)
	if len(fields) != 3 {
		t.Fatalf("fields = %d", len(fields))
	}
	if string(fields[0]) != "hi" {
		t.Errorf("field 0 = %q", fields[0])
	}
	if fields[1] != nil {
		t.Error("field 1 should be nil")
	}
	if string(fields[2]) != "ok" {
		t.Errorf("field 2 = %q", fields[2])
	}
}

// --- buildMySQLTextRow ---

func TestBuildMySQLTextRowWithNull(t *testing.T) {
	fields := []masking.FieldValue{
		{Data: []byte("hello")},
		{IsNull: true},
		{Data: []byte("world")},
	}
	data := buildMySQLTextRow(fields)
	if len(data) == 0 {
		t.Fatal("empty output")
	}
	// Parse it back
	parsed := parseMySQLTextRow(data, 3)
	if string(parsed[0]) != "hello" {
		t.Errorf("field 0 = %q", parsed[0])
	}
	if parsed[1] != nil {
		t.Error("field 1 should be nil")
	}
	if string(parsed[2]) != "world" {
		t.Errorf("field 2 = %q", parsed[2])
	}
}

// --- handlePrepareResponse with short payload ---

func TestHandlePrepareResponseShortPayload(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		// OK with short payload (< 12 bytes)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{0x00, 1, 0, 0, 0}})
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_ = stats
}

// --- WriteError ---

func TestWriteErrorPacket(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		h.WriteError(context.Background(), proxyConn, "42000", "test error")
	}()

	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(clientConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if len(pkt.Payload) == 0 || pkt.Payload[0] != 0xFF {
		t.Error("should be ERR packet")
	}
}

// --- DetectProtocol ---

func TestDetectProtocolAlwaysFalse(t *testing.T) {
	h := New()
	if h.DetectProtocol([]byte{1, 2, 3}) {
		t.Error("MySQL detect should always return false")
	}
	if h.DetectProtocol(nil) {
		t.Error("nil should be false")
	}
}
