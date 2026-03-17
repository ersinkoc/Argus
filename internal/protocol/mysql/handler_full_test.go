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

func TestHandlerHandshakeFullFlow(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	// Backend: send greeting, read response, send OK
	go func() {
		greeting := BuildHandshakeV10(1, "5.7.0-argus")
		WritePacket(backendConn, greeting)
		ReadPacket(backendConn) // client handshake response
		ok := BuildOKPacket(2, 0, 0)
		WritePacket(backendConn, ok)
	}()

	// Client: read greeting, send handshake, read OK
	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00) // caps with CONNECT_WITH_DB
		payload = append(payload, 0x00, 0x00, 0x00, 0x01) // max pkt
		payload = append(payload, 45)                       // charset
		payload = append(payload, make([]byte, 23)...)      // reserved
		payload = append(payload, []byte("testuser")...)
		payload = append(payload, 0)
		payload = append(payload, 0) // empty auth
		payload = append(payload, []byte("testdb")...)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // OK
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if info.Username != "testuser" {
		t.Errorf("username = %q", info.Username)
	}
}

func TestHandlerReadAndForwardResultOK(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	// Backend: send OK packet (no result set)
	go func() {
		WritePacket(backendConn, BuildOKPacket(1, 1, 0))
	}()

	// Client: read forwarded OK
	go func() {
		ReadPacket(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 0 {
		t.Errorf("rows = %d, want 0 for OK", stats.RowCount)
	}
}

func TestHandlerReadAndForwardResultErr(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	// Backend: send ERR packet
	go func() {
		WritePacket(backendConn, BuildErrPacket(1, 1045, "Access denied"))
	}()

	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_ = stats
}

func TestHandlerReadAndForwardResultSet(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	// Backend: column count + column def + EOF + row + EOF
	go func() {
		// Column count = 1
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})

		// Column definition (simplified)
		var colDef []byte
		colDef = append(colDef, 3) // catalog "def"
		colDef = append(colDef, []byte("def")...)
		colDef = append(colDef, 4) // schema
		colDef = append(colDef, []byte("test")...)
		colDef = append(colDef, 5) // table
		colDef = append(colDef, []byte("users")...)
		colDef = append(colDef, 5) // org_table
		colDef = append(colDef, []byte("users")...)
		colDef = append(colDef, 4) // name "name"
		colDef = append(colDef, []byte("name")...)
		colDef = append(colDef, 4) // org_name
		colDef = append(colDef, []byte("name")...)
		colDef = append(colDef, 0x0c)        // filler
		colDef = append(colDef, make([]byte, 12)...) // charset + length + type + flags + decimals + filler
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})

		// EOF
		WritePacket(backendConn, BuildEOFPacket(3))

		// Row: "Alice"
		var row []byte
		row = append(row, 5) // length
		row = append(row, []byte("Alice")...)
		WritePacket(backendConn, &Packet{SequenceID: 4, Payload: row})

		// EOF (end of rows)
		WritePacket(backendConn, BuildEOFPacket(5))
	}()

	// Client reads all
	go func() {
		for range 5 {
			ReadPacket(clientConn)
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

func TestHandlerReadAndForwardResultWithMasking(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	rules := []policy.MaskingRule{{Column: "email", Transformer: "partial_email"}}

	// Backend: result set with email column
	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})

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

		var row []byte
		email := "john@example.com"
		row = append(row, byte(len(email)))
		row = append(row, []byte(email)...)
		WritePacket(backendConn, &Packet{SequenceID: 4, Payload: row})

		WritePacket(backendConn, BuildEOFPacket(5))
	}()

	var receivedEmail string
	go func() {
		for range 5 {
			pkt, err := ReadPacket(clientConn)
			if err != nil { return }
			// 4th packet is the row
			if pkt.SequenceID == 4 && len(pkt.Payload) > 1 {
				nameLen := int(pkt.Payload[0])
				if nameLen > 0 && 1+nameLen <= len(pkt.Payload) {
					receivedEmail = string(pkt.Payload[1 : 1+nameLen])
				}
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	pipeline := masking.NewPipeline(rules, nil, 0)
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if receivedEmail != "j***@example.com" {
		t.Errorf("email should be masked: got %q", receivedEmail)
	}
}

func TestHandlerRebuildQueryContent(t *testing.T) {
	h := New()
	rebuilt := h.RebuildQuery(nil, "SELECT 42 FROM t")

	if len(rebuilt) < headerSize+2 {
		t.Fatal("rebuilt too short")
	}

	// Parse: header(4) + payload
	length := int(rebuilt[0]) | int(rebuilt[1])<<8 | int(rebuilt[2])<<16
	payload := rebuilt[headerSize : headerSize+length]

	if payload[0] != ComQuery {
		t.Errorf("first byte = 0x%02x, want ComQuery", payload[0])
	}
	if string(payload[1:]) != "SELECT 42 FROM t" {
		t.Errorf("sql = %q", payload[1:])
	}
}

func TestHandlerReadCommandStmtExecuteWithSQL(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()
	// Pre-register a statement
	h.stmtStore.Add(&PreparedStatement{ID: 99, SQL: "SELECT * FROM orders", NumParams: 0})

	go func() {
		payload := make([]byte, 15)
		payload[0] = ComStmtExecute
		binary.LittleEndian.PutUint32(payload[1:5], 99)
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "SELECT * FROM orders" {
		t.Errorf("SQL = %q, want 'SELECT * FROM orders'", cmd.Raw)
	}
}

func TestHandlerReadCommandStmtReset(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		payload := make([]byte, 5)
		payload[0] = ComStmtReset
		binary.LittleEndian.PutUint32(payload[1:5], 1)
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "[STMT_RESET]" {
		t.Errorf("Raw = %q", cmd.Raw)
	}
}

func TestHandlerReadCommandEmptyPayload(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: []byte{}})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd != nil {
		t.Error("empty payload should return nil cmd")
	}
}

func TestHandlerCloseMethod(t *testing.T) {
	h := New()
	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
