package pg

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

func TestHandlerHandshakeSimple(t *testing.T) {
	// client ↔ proxy ↔ backend (via pipes)
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	// Client sends startup
	go func() {
		msg := BuildStartupMessage(map[string]string{"user": "testuser", "database": "testdb"})
		clientConn.Write(msg)

		// Read auth messages and respond
		for {
			m, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
			if m.Type == MsgReadyForQuery {
				return
			}
		}
	}()

	// Backend: read startup, send AuthOK + params + ReadyForQuery
	go func() {
		ReadStartupMessage(backendConn)

		// AuthOK
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		// ParameterStatus
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16.0")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})

		// BackendKeyData
		bkd := make([]byte, 8)
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: bkd})

		// ReadyForQuery
		WriteMessage(backendConn, BuildReadyForQuery('I'))
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
	if info.Database != "testdb" {
		t.Errorf("database = %q", info.Database)
	}
}

func TestHandlerReadCommandSimpleQuery(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		payload := append([]byte("SELECT * FROM users"), 0)
		WriteMessage(clientConn, &Message{Type: MsgQuery, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "SELECT * FROM users" {
		t.Errorf("sql = %q", cmd.Raw)
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg empty")
	}
}

func TestHandlerReadCommandTerminate(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WriteMessage(clientConn, &Message{Type: MsgTerminate, Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd != nil {
		t.Error("terminate should return nil command")
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg should contain terminate message")
	}
}

func TestHandlerForwardCommand(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	h := New()
	raw := EncodeMessage(&Message{Type: MsgQuery, Payload: append([]byte("SELECT 1"), 0)})

	go func() {
		h.ForwardCommand(context.Background(), raw, proxyConn)
	}()

	backendConn.SetReadDeadline(time.Now().Add(time.Second))
	msg, err := ReadMessage(backendConn)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MsgQuery {
		t.Errorf("type = %c", msg.Type)
	}
}

func TestHandlerReadAndForwardResult(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	// Backend sends RowDescription + DataRow + CommandComplete + ReadyForQuery
	go func() {
		// RowDescription (1 col: "val")
		var rdPayload []byte
		rdPayload = append(rdPayload, 0, 1) // 1 column
		rdPayload = append(rdPayload, []byte("val")...)
		rdPayload = append(rdPayload, 0)
		rdPayload = append(rdPayload, make([]byte, 18)...) // col metadata
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rdPayload})

		// DataRow
		WriteMessage(backendConn, BuildDataRow([][]byte{[]byte("hello")}))

		// CommandComplete
		WriteMessage(backendConn, BuildCommandComplete("SELECT 1"))

		// ReadyForQuery
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	// Read results on client side
	go func() {
		for {
			m, err := ReadMessage(clientConn)
			if err != nil || m.Type == MsgReadyForQuery {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	pipeline := masking.NewPipeline(nil, nil, 0)
	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("ReadAndForwardResult: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d, want 1", stats.RowCount)
	}
}

func TestHandlerWriteErrorFull(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		h.WriteError(context.Background(), proxyConn, "42501", "denied")
	}()

	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	// Error message
	msg, _ := ReadMessage(clientConn)
	if msg.Type != MsgErrorResponse {
		t.Errorf("type = %c", msg.Type)
	}
	fields := ParseErrorResponse(msg.Payload)
	if fields['M'] != "denied" {
		t.Errorf("message = %q", fields['M'])
	}

	// ReadyForQuery
	msg, _ = ReadMessage(clientConn)
	if msg.Type != MsgReadyForQuery {
		t.Errorf("expected ReadyForQuery, got %c", msg.Type)
	}
}

func TestForwardQuery(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	go func() {
		ForwardQuery(context.Background(), []byte("test data"), proxyConn)
	}()

	buf := make([]byte, 100)
	backendConn.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := backendConn.Read(buf)
	if string(buf[:n]) != "test data" {
		t.Errorf("got %q", buf[:n])
	}
}

// Ensure masking works through handler
func TestHandlerResultWithMasking(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	rules := []policy.MaskingRule{{Column: "email", Transformer: "partial_email"}}

	go func() {
		// RowDescription: id, email
		var rd []byte
		rd = append(rd, 0, 2)
		for _, name := range []string{"id", "email"} {
			rd = append(rd, []byte(name)...)
			rd = append(rd, 0)
			rd = append(rd, make([]byte, 18)...)
		}
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})
		WriteMessage(backendConn, BuildDataRow([][]byte{[]byte("1"), []byte("john@example.com")}))
		WriteMessage(backendConn, BuildCommandComplete("SELECT 1"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	var maskedEmail string
	go func() {
		for {
			m, err := ReadMessage(clientConn)
			if err != nil { return }
			if m.Type == MsgDataRow {
				fields, _ := ParseDataRow(m.Payload)
				if len(fields) > 1 {
					maskedEmail = string(fields[1])
				}
			}
			if m.Type == MsgReadyForQuery { return }
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	pipeline := masking.NewPipeline(rules, nil, 0)
	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	if maskedEmail != "j***@example.com" {
		t.Errorf("email should be masked: got %q", maskedEmail)
	}
	_ = stats
}
