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

// --- ReadMessage error paths ---

func TestReadMessageLengthReadError(t *testing.T) {
	// Send type byte then close — length read fails
	clientConn, serverConn := net.Pipe()
	go func() {
		clientConn.Write([]byte{'Q'}) // type byte
		clientConn.Close()            // close before length
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on length read")
	}
}

func TestReadMessageNegativeLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		buf := make([]byte, 5)
		buf[0] = 'Q'
		binary.BigEndian.PutUint32(buf[1:5], 2) // length 2 → payload = 2-4 = negative
		clientConn.Write(buf)
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on negative length")
	}
}

func TestReadMessageHugeLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		buf := make([]byte, 5)
		buf[0] = 'Q'
		binary.BigEndian.PutUint32(buf[1:5], 0x02000000) // > 16MB
		clientConn.Write(buf)
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on huge length")
	}
}

func TestReadMessagePayloadReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		buf := make([]byte, 5)
		buf[0] = 'Q'
		binary.BigEndian.PutUint32(buf[1:5], 100) // length 100 → payload = 96
		clientConn.Write(buf)
		clientConn.Write([]byte("short")) // only 5 bytes, not 96
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on truncated payload")
	}
}

// --- ReadStartupMessage error paths ---

func TestReadStartupMessageLengthReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		clientConn.Write([]byte{0, 0}) // partial length
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadStartupMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on length read")
	}
}

func TestReadStartupMessageInvalidLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 2) // < 4
		clientConn.Write(buf)
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadStartupMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on invalid length")
	}
}

func TestReadStartupMessageTooLarge(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 20000) // > 10000
		clientConn.Write(buf)
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadStartupMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on too-large startup")
	}
}

func TestReadStartupMessagePayloadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 100) // length 100 → payload 96
		clientConn.Write(buf)
		clientConn.Write([]byte("short")) // only 5 bytes
		clientConn.Close()
	}()
	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadStartupMessage(serverConn)
	serverConn.Close()
	if err == nil {
		t.Error("should fail on truncated payload")
	}
}

// --- DoHandshakeWithOpts error paths ---

func TestDoHandshakeStartupReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	// Close client immediately → startup read fails
	clientConn.Close()

	proxyClient.SetReadDeadline(time.Now().Add(time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	proxyClient.Close()
	if err == nil {
		t.Error("should fail on startup read")
	}
}

func TestDoHandshakeForwardStartupError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test"})
		clientConn.Write(startup)
	}()

	// Close backend so write fails
	proxyBackend.Close()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	clientConn.Close()
	proxyClient.Close()
	if err == nil {
		t.Error("should fail on forwarding startup")
	}
}

// --- relayAuth error paths ---

func TestRelayAuthContextCancel(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		// Don't read — let context cancel
		time.Sleep(2 * time.Second)
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)
		// Don't respond — let context cancel
		time.Sleep(2 * time.Second)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(ctx, proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("should fail on context cancel")
	}
}

func TestRelayAuthUnexpectedMessageType(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		// Read whatever comes
		for {
			clientConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)
		// Send unexpected message type (not Auth, not Error)
		WriteMessage(backendConn, &Message{Type: MsgDataRow, Payload: []byte{0, 0}})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("unexpected message type during auth should fail")
	}
}

// --- ForwardResult write error paths ---

func TestForwardResultRowDescWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	// Close client side immediately → write will fail
	proxyClient.Close()

	go func() {
		var rd []byte
		rd = append(rd, 0, 1)
		rd = append(rd, []byte("col")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("should fail on write error")
	}
}

func TestForwardResultCommandCompleteWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		WriteMessage(backendConn, BuildCommandComplete("SELECT 0"))
	}()

	// Close client after starting read
	go func() {
		time.Sleep(50 * time.Millisecond)
		clientConn.Close()
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("should fail on CommandComplete write error")
	}
}

func TestForwardResultReadyForQueryWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer clientConn.Close()

	go func() {
		WriteMessage(backendConn, BuildCommandComplete("SELECT 0"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	// Read CommandComplete then close
	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(clientConn) // CommandComplete
		clientConn.Close()      // close before ReadyForQuery
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("should fail on ReadyForQuery write error")
	}
}

func TestForwardResultDataRowMaskingParseError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		var rd []byte
		rd = append(rd, 0, 1) // 1 column
		rd = append(rd, []byte("email")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})

		// Malformed DataRow (can't parse fields)
		WriteMessage(backendConn, &Message{Type: MsgDataRow, Payload: []byte{0xFF}})

		WriteMessage(backendConn, BuildCommandComplete("SELECT 1"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "email", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "email", Index: 0}}, 0)

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Should forward as-is when parse fails
	if stats.RowCount != 1 {
		t.Errorf("rows = %d", stats.RowCount)
	}
}

func TestForwardResultErrorResponseWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close() // close immediately

	go func() {
		errMsg := BuildErrorResponse("ERROR", "42601", "syntax error")
		WriteMessage(backendConn, errMsg)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("should fail on ErrorResponse write error")
	}
}

// --- HandleCopyIn error paths ---

func TestHandleCopyInReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	// Close client so read fails
	clientConn.Close()

	proxyClient.SetDeadline(time.Now().Add(time.Second))
	err := HandleCopyIn(context.Background(), proxyClient, proxyBackend)
	proxyClient.Close()
	if err == nil {
		t.Error("should fail on read error")
	}
}

func TestHandleCopyInWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()

	go func() {
		WriteMessage(clientConn, &Message{Type: MsgCopyData, Payload: []byte("data")})
	}()

	// Close backend so write fails
	proxyBackend.Close()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	err := HandleCopyIn(context.Background(), proxyClient, proxyBackend)
	clientConn.Close()
	proxyClient.Close()
	if err == nil {
		t.Error("should fail on write error")
	}
}

func TestHandleCopyInUnexpectedMsg(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		// Send unexpected message type during COPY IN
		WriteMessage(clientConn, &Message{Type: 'X', Payload: nil})
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(backendConn)
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	err := HandleCopyIn(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("unexpected msg during COPY IN should fail")
	}
}

// --- HandleCopyOut error paths ---

func TestHandleCopyOutReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer proxyClient.Close()

	// Close backend so read fails
	backendConn.Close()

	proxyBackend.SetDeadline(time.Now().Add(time.Second))
	err := HandleCopyOut(context.Background(), proxyBackend, proxyClient)
	proxyBackend.Close()
	if err == nil {
		t.Error("should fail on read error")
	}
}

func TestHandleCopyOutWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()

	go func() {
		WriteMessage(backendConn, &Message{Type: MsgCopyData, Payload: []byte("data")})
	}()

	proxyClient.Close() // close client so write fails

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	err := HandleCopyOut(context.Background(), proxyBackend, proxyClient)
	backendConn.Close()
	proxyBackend.Close()
	if err == nil {
		t.Error("should fail on write error")
	}
}

func TestHandleCopyOutUnexpectedMsg(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WriteMessage(backendConn, &Message{Type: 'X', Payload: nil})
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	err := HandleCopyOut(context.Background(), proxyBackend, proxyClient)
	if err == nil {
		t.Error("unexpected msg during COPY OUT should fail")
	}
}

// --- readExtendedBatch Bind with named statement ---

func TestReadExtendedBatchBindNamedStmt(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		// Bind with named statement (no prior Parse)
		var bindPayload []byte
		bindPayload = append(bindPayload, 0)                    // portal ""
		bindPayload = append(bindPayload, []byte("my_stmt")...) // stmt name
		bindPayload = append(bindPayload, 0)
		bindPayload = append(bindPayload, 0, 0) // format codes
		bindPayload = append(bindPayload, 0, 0) // params
		bindPayload = append(bindPayload, 0, 0) // result formats

		// Then Parse with SQL
		var parsePayload []byte
		parsePayload = append(parsePayload, 0)
		parsePayload = append(parsePayload, []byte("SELECT 1")...)
		parsePayload = append(parsePayload, 0)
		parsePayload = append(parsePayload, 0, 0)

		WriteMessage(clientConn, &Message{Type: 'B', Payload: bindPayload})
		WriteMessage(clientConn, &Message{Type: MsgParse, Payload: parsePayload})
		WriteMessage(clientConn, &Message{Type: 'S', Payload: nil}) // Sync
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Read first message manually to pass to readExtendedBatch
	first, _ := ReadMessage(proxyConn)
	batch, err := readExtendedBatch(context.Background(), proxyConn, first)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if batch.SQL != "SELECT 1" {
		t.Errorf("SQL = %q", batch.SQL)
	}
	if !batch.HasParse {
		t.Error("should have parse")
	}
}

// --- ParseStartupMessage edge cases ---

func TestParseStartupMessageVersionMismatch(t *testing.T) {
	// Build a startup with version 2.0 (not 3.0 or SSL)
	var data []byte
	lenBuf := make([]byte, 4)
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint16(versionBuf[0:2], 2) // major version 2
	binary.BigEndian.PutUint16(versionBuf[2:4], 0) // minor version 0
	data = append(data, lenBuf...)
	data = append(data, versionBuf...)
	data = append(data, 0) // terminator
	binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}
	if startup.IsSSLRequest {
		t.Error("v2 should not be SSL request")
	}
}

// --- ParseDataRow truncated ---

func TestParseDataRowNegativeFieldCount(t *testing.T) {
	// Build data row with column count but truncated field data
	var payload []byte
	cols := make([]byte, 2)
	binary.BigEndian.PutUint16(cols, 1) // 1 column
	payload = append(payload, cols...)
	// Field length but no data
	fieldLen := make([]byte, 4)
	binary.BigEndian.PutUint32(fieldLen, 100) // says 100 bytes
	payload = append(payload, fieldLen...)
	// No actual data follows

	_, err := ParseDataRow(payload)
	if err == nil {
		t.Error("truncated field data should fail")
	}
}
