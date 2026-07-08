package mongodb

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- Handshake with OP_MSG hello ---

func TestHandshakeWithOpMsg(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()

	go func() {
		// Client: send OP_MSG with "hello" command
		var payload []byte
		// FlagBits
		payload = append(payload, 0, 0, 0, 0)
		// Section kind=0
		payload = append(payload, 0)
		// BSON doc: {hello: 1}
		doc := []byte{14, 0, 0, 0, 0x10, 'h', 'e', 'l', 'l', 'o', 0, 1, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
		payload = append(payload, doc...)

		msg := &Message{
			Header:  MsgHeader{RequestID: 1, OpCode: OpMsg},
			Payload: payload,
		}
		WriteMessage(clientConn, msg)

		// Read response
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(clientConn)
	}()

	go func() {
		// Backend: read hello, send response
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(backendConn)

		// Send OP_MSG response
		var payload []byte
		payload = append(payload, 0, 0, 0, 0)
		payload = append(payload, 0)
		doc := []byte{12, 0, 0, 0, 0x10, 'o', 'k', 0, 1, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
		payload = append(payload, doc...)

		resp := &Message{
			Header:  MsgHeader{RequestID: 2, ResponseTo: 1, OpCode: OpMsg},
			Payload: payload,
		}
		WriteMessage(backendConn, resp)
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if info.Username != "mongodb_user" {
		t.Errorf("username = %q", info.Username)
	}
	if info.Parameters["hello_cmd"] != "hello" {
		t.Errorf("hello_cmd = %q", info.Parameters["hello_cmd"])
	}
}

func TestHandshakeNonOpMsg(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()

	go func() {
		// Client: send OP_QUERY (not OP_MSG)
		msg := &Message{
			Header:  MsgHeader{RequestID: 1, OpCode: OpQuery},
			Payload: []byte("query data"),
		}
		WriteMessage(clientConn, msg)
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(clientConn)
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(backendConn)
		resp := &Message{
			Header:  MsgHeader{RequestID: 2, ResponseTo: 1, OpCode: OpReply},
			Payload: []byte("reply data"),
		}
		WriteMessage(backendConn, resp)
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	// Non-OP_MSG: cmdName should be empty
	if info.Parameters["hello_cmd"] != "" {
		t.Errorf("hello_cmd should be empty for non-OP_MSG, got %q", info.Parameters["hello_cmd"])
	}
}

// --- ReadAndForwardResult ---

func TestReadAndForwardResult(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		msg := &Message{
			Header:  MsgHeader{RequestID: 2, ResponseTo: 1, OpCode: OpMsg},
			Payload: []byte("result data"),
		}
		WriteMessage(backendConn, msg)
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.ByteCount == 0 {
		t.Error("byte count should be non-zero")
	}
}

// --- ReadMessage edge cases ---

func TestReadMessageInvalidLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// Write header with length < 16
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint32(buf[0:4], 8) // too short
		clientConn.Write(buf)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadMessage(serverConn)
	if err == nil {
		t.Error("should fail for invalid length")
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint32(buf[0:4], 50*1024*1024) // > 48MB
		clientConn.Write(buf)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadMessage(serverConn)
	if err == nil {
		t.Error("should fail for oversized message")
	}
}

func TestReadMessageExactHeader(t *testing.T) {
	// Message with exactly 16 bytes (no payload)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint32(buf[0:4], 16)           // exact header size
		binary.LittleEndian.PutUint32(buf[12:16], uint32(OpMsg))
		clientConn.Write(buf)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	msg, err := ReadMessage(serverConn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if len(msg.Payload) != 0 {
		t.Errorf("payload should be empty, got %d bytes", len(msg.Payload))
	}
}

// --- ParseOpMsg edge cases ---

func TestParseOpMsgBodyTruncated(t *testing.T) {
	// Kind=0 but not enough data for BSON doc length
	payload := []byte{0, 0, 0, 0, 0, 1, 2} // flagBits + kind=0 + only 2 bytes
	_, _, err := ParseOpMsg(payload)
	if err == nil {
		t.Error("should fail for truncated body")
	}
}

func TestParseOpMsgBodyDocTruncated(t *testing.T) {
	// Kind=0, BSON doc length says 100 but only 4 bytes
	payload := []byte{0, 0, 0, 0, 0, 100, 0, 0, 0}
	_, _, err := ParseOpMsg(payload)
	if err == nil {
		t.Error("should fail for truncated body doc")
	}
}

func TestParseOpMsgSequenceTruncated(t *testing.T) {
	// Kind=1 but not enough data for sequence length
	payload := []byte{0, 0, 0, 0, 1, 1, 2}
	_, _, err := ParseOpMsg(payload)
	if err == nil {
		t.Error("should fail for truncated sequence")
	}
}

func TestParseOpMsgSequenceDataTruncated(t *testing.T) {
	// Kind=1, sequence length says 100 but only 4 bytes
	payload := []byte{0, 0, 0, 0, 1, 100, 0, 0, 0}
	_, _, err := ParseOpMsg(payload)
	if err == nil {
		t.Error("should fail for truncated sequence data")
	}
}

func TestParseOpMsgTooShortDeep(t *testing.T) {
	_, _, err := ParseOpMsg([]byte{1, 2, 3})
	if err == nil {
		t.Error("should fail for too-short payload")
	}
	_, _, err = ParseOpMsg(nil)
	if err == nil {
		t.Error("nil should fail")
	}
}

// --- ExtractCommandName edge cases ---

func TestExtractCommandNameShort(t *testing.T) {
	if ExtractCommandName(nil) != "" {
		t.Error("nil should return empty")
	}
	if ExtractCommandName([]byte{1, 2}) != "" {
		t.Error("short doc should return empty")
	}
}

func TestExtractCommandNameEmptyDoc(t *testing.T) {
	// BSON doc with just terminator
	doc := []byte{5, 0, 0, 0, 0}
	if ExtractCommandName(doc) != "" {
		t.Error("empty doc should return empty")
	}
}

func TestExtractCommandNameValid(t *testing.T) {
	// BSON: {find: 1}
	doc := []byte{13, 0, 0, 0, 0x10, 'f', 'i', 'n', 'd', 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
	got := ExtractCommandName(doc)
	if got != "find" {
		t.Errorf("got %q, want 'find'", got)
	}
}

// --- encodeHeader ---

func TestEncodeHeaderFields(t *testing.T) {
	msg := &Message{
		Header:  MsgHeader{RequestID: 42, ResponseTo: 10, OpCode: OpMsg},
		Payload: []byte("test"),
	}
	hdr := encodeHeader(msg)
	if len(hdr) != 16 {
		t.Fatalf("header len = %d", len(hdr))
	}
	totalLen := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	if totalLen != 20 { // 16 + 4
		t.Errorf("totalLen = %d, want 20", totalLen)
	}
	reqID := int32(binary.LittleEndian.Uint32(hdr[4:8]))
	if reqID != 42 {
		t.Errorf("requestID = %d", reqID)
	}
}

// --- WriteError and RebuildQuery ---

func TestWriteErrorSendsOpMsg(t *testing.T) {
	h := New()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		buf := make([]byte, 4096)
		c1.SetReadDeadline(time.Now().Add(time.Second))
		c1.Read(buf)
	}()

	err := h.WriteError(context.Background(), c2, "42000", "access denied")
	if err != nil {
		t.Errorf("WriteError: %v", err)
	}
}

// --- ReadCommand with non-OP_MSG ---

func TestReadCommandNonOpMsg(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		msg := &Message{
			Header:  MsgHeader{RequestID: 1, OpCode: OpQuery},
			Payload: []byte("query payload"),
		}
		WriteMessage(clientConn, msg)
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Type.String() != "UNKNOWN" {
		t.Errorf("type = %v", cmd.Type)
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg empty")
	}
}

func TestReadCommandOpMsgFind(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		var payload []byte
		payload = append(payload, 0, 0, 0, 0) // flagBits
		payload = append(payload, 0) // kind=0
		doc := []byte{13, 0, 0, 0, 0x10, 'f', 'i', 'n', 'd', 0, 1, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
		payload = append(payload, doc...)

		msg := &Message{
			Header:  MsgHeader{RequestID: 1, OpCode: OpMsg},
			Payload: payload,
		}
		WriteMessage(clientConn, msg)
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "find" {
		t.Errorf("cmd = %q, want 'find'", cmd.Raw)
	}
	if cmd.Type.String() != "SELECT" {
		t.Errorf("type = %v, want SELECT", cmd.Type)
	}
}
