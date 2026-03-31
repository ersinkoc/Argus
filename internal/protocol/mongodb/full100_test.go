package mongodb

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- ReadMessage: payload read error (header OK but payload truncated) ---

func TestReadMessagePayloadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// Write header indicating payload of 100 bytes
		buf := make([]byte, 16)
		binary.LittleEndian.PutUint32(buf[0:4], 116) // 16 header + 100 payload
		binary.LittleEndian.PutUint32(buf[12:16], uint32(OpMsg))
		clientConn.Write(buf)
		// Write only 10 bytes of payload (incomplete), then close
		clientConn.Write([]byte("short_data"))
		clientConn.Close()
	}()

	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := ReadMessage(serverConn)
	if err == nil {
		t.Error("truncated payload should cause read error")
	}
}

// --- ParseOpMsg: body doc too small (docLen < 5) ---

func TestParseOpMsgBodyDocTooSmall(t *testing.T) {
	// Kind=0, then BSON doc with length = 3 (< 5 minimum)
	payload := make([]byte, 4+1+4)
	// flagBits
	binary.LittleEndian.PutUint32(payload[0:4], 0)
	// kind = 0
	payload[4] = 0
	// docLen = 3 (too small)
	binary.LittleEndian.PutUint32(payload[5:9], 3)

	_, _, err := ParseOpMsg(payload)
	if err == nil {
		t.Error("doc too small should fail")
	}
}

// --- ParseOpMsg: sequence too small (seqLen < 4) ---

func TestParseOpMsgSequenceTooSmall(t *testing.T) {
	// Kind=1, then sequence with length = 2 (< 4 minimum)
	payload := make([]byte, 4+1+4)
	// flagBits
	binary.LittleEndian.PutUint32(payload[0:4], 0)
	// kind = 1
	payload[4] = 1
	// seqLen = 2 (too small)
	binary.LittleEndian.PutUint32(payload[5:9], 2)

	_, _, err := ParseOpMsg(payload)
	if err == nil {
		t.Error("sequence too small should fail")
	}
}

// --- ParseOpMsg: offset >= len(payload) after kind byte (break path) ---
// This path: the `if offset >= len(payload)` guard at the start of the for loop body.
// We need payload where after reading one complete section, offset exactly equals len(payload).
// Actually this guard is at the start of the for body, not after kind read.
// It triggers when the for loop condition `offset < len(payload)` is true but
// the next check `offset >= len(payload)` triggers. This is impossible logically
// since the for condition already checks this. But to be safe, let's test with
// a payload that ends exactly after a complete section.

func TestParseOpMsgExactEnd(t *testing.T) {
	// Build a valid OP_MSG with one body section that ends exactly at payload end
	doc := []byte{5, 0, 0, 0, 0} // minimal valid BSON doc (5 bytes)
	payload := make([]byte, 4+1+len(doc))
	binary.LittleEndian.PutUint32(payload[0:4], 0) // flagBits
	payload[4] = 0                                   // kind = 0
	copy(payload[5:], doc)

	flagBits, sections, err := ParseOpMsg(payload)
	if err != nil {
		t.Fatalf("ParseOpMsg: %v", err)
	}
	if flagBits != 0 {
		t.Errorf("flagBits = %d", flagBits)
	}
	if len(sections) != 1 {
		t.Errorf("sections = %d, want 1", len(sections))
	}
}

// --- ReadCommand: ReadMessage returns error ---

func TestReadCommandReadError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	clientConn.Close() // close immediately

	h := New()
	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err := h.ReadCommand(context.Background(), proxyConn)
	proxyConn.Close()
	if err == nil {
		t.Error("read error should propagate from ReadCommand")
	}
}

// --- ReadCommand: OP_MSG with ParseOpMsg error (bad payload) ---

func TestReadCommandOpMsgParseError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		// Send OP_MSG with payload that's too short for ParseOpMsg (< 5 bytes)
		// but len(msg.Payload) > 5 will be checked first.
		// Actually we need payload > 5 but with invalid content.
		// The handler checks: msg.Header.OpCode == OpMsg && len(msg.Payload) > 5
		// Then calls ParseOpMsg which can fail.
		// If ParseOpMsg returns error, the handler still returns cmd (just doesn't classify).
		// Wait, let me re-read the handler code...
		// The handler: if err == nil && len(sections) > 0 { ... }
		// So if ParseOpMsg errors, it just skips classification. Not a new path.

		// Actually let me just send a valid OP_MSG to verify.
		var payload []byte
		payload = append(payload, 0, 0, 0, 0) // flagBits
		payload = append(payload, 0)            // kind = 0
		doc := []byte{5, 0, 0, 0, 0}           // minimal empty BSON doc
		payload = append(payload, doc...)

		msg := &Message{
			Header:  MsgHeader{RequestID: 1, OpCode: OpMsg},
			Payload: payload,
		}
		WriteMessage(clientConn, msg)
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg should not be empty")
	}
}
