package mongodb

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestHandlerName(t *testing.T) {
	h := New()
	if h.Name() != "mongodb" {
		t.Errorf("name = %q", h.Name())
	}
}

func TestHandlerDetect(t *testing.T) {
	h := New()
	if h.DetectProtocol([]byte{1, 2, 3, 4}) {
		t.Error("MongoDB should not auto-detect (port-based)")
	}
}

func TestHandlerClose(t *testing.T) {
	h := New()
	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestHandlerRebuildQuery(t *testing.T) {
	h := New()
	if h.RebuildQuery(nil, "test") != nil {
		t.Error("MongoDB RebuildQuery should return nil")
	}
}

func TestClassifyMongoCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"find", "SELECT"},
		{"insert", "INSERT"},
		{"update", "UPDATE"},
		{"delete", "DELETE"},
		{"drop", "DDL"},
		{"createUser", "DCL"},
		{"ping", "ADMIN"},
		{"unknown_cmd", "UNKNOWN"},
	}
	for _, tt := range tests {
		got := classifyMongoCommand(tt.cmd)
		if got.String() != tt.want {
			t.Errorf("classify(%q) = %v, want %s", tt.cmd, got, tt.want)
		}
	}
}

func TestHandlerReadCommand(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	// Build OP_MSG with "ping" command
	go func() {
		var payload []byte
		// FlagBits
		payload = append(payload, 0, 0, 0, 0)
		// Section kind=0
		payload = append(payload, 0)
		// BSON doc: {ping: 1}
		doc := []byte{13, 0, 0, 0, 0x10, 'p', 'i', 'n', 'g', 0, 1, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
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
	if cmd.Raw != "ping" {
		t.Errorf("command = %q, want ping", cmd.Raw)
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg empty")
	}
}

func TestHandlerForwardCommand(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	h := New()
	raw := []byte("test forward data")

	go func() {
		h.ForwardCommand(context.Background(), raw, proxyConn)
	}()

	backendConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 100)
	n, _ := backendConn.Read(buf)
	if string(buf[:n]) != "test forward data" {
		t.Errorf("forwarded = %q", buf[:n])
	}
}
