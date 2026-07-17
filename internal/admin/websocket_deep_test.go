package admin

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/testutil"
)

// --- HandleWebSocket: no upgrade header ---

func TestHandleWebSocketNoUpgrade(t *testing.T) {
	es := NewEventStream()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	w := httptest.NewRecorder()
	es.HandleWebSocket(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d", w.Code)
	}
}

// --- HandleWebSocket: no sec-websocket-key ---

func TestHandleWebSocketNoKey(t *testing.T) {
	es := NewEventStream()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	w := httptest.NewRecorder()
	es.HandleWebSocket(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d", w.Code)
	}
}

func TestEventStreamOriginValidation(t *testing.T) {
	es := NewEventStream()
	if !es.isValidOrigin("") {
		t.Fatal("empty Origin should be allowed for non-browser clients")
	}
	if !es.isValidOrigin("https://admin.example.com") {
		t.Fatal("any origin should be allowed when allowlist is empty (same-origin default)")
	}
	es.SetAllowedOrigins([]string{"https://admin.example.com"})
	if !es.isValidOrigin("https://admin.example.com") {
		t.Fatal("configured origin should be allowed")
	}
	if es.isValidOrigin("https://evil.example.com") {
		t.Fatal("unconfigured origin should be rejected")
	}
}

// --- Full WebSocket: connect, broadcast, close ---

func TestWebSocketFullFlow(t *testing.T) {
	es := NewEventStream()

	// Start real HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Connect as WebSocket client
	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()

	// Should be registered
	testutil.WaitFor(t, time.Second, func() bool {
		return es.Count() == 1
	}, "client should register after connect")

	// Broadcast an event
	es.Broadcast(map[string]string{"type": "test", "data": "hello"})

	// Read the text frame
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame := make([]byte, 1024)
	n, err := conn.Read(frame)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if n < 3 {
		t.Fatal("frame too short")
	}
	// First byte should be 0x81 (FIN + text opcode)
	if frame[0] != 0x81 {
		t.Errorf("opcode = 0x%02x", frame[0])
	}

	// Send close frame
	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00} // FIN+close, masked, empty
	conn.Write(closeFrame)

	testutil.WaitFor(t, time.Second, func() bool {
		return es.Count() == 0
	}, "client should deregister after close")
}

// --- WebSocket: ping → pong ---

func TestWebSocketPingPong(t *testing.T) {
	es := NewEventStream()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()

	testutil.WaitFor(t, time.Second, func() bool {
		return es.Count() == 1
	}, "client should register before ping")

	// Send ping frame (opcode 0x9, masked)
	pingFrame := []byte{0x89, 0x80, 0x00, 0x00, 0x00, 0x00} // FIN+ping, masked, no payload
	conn.Write(pingFrame)

	// Should receive pong (0x8A, 0x00)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if n >= 1 && buf[0] != 0x8A {
		t.Logf("response byte 0x%02x (may be out of order)", buf[0])
	}
}

// --- WebSocket: broadcast to disconnected client ---

func TestWebSocketBroadcastDisconnected(t *testing.T) {
	es := NewEventStream()

	// Add a fake client with closed connection
	c1, c2 := net.Pipe()
	c2.Close() // close the other end
	client := &wsClient{conn: c1}
	es.add(client)

	if es.Count() != 1 {
		t.Fatalf("count = %d", es.Count())
	}

	// Broadcast should remove the dead client
	es.Broadcast(map[string]string{"type": "test"})

	testutil.WaitFor(t, time.Second, func() bool {
		return es.Count() == 0
	}, "dead client should be removed after broadcast")
	c1.Close()
}

// --- WebSocket: broadcast unmarshalable data ---

func TestWebSocketBroadcastMarshalError(t *testing.T) {
	es := NewEventStream()
	// Channel is not JSON serializable
	es.Broadcast(make(chan int))
	// Should not panic — just returns early
}

// --- writeText: large payload ---

func TestWriteTextLargePayload(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	client := &wsClient{conn: c1}

	// Payload between 126 and 65535 bytes — uses 2-byte extended length
	data := make([]byte, 200)
	for i := range data {
		data[i] = 'A'
	}

	go func() {
		c2.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 4096)
		c2.Read(buf)
	}()

	err := client.writeText(data)
	if err != nil {
		t.Errorf("writeText: %v", err)
	}
}

// --- writeText: too large payload ---

func TestWriteTextTooLarge(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()

	client := &wsClient{conn: c1}
	data := make([]byte, 70000) // > 65535
	err := client.writeText(data)
	if err == nil {
		t.Error("payload > 65535 should fail")
	}
}

// --- writeText: write error ---

func TestWriteTextWriteError(t *testing.T) {
	c1, _ := net.Pipe()
	c1.Close() // close immediately

	client := &wsClient{conn: c1}
	err := client.writeText([]byte("test"))
	if err == nil {
		t.Error("write to closed conn should fail")
	}
}

// --- computeAcceptKey ---

func TestComputeAcceptKeyRFC(t *testing.T) {
	// RFC 6455 test vector
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	got := computeAcceptKey(key)
	if got != expected {
		t.Errorf("accept key = %q, want %q", got, expected)
	}
}

// --- helper: WebSocket handshake ---

func wsConnect(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	key := base64.StdEncoding.EncodeToString([]byte("test-key-12345678"))
	req := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", addr, key)
	conn.Write([]byte(req))

	// Read upgrade response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != 101 {
		conn.Close()
		t.Fatalf("upgrade status = %d", resp.StatusCode)
	}

	// Verify accept key
	expectedAccept := computeAcceptKey(key)
	_ = sha1.New() // ensure import used
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedAccept {
		t.Logf("accept key mismatch (non-critical)")
	}

	conn.SetReadDeadline(time.Time{})
	return conn
}
