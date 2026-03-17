package admin

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestWebSocketHandshake(t *testing.T) {
	es := NewEventStream()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	// Connect as WebSocket client
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send WebSocket upgrade request
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	req := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", key)
	conn.Write([]byte(req))

	// Read response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if resp.StatusCode != 101 {
		t.Errorf("status = %d, want 101", resp.StatusCode)
	}

	// Verify accept key
	magic := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	expectedAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	gotAccept := resp.Header.Get("Sec-WebSocket-Accept")
	if gotAccept != expectedAccept {
		t.Errorf("accept = %q, want %q", gotAccept, expectedAccept)
	}

	time.Sleep(100 * time.Millisecond)

	// Client count should be 1
	if es.Count() < 1 {
		t.Errorf("connected clients = %d, want >= 1", es.Count())
	}

	// Broadcast a message
	es.Broadcast(map[string]string{"test": "hello"})

	// Read WebSocket frame
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame := make([]byte, 256)
	n, err := conn.Read(frame)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	if n < 2 {
		t.Fatal("frame too short")
	}

	// First byte: 0x81 = FIN + text opcode
	if frame[0] != 0x81 {
		t.Errorf("opcode = 0x%02x, want 0x81", frame[0])
	}

	// Send close frame
	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00} // masked empty close
	conn.Write(closeFrame)

	time.Sleep(200 * time.Millisecond)
}

func TestWebSocketBadUpgrade(t *testing.T) {
	es := NewEventStream()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	// Regular HTTP GET (not WebSocket)
	conn, _ := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	defer conn.Close()

	conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: localhost\r\n\r\n"))

	conn.SetReadDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(conn)
	resp, _ := http.ReadResponse(reader, nil)

	if resp != nil && resp.StatusCode != 400 {
		t.Errorf("non-WS request: status = %d, want 400", resp.StatusCode)
	}
}

func TestWebSocketMissingKey(t *testing.T) {
	es := NewEventStream()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	conn, _ := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	defer conn.Close()

	// Upgrade header but no Sec-WebSocket-Key
	conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))

	conn.SetReadDeadline(time.Now().Add(time.Second))
	reader := bufio.NewReader(conn)
	resp, _ := http.ReadResponse(reader, nil)

	if resp != nil && resp.StatusCode != 400 {
		t.Errorf("missing key: status = %d, want 400", resp.StatusCode)
	}
}
