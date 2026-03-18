package admin

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadLoopExtendedPayload126(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)

	// Send a masked text frame with 130-byte payload (triggers 126 extended length)
	payload := make([]byte, 130)
	for i := range payload {
		payload[i] = 'x'
	}
	mask := []byte{0x01, 0x02, 0x03, 0x04}
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}

	// Frame: FIN+text(0x81), masked+126(0xFE), 2-byte length, 4-byte mask, payload
	frame := []byte{0x81, 0x80 | 126, byte(len(payload) >> 8), byte(len(payload))}
	frame = append(frame, mask...)
	frame = append(frame, masked...)
	conn.Write(frame)

	time.Sleep(100 * time.Millisecond)

	// Client should still be connected
	if es.Count() != 1 {
		t.Errorf("client disconnected after extended payload, count=%d", es.Count())
	}

	// Send close to clean up
	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	time.Sleep(100 * time.Millisecond)
}

func TestReadLoopPongFrame(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)

	// Send a pong frame (opcode 0xA) — server should just continue
	pongFrame := []byte{0x8A, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(pongFrame)
	time.Sleep(100 * time.Millisecond)

	if es.Count() != 1 {
		t.Errorf("client disconnected after pong, count=%d", es.Count())
	}

	// Clean up
	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	time.Sleep(100 * time.Millisecond)
}

func TestReadLoopConnectionDrop(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	time.Sleep(50 * time.Millisecond)

	if es.Count() != 1 {
		t.Fatalf("expected 1 client, got %d", es.Count())
	}

	// Drop connection abruptly
	conn.Close()
	time.Sleep(200 * time.Millisecond)

	// readLoop should detect and remove the client
	if es.Count() != 0 {
		t.Errorf("client not removed after drop, count=%d", es.Count())
	}
}

func TestReadLoopMaskedTextFrame(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)

	// Send a short masked text frame (5 bytes payload)
	payload := []byte("hello")
	mask := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}

	frame := []byte{0x81, 0x80 | byte(len(payload))}
	frame = append(frame, mask...)
	frame = append(frame, masked...)
	conn.Write(frame)

	time.Sleep(100 * time.Millisecond)

	// Should still be connected — server ignores text frames from client
	if es.Count() != 1 {
		t.Errorf("client disconnected after text frame, count=%d", es.Count())
	}

	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	time.Sleep(100 * time.Millisecond)
}

func TestReadLoopUnmaskedFrame(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)

	// Send an unmasked text frame (no mask bit)
	payload := []byte("hi")
	frame := []byte{0x81, byte(len(payload))}
	frame = append(frame, payload...)
	conn.Write(frame)

	time.Sleep(100 * time.Millisecond)

	// Server should handle it (no crash)
	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	time.Sleep(100 * time.Millisecond)
}

func TestWritePong(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	client := &wsClient{conn: c1}

	go func() {
		buf := make([]byte, 10)
		c2.SetReadDeadline(time.Now().Add(time.Second))
		n, err := c2.Read(buf)
		if err != nil {
			return
		}
		// Should be pong frame: 0x8A, 0x00
		if n != 2 || buf[0] != 0x8A || buf[1] != 0x00 {
			t.Errorf("pong frame: got %x", buf[:n])
		}
	}()

	client.writePong()
	time.Sleep(100 * time.Millisecond)
}

func TestHandleWebSocketNonHijacker(t *testing.T) {
	es := NewEventStream()
	// httptest.NewRecorder does NOT implement Hijacker
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Key", "dGVzdA==")
	es.HandleWebSocket(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-hijacker, got %d", w.Code)
	}
}

// hijackableRecorder implements http.Hijacker for testing
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	conn   net.Conn
	reader *bufio.ReadWriter
}

func (hr *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return hr.conn, hr.reader, nil
}
