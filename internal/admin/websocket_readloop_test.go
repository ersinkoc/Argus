package admin

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/testutil"
)

func TestReadLoopExtendedPayload126(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should register")

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

	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should stay connected after extended payload")

	// Send close to clean up
	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 0 }, "client should deregister after close")
}

func TestReadLoopPongFrame(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should register")

	// Send a pong frame (opcode 0xA) — server should just continue
	pongFrame := []byte{0x8A, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(pongFrame)

	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should stay connected after pong")

	// Clean up
	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 0 }, "client should deregister after close")
}

func TestReadLoopConnectionDrop(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())

	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should register")

	// Drop connection abruptly
	conn.Close()
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 0 }, "client should be removed after connection drop")
}

func TestReadLoopMaskedTextFrame(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should register")

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

	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should stay connected after text frame")

	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 0 }, "client should deregister after close")
}

func TestReadLoopUnmaskedFrame(t *testing.T) {
	es := NewEventStream()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	conn := wsConnect(t, srv.Listener.Addr().String())
	defer conn.Close()
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should register")

	// Send an unmasked text frame (no mask bit)
	payload := []byte("hi")
	frame := []byte{0x81, byte(len(payload))}
	frame = append(frame, payload...)
	conn.Write(frame)

	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 1 }, "client should stay connected after unmasked frame")

	closeFrame := []byte{0x88, 0x80, 0x00, 0x00, 0x00, 0x00}
	conn.Write(closeFrame)
	testutil.WaitFor(t, time.Second, func() bool { return es.Count() == 0 }, "client should deregister after close")
}

func TestWritePong(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	client := &wsClient{conn: c1}

	done := make(chan struct{})
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
		close(done)
	}()

	client.writePong()
	testutil.WaitFor(t, time.Second, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, "goroutine should receive pong frame")
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
