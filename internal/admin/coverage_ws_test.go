package admin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/testutil"
)

// maskedFrame builds a masked client-to-server WebSocket text frame (RFC 6455).
func maskedFrame(payload []byte) []byte {
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	frame := []byte{0x81} // FIN + text opcode
	switch {
	case len(payload) < 126:
		frame = append(frame, byte(len(payload))|0x80)
	case len(payload) < 65536:
		frame = append(frame, 126|0x80, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 127|0x80)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(len(payload)>>(8*i)))
		}
	}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	return frame
}

// maskedFrame64 builds a masked frame that uses the 64-bit extended length
// encoding regardless of payload size.
func maskedFrame64(payload []byte) []byte {
	mask := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	frame := []byte{0x81, 127 | 0x80}
	for i := 7; i >= 0; i-- {
		frame = append(frame, byte(len(payload)>>(8*i)))
	}
	frame = append(frame, mask...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	return frame
}

func TestReadFramePayloadSmall(t *testing.T) {
	want := []byte(`{"type":"auth","token":"x"}`)
	br := bufio.NewReader(bytes.NewReader(maskedFrame(want)))

	got, err := readFramePayload(br)
	if err != nil {
		t.Fatalf("readFramePayload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("payload = %q, want %q", got, want)
	}
}

func TestReadFramePayloadExtended16(t *testing.T) {
	want := bytes.Repeat([]byte("a"), 300)
	br := bufio.NewReader(bytes.NewReader(maskedFrame(want)))

	got, err := readFramePayload(br)
	if err != nil {
		t.Fatalf("readFramePayload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestReadFramePayloadExtended64(t *testing.T) {
	want := []byte("sixty-four-bit length encoding")
	br := bufio.NewReader(bytes.NewReader(maskedFrame64(want)))

	got, err := readFramePayload(br)
	if err != nil {
		t.Fatalf("readFramePayload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("payload = %q, want %q", got, want)
	}
}

func TestReadFramePayloadErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"empty input", nil, "reading frame header"},
		{"missing extended length 16", []byte{0x81, 126 | 0x80}, "reading extended length"},
		{"missing extended length 64", []byte{0x81, 127 | 0x80}, "reading extended length 64"},
		{"missing mask", []byte{0x81, 5 | 0x80}, "reading mask key"},
		{"truncated payload", []byte{0x81, 5 | 0x80, 0x01, 0x02, 0x03, 0x04, 'a', 'b'}, "reading payload"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(bytes.NewReader(tt.data))
			_, err := readFramePayload(br)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

// readAllFrom drains a pipe end in the background so writes to the other
// end (e.g. close frames) never block. Returns a channel with everything read.
func readAllFrom(conn net.Conn) <-chan []byte {
	out := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(conn)
		out <- data
	}()
	return out
}

func TestSendCloseFrame(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	got := readAllFrom(client)

	sendCloseFrame(server, 1008, "policy violation")
	server.Close()

	frame := <-got
	if len(frame) < 4 {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	if frame[0] != 0x88 {
		t.Errorf("opcode byte = 0x%02x, want 0x88", frame[0])
	}
	reason := "policy violation"
	if int(frame[1]) != 2+len(reason) {
		t.Errorf("length byte = %d, want %d", frame[1], 2+len(reason))
	}
	code := int(frame[2])<<8 | int(frame[3])
	if code != 1008 {
		t.Errorf("status code = %d, want 1008", code)
	}
	if string(frame[4:]) != reason {
		t.Errorf("reason = %q, want %q", frame[4:], reason)
	}
}

func TestSendCloseFrameLongReasonTruncated(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	got := readAllFrom(client)

	longReason := strings.Repeat("x", 200)
	sendCloseFrame(server, 1000, longReason)
	server.Close()

	frame := <-got
	if len(frame) < 4 {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	// Reason must be truncated to 123 bytes so total payload is 125.
	if int(frame[1]) != 125 {
		t.Errorf("length byte = %d, want 125", frame[1])
	}
	if got, want := len(frame[4:]), 123; got != want {
		t.Errorf("reason length = %d, want %d", got, want)
	}
}

func TestSendCloseFrameClosedConn(t *testing.T) {
	server, client := net.Pipe()
	client.Close()
	server.Close()
	// Must not panic or block on a dead connection.
	sendCloseFrame(server, 1008, "already gone")
}

// newAuthPipe returns an EventStream with auth enabled, plus the server-side
// bufio pair used by authenticateClient and the client end of the pipe.
func newAuthPipe(t *testing.T, validate func(string) bool) (*EventStream, net.Conn, *bufio.ReadWriter, net.Conn) {
	t.Helper()
	es := NewEventStream()
	es.SetAuth(validate)
	server, client := net.Pipe()
	t.Cleanup(func() {
		server.Close()
		client.Close()
	})
	br := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
	return es, server, br, client
}

func TestAuthenticateClientValidToken(t *testing.T) {
	es, server, br, client := newAuthPipe(t, func(tok string) bool { return tok == "secret" })

	go func() {
		client.Write(maskedFrame([]byte(`{"type":"auth","token":"secret"}`)))
	}()

	if err := es.authenticateClient(server, br); err != nil {
		t.Fatalf("authenticateClient: %v", err)
	}
}

func TestAuthenticateClientInvalidToken(t *testing.T) {
	es, server, br, client := newAuthPipe(t, func(tok string) bool { return tok == "secret" })

	frames := make(chan []byte, 1)
	go func() {
		client.Write(maskedFrame([]byte(`{"type":"auth","token":"wrong"}`)))
		buf := make([]byte, 256)
		n, _ := client.Read(buf)
		frames <- buf[:n]
	}()

	err := es.authenticateClient(server, br)
	if err == nil || !strings.Contains(err.Error(), "invalid auth token") {
		t.Fatalf("error = %v, want invalid auth token", err)
	}

	frame := <-frames
	if len(frame) < 4 || frame[0] != 0x88 {
		t.Fatalf("expected close frame, got % x", frame)
	}
	if code := int(frame[2])<<8 | int(frame[3]); code != 1008 {
		t.Errorf("close code = %d, want 1008", code)
	}
}

func TestAuthenticateClientWrongFrameType(t *testing.T) {
	es, server, br, client := newAuthPipe(t, func(string) bool { return true })

	go func() {
		client.Write(maskedFrame([]byte(`{"type":"hello","token":"secret"}`)))
		io.Copy(io.Discard, client)
	}()

	err := es.authenticateClient(server, br)
	if err == nil || !strings.Contains(err.Error(), "expected auth frame") {
		t.Fatalf("error = %v, want expected auth frame", err)
	}
}

func TestAuthenticateClientInvalidJSON(t *testing.T) {
	es, server, br, client := newAuthPipe(t, func(string) bool { return true })

	go func() {
		client.Write(maskedFrame([]byte(`{not json`)))
		io.Copy(io.Discard, client)
	}()

	err := es.authenticateClient(server, br)
	if err == nil || !strings.Contains(err.Error(), "parsing auth frame") {
		t.Fatalf("error = %v, want parsing auth frame", err)
	}
}

func TestAuthenticateClientReadError(t *testing.T) {
	es, server, br, client := newAuthPipe(t, func(string) bool { return true })

	client.Close() // client disconnects before sending the auth frame

	err := es.authenticateClient(server, br)
	if err == nil || !strings.Contains(err.Error(), "reading auth frame") {
		t.Fatalf("error = %v, want reading auth frame", err)
	}
}

func TestAuthenticateClientNilValidator(t *testing.T) {
	// authEnabled with a nil validateToken must reject the token.
	es := NewEventStream()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	br := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))

	go func() {
		client.Write(maskedFrame([]byte(`{"type":"auth","token":"anything"}`)))
		io.Copy(io.Discard, client)
	}()

	err := es.authenticateClient(server, br)
	if err == nil || !strings.Contains(err.Error(), "invalid auth token") {
		t.Fatalf("error = %v, want invalid auth token", err)
	}
}

// wsUpgrade dials the test server and performs a WebSocket upgrade handshake.
func wsUpgrade(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	req := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", "dGhlIHNhbXBsZSBub25jZQ==")
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	return conn
}

func startWSServer(t *testing.T, es *EventStream) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", es.HandleWebSocket)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})
	return ln.Addr().String()
}

func TestHandleWebSocketFirstFrameAuthAccepted(t *testing.T) {
	es := NewEventStream()
	es.SetAuth(func(tok string) bool { return tok == "tok-123" })
	addr := startWSServer(t, es)

	conn := wsUpgrade(t, addr)

	auth, _ := json.Marshal(authFrame{Type: "auth", Token: "tok-123"})
	if _, err := conn.Write(maskedFrame(auth)); err != nil {
		t.Fatalf("write auth frame: %v", err)
	}

	testutil.WaitFor(t, 2*time.Second, func() bool { return es.Count() == 1 },
		"authenticated client should be registered")
}

func TestHandleWebSocketFirstFrameAuthRejected(t *testing.T) {
	es := NewEventStream()
	es.SetAuth(func(tok string) bool { return tok == "tok-123" })
	addr := startWSServer(t, es)

	conn := wsUpgrade(t, addr)

	auth, _ := json.Marshal(authFrame{Type: "auth", Token: "bad-token"})
	if _, err := conn.Write(maskedFrame(auth)); err != nil {
		t.Fatalf("write auth frame: %v", err)
	}

	// Server must answer with a close frame (0x88) and never register the client.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read close frame: %v", err)
	}
	if n < 2 || buf[0] != 0x88 {
		t.Fatalf("expected close frame, got % x", buf[:n])
	}
	if es.Count() != 0 {
		t.Errorf("client count = %d, want 0", es.Count())
	}
}
