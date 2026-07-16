package admin

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// EventStream manages WebSocket clients for live event streaming.
type EventStream struct {
	mu             sync.RWMutex
	clients        map[*wsClient]struct{}
	allowedOrigins map[string]struct{}
	validateToken  func(string) bool // nil = no auth required
	authEnabled    bool
}

// SetAuth sets the token validation function for first-frame WebSocket auth.
// When set, every WebSocket connection must send a JSON auth frame
// {"type":"auth","token":"..."} as its first message after upgrade.
func (es *EventStream) SetAuth(validateToken func(string) bool) {
	es.validateToken = validateToken
	es.authEnabled = validateToken != nil
}

type wsClient struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewEventStream creates a new event stream manager.
func NewEventStream() *EventStream {
	return &EventStream{
		clients:        make(map[*wsClient]struct{}),
		allowedOrigins: make(map[string]struct{}),
	}
}

// SetAllowedOrigins replaces the WebSocket/browser origin allowlist.
func (es *EventStream) SetAllowedOrigins(origins []string) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.allowedOrigins = make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		if origin != "" {
			es.allowedOrigins[origin] = struct{}{}
		}
	}
}

// Broadcast sends an event to all connected WebSocket clients.
func (es *EventStream) Broadcast(event any) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	es.mu.RLock()
	clients := make([]*wsClient, 0, len(es.clients))
	for c := range es.clients {
		clients = append(clients, c)
	}
	es.mu.RUnlock()

	for _, c := range clients {
		if err := c.writeText(data); err != nil {
			es.remove(c)
		}
	}
}

// Count returns the number of connected clients.
func (es *EventStream) Count() int {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return len(es.clients)
}

func (es *EventStream) add(c *wsClient) {
	es.mu.Lock()
	es.clients[c] = struct{}{}
	es.mu.Unlock()
}

func (es *EventStream) remove(c *wsClient) {
	es.mu.Lock()
	delete(es.clients, c)
	es.mu.Unlock()
	c.conn.Close()
}

// authFrame is the expected first-frame auth message from WebSocket clients.
type authFrame struct {
	Type  string `json:"type"`
	Token string `json:"token"`
}

// HandleWebSocket upgrades an HTTP connection to WebSocket.
// Minimal WebSocket implementation (RFC 6455) — no external dependencies.
// If auth is enabled, the client must send a first-frame auth message
// {"type":"auth","token":"..."} immediately after the upgrade handshake.
func (es *EventStream) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Validate WebSocket upgrade headers
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "Expected WebSocket upgrade", http.StatusBadRequest)
		return
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Validate Origin header (RFC 6455) — prevent cross-site WebSocket hijacking
	origin := r.Header.Get("Origin")
	if !es.isValidOrigin(origin) {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}

	// Compute accept key
	accept := computeAcceptKey(key)

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send upgrade response
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	bufrw.WriteString(resp)
	bufrw.Flush()

	// First-frame authentication (if enabled)
	if es.authEnabled {
		if err := es.authenticateClient(conn, bufrw); err != nil {
			slog.Warn("WebSocket auth rejected", "error", err)
			return
		}
	}

	client := &wsClient{conn: conn}
	es.add(client)
	slog.Info("WebSocket client connected", "total", es.Count())

	// Read loop (handle ping/pong/close)
	go es.readLoop(client, bufrw)
}

// authenticateClient reads the first WebSocket frame and validates the auth token.
// It sends a close frame and returns an error if authentication fails.
func (es *EventStream) authenticateClient(conn net.Conn, br *bufio.ReadWriter) error {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	payload, err := readFramePayload(br.Reader)
	if err != nil {
		sendCloseFrame(conn, 1008, "auth read error")
		return fmt.Errorf("reading auth frame: %w", err)
	}

	var frame authFrame
	if err := json.Unmarshal(payload, &frame); err != nil {
		sendCloseFrame(conn, 1008, "invalid auth frame")
		return fmt.Errorf("parsing auth frame: %w", err)
	}

	if frame.Type != "auth" {
		sendCloseFrame(conn, 1008, "expected auth frame")
		return fmt.Errorf("expected auth frame, got %q", frame.Type)
	}

	if es.validateToken == nil || !es.validateToken(frame.Token) {
		sendCloseFrame(conn, 1008, "invalid token")
		return fmt.Errorf("invalid auth token")
	}

	return nil
}

func (es *EventStream) readLoop(c *wsClient, br *bufio.ReadWriter) {
	defer es.remove(c)

	for {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		// Read WebSocket frame header
		header := make([]byte, 2)
		if _, err := br.Read(header); err != nil {
			return
		}

		opcode := header[0] & 0x0F
		// masked := header[1] & 0x80 != 0
		payloadLen := int(header[1] & 0x7F)

		if payloadLen == 126 {
			ext := make([]byte, 2)
			if _, err := br.Read(ext); err != nil {
				return
			}
			payloadLen = int(ext[0])<<8 | int(ext[1])
		}

		// Read mask key (4 bytes if masked)
		if header[1]&0x80 != 0 {
			mask := make([]byte, 4)
			br.Read(mask)
		}

		// Read payload
		if payloadLen > 0 {
			payload := make([]byte, payloadLen)
			br.Read(payload)
		}

		switch opcode {
		case 0x8: // close
			return
		case 0x9: // ping → send pong
			c.writePong()
		case 0xA: // pong
			continue
		}
	}
}

// writeText sends a text frame over WebSocket.
func (c *wsClient) writeText(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	frame := make([]byte, 0, 2+len(data))
	frame = append(frame, 0x81) // FIN + text opcode

	if len(data) < 126 {
		frame = append(frame, byte(len(data)))
	} else if len(data) < 65536 {
		frame = append(frame, 126, byte(len(data)>>8), byte(len(data)))
	} else {
		return fmt.Errorf("payload too large for WebSocket frame")
	}

	frame = append(frame, data...)

	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := c.conn.Write(frame)
	return err
}

func (c *wsClient) writePong() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conn.Write([]byte{0x8A, 0x00}) // FIN + pong, no payload
}

func computeAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// readFramePayload reads one WebSocket frame and returns its unmasked payload.
// Client-to-server frames are always masked (RFC 6455 §5.1).
func readFramePayload(br *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := br.Read(header); err != nil {
		return nil, fmt.Errorf("reading frame header: %w", err)
	}

	payloadLen := int64(header[1] & 0x7F)
	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := br.Read(ext); err != nil {
			return nil, fmt.Errorf("reading extended length: %w", err)
		}
		payloadLen = int64(ext[0])<<8 | int64(ext[1])
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := br.Read(ext); err != nil {
			return nil, fmt.Errorf("reading extended length 64: %w", err)
		}
		payloadLen = 0
		for i := 0; i < 8; i++ {
			payloadLen = (payloadLen << 8) | int64(ext[i])
		}
	}

	// Read mask key (always present from client)
	mask := make([]byte, 4)
	if _, err := br.Read(mask); err != nil {
		return nil, fmt.Errorf("reading mask key: %w", err)
	}

	// Read and unmask payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}

	return payload, nil
}

// sendCloseFrame sends a WebSocket close frame with the given status code and reason.
func sendCloseFrame(conn net.Conn, statusCode int, reason string) {
	reasonBytes := []byte(reason)
	if len(reasonBytes) > 123 {
		reasonBytes = reasonBytes[:123]
	}
	frame := []byte{0x88} // FIN + close opcode
	length := 2 + len(reasonBytes)
	if length <= 125 {
		frame = append(frame, byte(length))
	} else {
		frame = append(frame, 126, byte(length>>8), byte(length))
	}
	frame = append(frame, byte(statusCode>>8), byte(statusCode))
	frame = append(frame, reasonBytes...)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	conn.Write(frame)
}

// isValidOrigin checks if the Origin header is acceptable.
// Empty Origin is allowed for non-browser clients. Browser-originated requests
// must match the configured allowlist exactly.
func (es *EventStream) isValidOrigin(origin string) bool {
	// Empty Origin (no header) is always allowed for non-browser clients
	// such as curl, CLI tools, and programmatic WebSocket consumers.
	if origin == "" {
		return true
	}

	es.mu.RLock()
	defer es.mu.RUnlock()
	// Empty allowlist with a non-empty Origin means reject all.
	// Operators must explicitly configure allowed origins for browser clients.
	if len(es.allowedOrigins) == 0 {
		slog.Warn("WebSocket origin rejected (allowlist empty)", "origin", origin)
		return false
	}
	_, allowed := es.allowedOrigins[origin]
	if !allowed {
		slog.Warn("WebSocket origin rejected", "origin", origin)
	}
	return allowed
}
