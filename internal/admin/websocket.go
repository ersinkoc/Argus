package admin

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// EventStream manages WebSocket clients for live event streaming.
type EventStream struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
}

type wsClient struct {
	conn net.Conn
	mu   sync.Mutex
}

// NewEventStream creates a new event stream manager.
func NewEventStream() *EventStream {
	return &EventStream{
		clients: make(map[*wsClient]struct{}),
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

// HandleWebSocket upgrades an HTTP connection to WebSocket.
// Minimal WebSocket implementation (RFC 6455) — no external dependencies.
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

	client := &wsClient{conn: conn}
	es.add(client)
	log.Printf("[argus] WebSocket client connected (%d total)", es.Count())

	// Read loop (handle ping/pong/close)
	go es.readLoop(client, bufrw)
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
