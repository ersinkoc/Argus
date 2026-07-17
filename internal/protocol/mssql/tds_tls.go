package mssql

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tdsTLSMaxPacketSize = 4096
	tdsTLSMaxPayload    = tdsTLSMaxPacketSize - headerSize
)

// TDSTLSHandshakeConn adapts a TDS connection for use as the transport of a
// crypto/tls connection during the TDS 7.x TLS handshake. During the
// handshake, it wraps TLS bytes in PRELOGIN packets on write and removes the
// PRELOGIN packet headers on read.
//
// Once the TLS handshake is complete, call FinishHandshake (or
// SetPassthrough) so subsequent traffic is sent as raw TLS records. Any
// PRELOGIN payload already buffered by Read is returned before passthrough
// reads begin.
type TDSTLSHandshakeConn struct {
	conn net.Conn

	readMu       sync.Mutex
	pending      []byte
	handshakeRaw atomic.Bool
	rawSeen      atomic.Bool

	writeMu  sync.Mutex
	packetID byte

	passthrough atomic.Bool
}

var _ net.Conn = (*TDSTLSHandshakeConn)(nil)

// NewTDSTLSHandshakeConn returns a connection that frames TLS handshake bytes
// in TDS PRELOGIN packets.
func NewTDSTLSHandshakeConn(conn net.Conn) *TDSTLSHandshakeConn {
	return &TDSTLSHandshakeConn{conn: conn}
}

// Read returns TLS bytes with their TDS PRELOGIN framing removed.
func (c *TDSTLSHandshakeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if len(c.pending) != 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			if len(c.pending) == 0 {
				c.pending = nil
			}
			return n, nil
		}

		if c.passthrough.Load() || c.handshakeRaw.Load() {
			n, err := c.conn.Read(p)
			if n > 0 {
				// The client has switched to raw TLS records mid-handshake.
				// The server's next flight must be raw as well.
				c.rawSeen.Store(true)
			}
			return n, err
		}

		pkt, err := ReadPacket(c.conn)
		if err != nil {
			slog.Debug("tds tls read packet failed", "passthrough", c.passthrough.Load(), "raw", c.handshakeRaw.Load(), "error", err)
			return 0, err
		}
		slog.Debug("tds tls read packet", "type", fmt.Sprintf("0x%02x", pkt.Type), "length", len(pkt.Data), "status", pkt.Status, "seq", pkt.SeqNo)
		if pkt.Type != PacketPreLogin {
			return 0, fmt.Errorf("unexpected TDS packet type 0x%02x during TLS handshake, want PRELOGIN (0x%02x)", pkt.Type, PacketPreLogin)
		}
		// ODBC 18/sqlcmd sends only the initial ClientHello inside TDS PRELOGIN.
		// After the server's first TLS flight, subsequent client handshake bytes
		// arrive as raw TLS records on the same TCP stream.
		c.handshakeRaw.Store(true)
		if len(pkt.Data) > 0 {
			preview := pkt.Data
			if len(preview) > 5 {
				preview = preview[:5]
			}
			slog.Debug("tds tls unwrapped bytes", "preview", fmt.Sprintf("% x", preview))
		}
		c.pending = pkt.Data
		// A zero-length PRELOGIN packet carries no stream data. Read the next
		// packet rather than returning (0, nil), which would make callers spin.
	}
}

// Write wraps p in one or more TDS PRELOGIN packets until the peer switches
// to raw TLS records (see Read) or passthrough is enabled; after that, p is
// written unmodified. It reports p as written only after every byte of every
// corresponding TDS packet has been written.
func (c *TDSTLSHandshakeConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.passthrough.Load() || c.rawSeen.Load() {
		return c.conn.Write(p)
	}

	for offset := 0; offset < len(p); {
		payloadLen := len(p) - offset
		if payloadLen > tdsTLSMaxPayload {
			payloadLen = tdsTLSMaxPayload
		}

		status := StatusNormal
		if offset+payloadLen == len(p) {
			status = StatusEOM
		}

		frame := make([]byte, headerSize+payloadLen)
		frame[0] = PacketPreLogin
		frame[1] = status
		binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
		frame[6] = c.nextPacketID()
		copy(frame[headerSize:], p[offset:offset+payloadLen])
		slog.Debug("tds tls write packet", "length", payloadLen, "status", status, "seq", frame[6])

		if err := writeTDSFull(c.conn, frame); err != nil {
			return offset, err
		}
		offset += payloadLen
	}

	return len(p), nil
}

func (c *TDSTLSHandshakeConn) nextPacketID() byte {
	c.packetID++
	if c.packetID == 0 {
		c.packetID++
	}
	return c.packetID
}

func writeTDSFull(conn net.Conn, p []byte) error {
	for len(p) != 0 {
		n, err := conn.Write(p)
		if n < 0 || n > len(p) {
			return fmt.Errorf("invalid write count %d", n)
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// FinishHandshake switches subsequent reads and writes to raw passthrough.
// Buffered payload from a PRELOGIN packet is still delivered before the first
// raw read so TLS data already consumed from the network is not lost.
func (c *TDSTLSHandshakeConn) FinishHandshake() {
	c.passthrough.Store(true)
}

// SetPassthrough is an alias for FinishHandshake.
func (c *TDSTLSHandshakeConn) SetPassthrough() {
	c.FinishHandshake()
}

// Close closes the underlying connection.
func (c *TDSTLSHandshakeConn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the underlying connection's local address.
func (c *TDSTLSHandshakeConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the underlying connection's remote address.
func (c *TDSTLSHandshakeConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines on the underlying connection.
func (c *TDSTLSHandshakeConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *TDSTLSHandshakeConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *TDSTLSHandshakeConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
