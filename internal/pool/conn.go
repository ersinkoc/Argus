package pool

import (
	"net"
	"time"
)

// Conn wraps a net.Conn with pool metadata.
type Conn struct {
	conn      net.Conn
	createdAt time.Time
}

// NetConn returns the underlying net.Conn.
func (c *Conn) NetConn() net.Conn {
	return c.conn
}

// CreatedAt returns when the connection was established.
func (c *Conn) CreatedAt() time.Time {
	return c.createdAt
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Conn) isExpired(maxLifetime time.Duration) bool {
	if maxLifetime <= 0 {
		return false
	}
	return time.Since(c.createdAt) > maxLifetime
}

// isConnAlive checks if a TCP connection is still open by attempting
// a non-blocking read. If the remote end has closed the connection,
// Read will return immediately with EOF or an error.
func isConnAlive(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{}) // reset deadline

	if err == nil {
		// Got data unexpectedly — connection is alive but has stale data
		return false
	}

	// Timeout error means connection is alive (nothing to read, but socket is open)
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	// Any other error (EOF, connection reset) means dead
	return false
}
