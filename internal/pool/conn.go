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
