package mssql

import (
	"fmt"
	"io"
	"log/slog"
	"net"
)

func readLogin7FromConn(conn net.Conn) ([]byte, byte, error) {
	peek := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, peek); err != nil {
		return nil, 0, err
	}
	slog.Debug("mssql login7 peek", "bytes", fmt.Sprintf("% x", peek))

	typeConn := &prefixedConn{Conn: conn, prefix: peek}
	data, packetType, err := ReadAllPackets(typeConn)
	if err != nil {
		return nil, 0, err
	}
	slog.Debug("mssql login7 reassembled", "type", fmt.Sprintf("0x%02x", packetType), "bytes", len(data))
	return data, packetType, nil
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
