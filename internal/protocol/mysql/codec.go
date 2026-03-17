package mysql

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// MySQL packet header: 3 bytes length + 1 byte sequence ID
const headerSize = 4

// Command bytes
const (
	ComQuit    byte = 0x01
	ComQuery   byte = 0x03
	ComPing    byte = 0x0e
	ComInitDB  byte = 0x02
)

// Column types
const (
	FieldTypeString byte = 0xfe
)

// Status flags
const (
	StatusAutocommit     uint16 = 0x0002
	StatusMoreResultSets uint16 = 0x0008
)

// Packet represents a MySQL protocol packet.
type Packet struct {
	SequenceID byte
	Payload    []byte
}

// ReadPacket reads a single MySQL packet from a connection.
func ReadPacket(conn net.Conn) (*Packet, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading packet header: %w", err)
	}

	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	seqID := header[3]

	if length > 16*1024*1024 { // 16MB max packet
		return nil, fmt.Errorf("packet too large: %d bytes", length)
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, fmt.Errorf("reading packet payload: %w", err)
		}
	}

	return &Packet{SequenceID: seqID, Payload: payload}, nil
}

// WritePacket writes a MySQL packet to a connection.
func WritePacket(conn net.Conn, pkt *Packet) error {
	length := len(pkt.Payload)
	header := make([]byte, headerSize)
	header[0] = byte(length)
	header[1] = byte(length >> 8)
	header[2] = byte(length >> 16)
	header[3] = pkt.SequenceID

	buf := make([]byte, headerSize+length)
	copy(buf, header)
	copy(buf[headerSize:], pkt.Payload)

	_, err := conn.Write(buf)
	return err
}

// EncodePacket encodes a packet to bytes.
func EncodePacket(pkt *Packet) []byte {
	length := len(pkt.Payload)
	buf := make([]byte, headerSize+length)
	buf[0] = byte(length)
	buf[1] = byte(length >> 8)
	buf[2] = byte(length >> 16)
	buf[3] = pkt.SequenceID
	copy(buf[headerSize:], pkt.Payload)
	return buf
}

// HandshakeV10 represents the server's initial greeting packet.
type HandshakeV10 struct {
	ProtocolVersion byte
	ServerVersion   string
	ConnectionID    uint32
	AuthPluginData  []byte
	CapabilityFlags uint32
	CharacterSet    byte
	StatusFlags     uint16
	AuthPluginName  string
}

// BuildHandshakeV10 creates a minimal server greeting.
func BuildHandshakeV10(connID uint32, serverVersion string) *Packet {
	var payload []byte

	// Protocol version
	payload = append(payload, 10)

	// Server version (null-terminated)
	payload = append(payload, []byte(serverVersion)...)
	payload = append(payload, 0)

	// Connection ID
	connIDBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(connIDBuf, connID)
	payload = append(payload, connIDBuf...)

	// Auth-plugin-data-part-1 (8 bytes)
	payload = append(payload, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48)

	// Filler
	payload = append(payload, 0)

	// Capability flags (lower 2 bytes)
	capLower := make([]byte, 2)
	binary.LittleEndian.PutUint16(capLower, 0xFFFF)
	payload = append(payload, capLower...)

	// Character set (utf8mb4 = 45)
	payload = append(payload, 45)

	// Status flags
	status := make([]byte, 2)
	binary.LittleEndian.PutUint16(status, StatusAutocommit)
	payload = append(payload, status...)

	// Capability flags (upper 2 bytes)
	capUpper := make([]byte, 2)
	binary.LittleEndian.PutUint16(capUpper, 0x00FF)
	payload = append(payload, capUpper...)

	// Length of auth-plugin-data (21)
	payload = append(payload, 21)

	// Reserved (10 bytes of zeros)
	payload = append(payload, make([]byte, 10)...)

	// Auth-plugin-data-part-2 (13 bytes, 12 + null terminator)
	payload = append(payload, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54)
	payload = append(payload, 0)

	// Auth plugin name
	payload = append(payload, []byte("mysql_native_password")...)
	payload = append(payload, 0)

	return &Packet{SequenceID: 0, Payload: payload}
}

// ParseHandshakeResponse parses the client's response to the handshake.
type HandshakeResponse struct {
	CapabilityFlags uint32
	MaxPacketSize   uint32
	CharacterSet    byte
	Username        string
	Database        string
	AuthResponse    []byte
	AuthPluginName  string
}

// ParseHandshakeResponse41 parses a HandshakeResponse41 packet.
func ParseHandshakeResponse41(payload []byte) (*HandshakeResponse, error) {
	if len(payload) < 32 {
		return nil, fmt.Errorf("handshake response too short")
	}

	resp := &HandshakeResponse{}

	// Capability flags (4 bytes)
	resp.CapabilityFlags = binary.LittleEndian.Uint32(payload[0:4])
	resp.MaxPacketSize = binary.LittleEndian.Uint32(payload[4:8])
	resp.CharacterSet = payload[8]

	// Skip 23 bytes reserved
	i := 32

	// Username (null-terminated)
	nameEnd := i
	for nameEnd < len(payload) && payload[nameEnd] != 0 {
		nameEnd++
	}
	resp.Username = string(payload[i:nameEnd])
	i = nameEnd + 1

	// Auth response
	if i < len(payload) {
		// Length-encoded auth response
		authLen := int(payload[i])
		i++
		if i+authLen <= len(payload) {
			resp.AuthResponse = payload[i : i+authLen]
			i += authLen
		}
	}

	// Database (if CLIENT_CONNECT_WITH_DB flag is set)
	if resp.CapabilityFlags&0x0008 != 0 && i < len(payload) {
		dbEnd := i
		for dbEnd < len(payload) && payload[dbEnd] != 0 {
			dbEnd++
		}
		resp.Database = string(payload[i:dbEnd])
	}

	return resp, nil
}

// BuildOKPacket creates an OK response packet.
func BuildOKPacket(seqID byte, affectedRows, lastInsertID uint64) *Packet {
	var payload []byte
	payload = append(payload, 0x00) // OK marker
	payload = append(payload, encodeLenEnc(affectedRows)...)
	payload = append(payload, encodeLenEnc(lastInsertID)...)
	// Status flags
	payload = append(payload, byte(StatusAutocommit), byte(StatusAutocommit>>8))
	// Warnings
	payload = append(payload, 0, 0)
	return &Packet{SequenceID: seqID, Payload: payload}
}

// BuildErrPacket creates an error response packet.
func BuildErrPacket(seqID byte, code uint16, message string) *Packet {
	var payload []byte
	payload = append(payload, 0xFF) // ERR marker
	codeBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(codeBuf, code)
	payload = append(payload, codeBuf...)
	payload = append(payload, '#')
	payload = append(payload, []byte("HY000")...) // SQL state
	payload = append(payload, []byte(message)...)
	return &Packet{SequenceID: seqID, Payload: payload}
}

// BuildEOFPacket creates an EOF packet.
func BuildEOFPacket(seqID byte) *Packet {
	var payload []byte
	payload = append(payload, 0xFE) // EOF marker
	payload = append(payload, 0, 0) // warnings
	payload = append(payload, byte(StatusAutocommit), byte(StatusAutocommit>>8)) // status
	return &Packet{SequenceID: seqID, Payload: payload}
}

func encodeLenEnc(n uint64) []byte {
	if n < 251 {
		return []byte{byte(n)}
	}
	if n < 1<<16 {
		b := make([]byte, 3)
		b[0] = 0xfc
		binary.LittleEndian.PutUint16(b[1:], uint16(n))
		return b
	}
	if n < 1<<24 {
		b := make([]byte, 4)
		b[0] = 0xfd
		b[1] = byte(n)
		b[2] = byte(n >> 8)
		b[3] = byte(n >> 16)
		return b
	}
	b := make([]byte, 9)
	b[0] = 0xfe
	binary.LittleEndian.PutUint64(b[1:], n)
	return b
}
