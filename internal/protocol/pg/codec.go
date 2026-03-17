package pg

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// PostgreSQL message type bytes
const (
	// Frontend (client → server) message types
	MsgQuery       byte = 'Q'
	MsgTerminate   byte = 'X'
	MsgPassword    byte = 'p'

	// Extended Query frontend messages
	MsgParse       byte = 'P'
	MsgBind        byte = 'B'
	MsgDescribe    byte = 'D' // overloaded with DataRow — direction matters
	MsgExecute     byte = 'E' // overloaded with ErrorResponse — direction matters
	MsgSync        byte = 'S' // overloaded with ParameterStatus — direction matters
	MsgClose       byte = 'C' // overloaded with CommandComplete — direction matters
	MsgFlush       byte = 'H'

	// Backend (server → client) message types
	MsgAuth            byte = 'R'
	MsgParameterStatus byte = 'S'
	MsgBackendKeyData  byte = 'K'
	MsgReadyForQuery   byte = 'Z'
	MsgRowDescription  byte = 'T'
	MsgDataRow         byte = 'D'
	MsgCommandComplete byte = 'C'
	MsgErrorResponse   byte = 'E'
	MsgNoticeResponse  byte = 'N'
	MsgEmptyQuery      byte = 'I'
	MsgNoData          byte = 'n'
	MsgParseComplete   byte = '1'
	MsgBindComplete    byte = '2'
	MsgCloseComplete   byte = '3'
	MsgParameterDesc   byte = 't'
	MsgPortalSuspended byte = 's'

	// SSL
	SSLRequestCode = 80877103
)

// Auth types
const (
	AuthOK              int32 = 0
	AuthCleartextPwd    int32 = 3
	AuthMD5Pwd          int32 = 5
	AuthSASL            int32 = 10
	AuthSASLContinue    int32 = 11
	AuthSASLFinal       int32 = 12
)

// Message represents a PostgreSQL protocol message.
type Message struct {
	Type    byte
	Payload []byte
}

// ReadMessage reads a single message from a connection.
// For the startup phase (no message type byte), use ReadStartupMessage.
func ReadMessage(conn net.Conn) (*Message, error) {
	// Read message type (1 byte)
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, typeBuf); err != nil {
		return nil, fmt.Errorf("reading message type: %w", err)
	}

	// Read length (4 bytes, includes self)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("reading message length: %w", err)
	}
	length := int(binary.BigEndian.Uint32(lenBuf)) - 4

	if length < 0 {
		return nil, fmt.Errorf("invalid message length: %d", length+4)
	}
	if length > 1<<24 { // 16MB sanity check
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read payload
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, fmt.Errorf("reading message payload: %w", err)
		}
	}

	return &Message{Type: typeBuf[0], Payload: payload}, nil
}

// WriteMessage writes a message to a connection.
func WriteMessage(conn net.Conn, msg *Message) error {
	length := len(msg.Payload) + 4
	buf := make([]byte, 1+4+len(msg.Payload))
	buf[0] = msg.Type
	binary.BigEndian.PutUint32(buf[1:5], uint32(length))
	copy(buf[5:], msg.Payload)
	_, err := conn.Write(buf)
	return err
}

// WriteRawBytes writes raw bytes to a connection.
func WriteRawBytes(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

// ReadStartupMessage reads the initial startup/SSL message from a client.
// Startup messages have no type byte: just length (4 bytes) + payload.
func ReadStartupMessage(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("reading startup length: %w", err)
	}
	length := int(binary.BigEndian.Uint32(lenBuf))

	if length < 4 || length > 10000 {
		return nil, fmt.Errorf("invalid startup message length: %d", length)
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("reading startup payload: %w", err)
	}

	// Return full message including length prefix
	full := make([]byte, length)
	copy(full[:4], lenBuf)
	copy(full[4:], payload)
	return full, nil
}

// StartupMessage parses a startup message payload.
type StartupMessage struct {
	ProtocolVersion int32
	Parameters      map[string]string
	IsSSLRequest    bool
}

// ParseStartupMessage parses a startup message.
func ParseStartupMessage(data []byte) (*StartupMessage, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("startup message too short")
	}

	// Skip length (first 4 bytes)
	version := int32(binary.BigEndian.Uint32(data[4:8]))

	msg := &StartupMessage{
		ProtocolVersion: version,
		Parameters:      make(map[string]string),
	}

	// Check for SSLRequest
	if version == SSLRequestCode {
		msg.IsSSLRequest = true
		return msg, nil
	}

	// Parse parameters (null-terminated key-value pairs)
	payload := data[8:]
	for len(payload) > 1 { // at least 1 byte for the trailing null
		// Read key
		keyEnd := 0
		for keyEnd < len(payload) && payload[keyEnd] != 0 {
			keyEnd++
		}
		if keyEnd >= len(payload) {
			break
		}
		key := string(payload[:keyEnd])
		payload = payload[keyEnd+1:]

		if key == "" {
			break
		}

		// Read value
		valEnd := 0
		for valEnd < len(payload) && payload[valEnd] != 0 {
			valEnd++
		}
		if valEnd > len(payload) {
			break
		}
		value := string(payload[:valEnd])
		if valEnd < len(payload) {
			payload = payload[valEnd+1:]
		} else {
			payload = nil
		}

		msg.Parameters[key] = value
	}

	return msg, nil
}

// BuildStartupMessage constructs a startup message.
func BuildStartupMessage(params map[string]string) []byte {
	var buf []byte
	// Protocol version 3.0
	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, 0x00030000)
	buf = append(buf, version...)

	for k, v := range params {
		buf = append(buf, []byte(k)...)
		buf = append(buf, 0)
		buf = append(buf, []byte(v)...)
		buf = append(buf, 0)
	}
	buf = append(buf, 0) // trailing null

	// Prepend length
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(buf)+4))
	return append(length, buf...)
}

// BuildErrorResponse constructs an ErrorResponse message.
func BuildErrorResponse(severity, code, message string) *Message {
	var payload []byte

	// Severity
	payload = append(payload, 'S')
	payload = append(payload, []byte(severity)...)
	payload = append(payload, 0)

	// Severity (V field, non-localized)
	payload = append(payload, 'V')
	payload = append(payload, []byte(severity)...)
	payload = append(payload, 0)

	// Code
	payload = append(payload, 'C')
	payload = append(payload, []byte(code)...)
	payload = append(payload, 0)

	// Message
	payload = append(payload, 'M')
	payload = append(payload, []byte(message)...)
	payload = append(payload, 0)

	// Terminator
	payload = append(payload, 0)

	return &Message{Type: MsgErrorResponse, Payload: payload}
}

// BuildReadyForQuery constructs a ReadyForQuery message.
func BuildReadyForQuery(status byte) *Message {
	return &Message{Type: MsgReadyForQuery, Payload: []byte{status}}
}

// BuildCommandComplete constructs a CommandComplete message.
func BuildCommandComplete(tag string) *Message {
	payload := append([]byte(tag), 0)
	return &Message{Type: MsgCommandComplete, Payload: payload}
}

// ParseErrorResponse extracts fields from an ErrorResponse message.
func ParseErrorResponse(payload []byte) map[byte]string {
	fields := make(map[byte]string)
	i := 0
	for i < len(payload) {
		fieldType := payload[i]
		i++
		if fieldType == 0 {
			break
		}
		end := i
		for end < len(payload) && payload[end] != 0 {
			end++
		}
		fields[fieldType] = string(payload[i:end])
		i = end + 1
	}
	return fields
}

// ParseRowDescription parses a RowDescription message to extract column info.
type ColumnDesc struct {
	Name         string
	TableOID     int32
	ColumnIndex  int16
	TypeOID      int32
	TypeSize     int16
	TypeModifier int32
	Format       int16
}

func ParseRowDescription(payload []byte) ([]ColumnDesc, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("RowDescription too short")
	}
	numCols := int(binary.BigEndian.Uint16(payload[:2]))
	offset := 2
	cols := make([]ColumnDesc, numCols)

	for i := 0; i < numCols; i++ {
		// Column name (null-terminated)
		nameEnd := offset
		for nameEnd < len(payload) && payload[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd >= len(payload) {
			return nil, fmt.Errorf("invalid RowDescription at column %d", i)
		}
		cols[i].Name = string(payload[offset:nameEnd])
		offset = nameEnd + 1

		if offset+18 > len(payload) {
			return nil, fmt.Errorf("RowDescription truncated at column %d", i)
		}

		cols[i].TableOID = int32(binary.BigEndian.Uint32(payload[offset:]))
		cols[i].ColumnIndex = int16(binary.BigEndian.Uint16(payload[offset+4:]))
		cols[i].TypeOID = int32(binary.BigEndian.Uint32(payload[offset+6:]))
		cols[i].TypeSize = int16(binary.BigEndian.Uint16(payload[offset+10:]))
		cols[i].TypeModifier = int32(binary.BigEndian.Uint32(payload[offset+12:]))
		cols[i].Format = int16(binary.BigEndian.Uint16(payload[offset+16:]))
		offset += 18
	}

	return cols, nil
}

// ParseDataRow parses a DataRow message.
func ParseDataRow(payload []byte) ([][]byte, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("DataRow too short")
	}
	numFields := int(binary.BigEndian.Uint16(payload[:2]))
	offset := 2
	fields := make([][]byte, numFields)

	for i := 0; i < numFields; i++ {
		if offset+4 > len(payload) {
			return nil, fmt.Errorf("DataRow truncated at field %d", i)
		}
		length := int32(binary.BigEndian.Uint32(payload[offset:]))
		offset += 4

		if length == -1 {
			fields[i] = nil // NULL
		} else {
			if offset+int(length) > len(payload) {
				return nil, fmt.Errorf("DataRow field %d exceeds payload", i)
			}
			fields[i] = payload[offset : offset+int(length)]
			offset += int(length)
		}
	}

	return fields, nil
}

// BuildDataRow constructs a DataRow message from field values.
func BuildDataRow(fields [][]byte) *Message {
	var payload []byte
	numFields := make([]byte, 2)
	binary.BigEndian.PutUint16(numFields, uint16(len(fields)))
	payload = append(payload, numFields...)

	for _, field := range fields {
		if field == nil {
			// NULL
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFFF) // -1 in int32
			payload = append(payload, lenBuf...)
		} else {
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(field)))
			payload = append(payload, lenBuf...)
			payload = append(payload, field...)
		}
	}

	return &Message{Type: MsgDataRow, Payload: payload}
}

// EncodeMessage encodes a message to bytes (type + length + payload).
func EncodeMessage(msg *Message) []byte {
	length := len(msg.Payload) + 4
	buf := make([]byte, 1+4+len(msg.Payload))
	buf[0] = msg.Type
	binary.BigEndian.PutUint32(buf[1:5], uint32(length))
	copy(buf[5:], msg.Payload)
	return buf
}
