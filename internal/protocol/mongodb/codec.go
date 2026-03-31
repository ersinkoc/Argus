package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// MongoDB wire protocol opcodes
const (
	OpReply       int32 = 1    // Reply to a client request (deprecated but still used)
	OpUpdate      int32 = 2001 // Update document (deprecated)
	OpInsert      int32 = 2002 // Insert document (deprecated)
	OpQuery       int32 = 2004 // Query (deprecated but widely used)
	OpGetMore     int32 = 2005 // Get more data from cursor
	OpDelete      int32 = 2006 // Delete document (deprecated)
	OpKillCursors int32 = 2007 // Kill cursors
	OpCompressed  int32 = 2012 // Compressed message
	OpMsg         int32 = 2013 // Modern extensible message (MongoDB 3.6+)
)

// MsgHeader is the standard message header (16 bytes).
type MsgHeader struct {
	MessageLength int32 // total message size (including header)
	RequestID     int32 // client or server generated identifier
	ResponseTo    int32 // requestID from the original request
	OpCode        int32 // operation code
}

// Message represents a MongoDB wire protocol message.
type Message struct {
	Header  MsgHeader
	Payload []byte
}

// ReadMessage reads a single MongoDB message from a connection.
func ReadMessage(conn net.Conn) (*Message, error) {
	// Read header (16 bytes)
	header := make([]byte, 16)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading MongoDB header: %w", err)
	}

	msg := &Message{}
	msg.Header.MessageLength = int32(binary.LittleEndian.Uint32(header[0:4]))
	msg.Header.RequestID = int32(binary.LittleEndian.Uint32(header[4:8]))
	msg.Header.ResponseTo = int32(binary.LittleEndian.Uint32(header[8:12]))
	msg.Header.OpCode = int32(binary.LittleEndian.Uint32(header[12:16]))

	if msg.Header.MessageLength < 16 {
		return nil, fmt.Errorf("invalid MongoDB message length: %d", msg.Header.MessageLength)
	}
	if msg.Header.MessageLength > 48*1024*1024 { // 48MB max
		return nil, fmt.Errorf("MongoDB message too large: %d", msg.Header.MessageLength)
	}

	// Read payload
	payloadLen := int(msg.Header.MessageLength) - 16
	if payloadLen > 0 {
		msg.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, msg.Payload); err != nil {
			return nil, fmt.Errorf("reading MongoDB payload: %w", err)
		}
	}

	return msg, nil
}

// WriteMessage writes a MongoDB message to a connection.
func WriteMessage(conn net.Conn, msg *Message) error {
	totalLen := 16 + len(msg.Payload)
	buf := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(msg.Header.RequestID))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(msg.Header.ResponseTo))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(msg.Header.OpCode))

	copy(buf[16:], msg.Payload)

	_, err := conn.Write(buf)
	return err
}

// OpMsgSection represents a section in an OP_MSG message.
type OpMsgSection struct {
	Kind byte   // 0 = body, 1 = document sequence
	Data []byte // BSON document(s)
}

// ParseOpMsg parses an OP_MSG payload into sections.
func ParseOpMsg(payload []byte) (flagBits uint32, sections []OpMsgSection, err error) {
	if len(payload) < 5 {
		return 0, nil, fmt.Errorf("OP_MSG too short")
	}

	flagBits = binary.LittleEndian.Uint32(payload[0:4])
	offset := 4

	for offset < len(payload) {
		if offset >= len(payload) {
			break
		}

		kind := payload[offset]
		offset++

		switch kind {
		case 0: // Body (single BSON document)
			if offset+4 > len(payload) {
				return flagBits, sections, fmt.Errorf("OP_MSG body truncated")
			}
			docLen := int(binary.LittleEndian.Uint32(payload[offset:]))
			if docLen < 5 { // minimum BSON document is 5 bytes (length + null terminator)
				return flagBits, sections, fmt.Errorf("OP_MSG body doc too small: %d", docLen)
			}
			if offset+docLen > len(payload) {
				return flagBits, sections, fmt.Errorf("OP_MSG body doc truncated")
			}
			sections = append(sections, OpMsgSection{Kind: 0, Data: payload[offset : offset+docLen]})
			offset += docLen

		case 1: // Document sequence
			if offset+4 > len(payload) {
				return flagBits, sections, fmt.Errorf("OP_MSG sequence truncated")
			}
			seqLen := int(binary.LittleEndian.Uint32(payload[offset:]))
			if seqLen < 4 { // minimum sequence size is 4 bytes (the length field itself)
				return flagBits, sections, fmt.Errorf("OP_MSG sequence too small: %d", seqLen)
			}
			if offset+seqLen > len(payload) {
				return flagBits, sections, fmt.Errorf("OP_MSG sequence data truncated")
			}
			sections = append(sections, OpMsgSection{Kind: 1, Data: payload[offset : offset+seqLen]})
			offset += seqLen

		default:
			return flagBits, sections, fmt.Errorf("unknown OP_MSG section kind: %d", kind)
		}
	}

	return flagBits, sections, nil
}

// ExtractCommandName extracts the command name from a BSON document.
// In MongoDB, the first key of the command document is the command name.
func ExtractCommandName(bsonDoc []byte) string {
	if len(bsonDoc) < 5 {
		return ""
	}
	// Skip document length (4 bytes)
	offset := 4

	if offset >= len(bsonDoc) || bsonDoc[offset] == 0 {
		return ""
	}

	// Element type (1 byte)
	offset++

	// Key name (null-terminated string)
	keyEnd := offset
	for keyEnd < len(bsonDoc) && bsonDoc[keyEnd] != 0 {
		keyEnd++
	}

	return string(bsonDoc[offset:keyEnd])
}

// OpCodeName returns a human-readable name for an opcode.
func OpCodeName(code int32) string {
	switch code {
	case OpReply:
		return "OP_REPLY"
	case OpUpdate:
		return "OP_UPDATE"
	case OpInsert:
		return "OP_INSERT"
	case OpQuery:
		return "OP_QUERY"
	case OpGetMore:
		return "OP_GET_MORE"
	case OpDelete:
		return "OP_DELETE"
	case OpKillCursors:
		return "OP_KILL_CURSORS"
	case OpCompressed:
		return "OP_COMPRESSED"
	case OpMsg:
		return "OP_MSG"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", code)
	}
}
