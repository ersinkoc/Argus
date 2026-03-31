package mssql

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// TDS packet types
const (
	PacketSQLBatch   byte = 0x01 // SQL Batch
	PacketPreTDS7    byte = 0x02 // Pre-TDS7 Login
	PacketRPC        byte = 0x03 // RPC
	PacketReply      byte = 0x04 // Tabular result
	PacketAttention  byte = 0x06 // Attention
	PacketBulkLoad   byte = 0x07 // Bulk Load
	PacketFedAuth    byte = 0x08 // Federated Authentication Token
	PacketTransMgr   byte = 0x0E // Transaction Manager Request
	PacketTDS7Login  byte = 0x10 // TDS7 Login
	PacketSSPI       byte = 0x11 // SSPI
	PacketPreLogin   byte = 0x12 // Pre-Login
)

// TDS packet status flags
const (
	StatusNormal         byte = 0x00
	StatusEOM            byte = 0x01 // End of message
	StatusIgnore         byte = 0x02
	StatusResetConn      byte = 0x08
	StatusResetConnSkip  byte = 0x10
)

// TDS token types
const (
	TokenColMetadata  byte = 0x81
	TokenRow          byte = 0xD1
	TokenNBCRow       byte = 0xD2
	TokenDone         byte = 0xFD
	TokenDoneProc     byte = 0xFE
	TokenDoneInProc   byte = 0xFF
	TokenError        byte = 0xAA
	TokenInfo         byte = 0xAB
	TokenLoginAck     byte = 0xAD
	TokenEnvChange    byte = 0xE3
)

// Packet represents a TDS packet.
type Packet struct {
	Type   byte
	Status byte
	Length uint16
	SPID   uint16
	SeqNo  byte
	Window byte
	Data   []byte
}

const headerSize = 8

// ReadPacket reads a single TDS packet from a connection.
func ReadPacket(conn net.Conn) (*Packet, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading TDS header: %w", err)
	}

	pkt := &Packet{
		Type:   header[0],
		Status: header[1],
		Length: binary.BigEndian.Uint16(header[2:4]),
		SPID:   binary.BigEndian.Uint16(header[4:6]),
		SeqNo:  header[6],
		Window: header[7],
	}

	if pkt.Length < headerSize {
		return nil, fmt.Errorf("invalid TDS packet length: %d", pkt.Length)
	}
	if pkt.Length > 32768 { // TDS max packet size default
		return nil, fmt.Errorf("TDS packet too large: %d", pkt.Length)
	}

	dataLen := int(pkt.Length) - headerSize
	if dataLen > 0 {
		pkt.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(conn, pkt.Data); err != nil {
			return nil, fmt.Errorf("reading TDS data: %w", err)
		}
	}

	return pkt, nil
}

// WritePacket writes a TDS packet to a connection.
func WritePacket(conn net.Conn, pkt *Packet) error {
	totalLen := headerSize + len(pkt.Data)
	buf := make([]byte, totalLen)

	buf[0] = pkt.Type
	buf[1] = pkt.Status
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], pkt.SPID)
	buf[6] = pkt.SeqNo
	buf[7] = pkt.Window

	copy(buf[headerSize:], pkt.Data)

	_, err := conn.Write(buf)
	return err
}

// MaxReassemblySize is the maximum total size for reassembled TDS messages (16MB).
const MaxReassemblySize = 16 * 1024 * 1024

// ReadAllPackets reads TDS packets until EOM (end of message).
func ReadAllPackets(conn net.Conn) ([]byte, byte, error) {
	var data []byte
	var pktType byte

	for {
		pkt, err := ReadPacket(conn)
		if err != nil {
			return nil, 0, err
		}

		if pktType == 0 {
			pktType = pkt.Type
		}

		if len(data)+len(pkt.Data) > MaxReassemblySize {
			return nil, 0, fmt.Errorf("TDS reassembled message exceeds %d bytes", MaxReassemblySize)
		}

		data = append(data, pkt.Data...)

		if pkt.Status&StatusEOM != 0 {
			return data, pktType, nil
		}
	}
}

// patchPreLoginEncryption finds the ENCRYPTION token in a pre-login response
// and sets it to NOT_SUP (0x02) so clients fall back to plaintext.
// TDS pre-login format: repeating [token(1) offset(2) length(2)] terminated by 0xFF,
// followed by data at the specified offsets.
func patchPreLoginEncryption(data []byte) {
	const tokenEncryption = 0x01
	const encryptNotSup = 0x02

	pos := 0
	for pos < len(data) {
		tokenType := data[pos]
		if tokenType == 0xFF {
			break
		}
		if pos+5 > len(data) {
			break
		}
		offset := int(data[pos+1])<<8 | int(data[pos+2])
		length := int(data[pos+3])<<8 | int(data[pos+4])
		if tokenType == tokenEncryption && length >= 1 && offset < len(data) {
			data[offset] = encryptNotSup
			return
		}
		pos += 5
	}
}

// patchPreLoginMARS finds the MARS token (0x04) in a pre-login packet
// and sets it to 0x00 (MARS OFF) to prevent MARS negotiation.
func patchPreLoginMARS(data []byte) {
	const tokenMARS = 0x04
	const marsOff = 0x00

	pos := 0
	for pos < len(data) {
		tokenType := data[pos]
		if tokenType == 0xFF {
			break
		}
		if pos+5 > len(data) {
			break
		}
		offset := int(data[pos+1])<<8 | int(data[pos+2])
		length := int(data[pos+3])<<8 | int(data[pos+4])
		if tokenType == tokenMARS && length >= 1 && offset < len(data) {
			data[offset] = marsOff
			return
		}
		pos += 5
	}
}

// BuildPreLoginResponse creates a minimal pre-login response.
func BuildPreLoginResponse() *Packet {
	// Minimal pre-login response
	var data []byte

	// VERSION token (0x00): offset 6, length 6
	data = append(data, 0x00)                 // token type: VERSION
	data = append(data, 0, 26)                // offset (big-endian uint16)
	data = append(data, 0, 6)                 // length (big-endian uint16)

	// ENCRYPTION token (0x01): offset 32, length 1
	data = append(data, 0x01)                 // token type: ENCRYPTION
	data = append(data, 0, 32)                // offset
	data = append(data, 0, 1)                 // length

	// INSTOPT token (0x02): offset 33, length 1
	data = append(data, 0x02)                 // token type: INSTOPT
	data = append(data, 0, 33)                // offset
	data = append(data, 0, 1)                 // length

	// Terminator
	data = append(data, 0xFF)

	// Padding to match offsets
	for len(data) < 26 {
		data = append(data, 0)
	}

	// VERSION data: 15.0.0.0, subbuild 0
	data = append(data, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00)

	// ENCRYPTION: 0x02 = NOT_SUP
	data = append(data, 0x02)

	// INSTOPT: 0x00
	data = append(data, 0x00)

	return &Packet{
		Type:   PacketReply,
		Status: StatusEOM,
		Data:   data,
	}
}

// BuildErrorToken creates a TDS error token.
func BuildErrorToken(number int32, state, class byte, message, server, proc string, line int32) []byte {
	var token []byte
	token = append(token, TokenError)

	// Build content first to get length
	var content []byte
	numBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(numBuf, uint32(number))
	content = append(content, numBuf...)
	content = append(content, state, class)

	// Message (US_VARCHAR: uint16 length + UTF-16LE)
	msgUTF16 := toUTF16LE(message)
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(message)))
	content = append(content, lenBuf...)
	content = append(content, msgUTF16...)

	// Server name
	srvUTF16 := toUTF16LE(server)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(server)))
	content = append(content, lenBuf...)
	content = append(content, srvUTF16...)

	// Proc name
	procUTF16 := toUTF16LE(proc)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(proc)))
	content = append(content, lenBuf...)
	content = append(content, procUTF16...)

	// Line number
	lineBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lineBuf, uint32(line))
	content = append(content, lineBuf...)

	// Token length
	tokenLen := make([]byte, 2)
	binary.LittleEndian.PutUint16(tokenLen, uint16(len(content)))
	token = append(token, tokenLen...)
	token = append(token, content...)

	return token
}

func toUTF16LE(s string) []byte {
	result := make([]byte, len(s)*2)
	for i, r := range s {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	return result
}
