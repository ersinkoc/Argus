package mssql

import (
	"context"
	"fmt"
	"net"
	"unicode/utf16"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/session"
)

// Handler implements protocol.Handler for MSSQL TDS.
type Handler struct{}

// New creates a new MSSQL protocol handler.
func New() *Handler {
	return &Handler{}
}

func (h *Handler) Name() string {
	return "mssql"
}

// DetectProtocol checks for TDS pre-login packet (type 0x12).
func (h *Handler) DetectProtocol(peek []byte) bool {
	if len(peek) < 1 {
		return false
	}
	return peek[0] == PacketPreLogin
}

// Handshake performs TDS authentication passthrough.
func (h *Handler) Handshake(ctx context.Context, client, backend net.Conn) (*session.Info, error) {
	// Step 1: Read pre-login from client
	preLoginData, pktType, err := ReadAllPackets(client)
	if err != nil {
		return nil, fmt.Errorf("reading client pre-login: %w", err)
	}

	if pktType != PacketPreLogin {
		return nil, fmt.Errorf("expected pre-login packet, got 0x%02x", pktType)
	}

	// Forward pre-login to backend
	pkt := &Packet{
		Type:   PacketPreLogin,
		Status: StatusEOM,
		Data:   preLoginData,
	}
	if err := WritePacket(backend, pkt); err != nil {
		return nil, fmt.Errorf("forwarding pre-login: %w", err)
	}

	// Read backend pre-login response
	respData, _, err := ReadAllPackets(backend)
	if err != nil {
		return nil, fmt.Errorf("reading backend pre-login response: %w", err)
	}

	respPkt := &Packet{
		Type:   PacketReply,
		Status: StatusEOM,
		Data:   respData,
	}
	if err := WritePacket(client, respPkt); err != nil {
		return nil, fmt.Errorf("forwarding pre-login response: %w", err)
	}

	// Step 2: Read Login7 from client
	loginData, loginType, err := ReadAllPackets(client)
	if err != nil {
		return nil, fmt.Errorf("reading client login: %w", err)
	}

	if loginType != PacketTDS7Login {
		return nil, fmt.Errorf("expected TDS7 login, got 0x%02x", loginType)
	}

	// Extract username from Login7 packet
	username := extractLogin7Username(loginData)

	// Forward to backend
	loginPkt := &Packet{
		Type:   PacketTDS7Login,
		Status: StatusEOM,
		Data:   loginData,
	}
	if err := WritePacket(backend, loginPkt); err != nil {
		return nil, fmt.Errorf("forwarding login: %w", err)
	}

	// Read login response
	loginRespData, _, err := ReadAllPackets(backend)
	if err != nil {
		return nil, fmt.Errorf("reading login response: %w", err)
	}

	loginRespPkt := &Packet{
		Type:   PacketReply,
		Status: StatusEOM,
		Data:   loginRespData,
	}
	if err := WritePacket(client, loginRespPkt); err != nil {
		return nil, fmt.Errorf("forwarding login response: %w", err)
	}

	// Check for LoginAck token in response
	if !containsToken(loginRespData, TokenLoginAck) {
		return nil, fmt.Errorf("login failed: no LoginAck token")
	}

	info := &session.Info{
		Username:   username,
		AuthMethod: "tds7",
	}

	return info, nil
}

// ReadCommand reads a TDS SQL Batch from the client.
func (h *Handler) ReadCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
	data, pktType, err := ReadAllPackets(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading client command: %w", err)
	}

	rawPkt := &Packet{Type: pktType, Status: StatusEOM, Data: data}
	rawBytes := encodePacketBytes(rawPkt)

	switch pktType {
	case PacketSQLBatch:
		// SQL Batch: skip ALL_HEADERS, then UTF-16LE SQL text
		sql := extractSQLBatch(data)
		cmd := inspection.Classify(sql)
		return cmd, rawBytes, nil

	case PacketAttention:
		// Cancel request
		cmd := &inspection.Command{
			Type:      inspection.CommandADMIN,
			Raw:       "[ATTENTION/CANCEL]",
			RiskLevel: inspection.RiskNone,
		}
		return cmd, rawBytes, nil

	default:
		cmd := &inspection.Command{
			Type:      inspection.CommandUNKNOWN,
			Raw:       fmt.Sprintf("[tds_type=0x%02x]", pktType),
			RiskLevel: inspection.RiskNone,
		}
		return cmd, rawBytes, nil
	}
}

// RebuildQuery rebuilds a TDS SQL Batch with a new SQL string.
func (h *Handler) RebuildQuery(rawMsg []byte, newSQL string) []byte {
	utf16 := toUTF16LE(newSQL)
	// ALL_HEADERS (4-byte total length = 4, meaning no headers)
	allHeaders := []byte{4, 0, 0, 0}
	data := append(allHeaders, utf16...)
	return encodePacketBytes(&Packet{
		Type:   PacketSQLBatch,
		Status: StatusEOM,
		Data:   data,
	})
}

func (h *Handler) ForwardCommand(ctx context.Context, rawMsg []byte, backend net.Conn) error {
	_, err := backend.Write(rawMsg)
	return err
}

// ReadAndForwardResult reads TDS result tokens and forwards to client.
// Masking is not yet implemented for TDS (complex token stream parsing required).
func (h *Handler) ReadAndForwardResult(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
	stats := &protocol.ResultStats{}

	// Read all reply packets and forward
	for {
		pkt, err := ReadPacket(backend)
		if err != nil {
			return stats, fmt.Errorf("reading TDS result: %w", err)
		}

		// Count rows (approximate: look for Row tokens)
		stats.RowCount += int64(countTokens(pkt.Data, TokenRow))
		stats.RowCount += int64(countTokens(pkt.Data, TokenNBCRow))
		stats.ByteCount += int64(len(pkt.Data))

		if err := WritePacket(client, pkt); err != nil {
			return stats, fmt.Errorf("forwarding TDS result: %w", err)
		}

		// EOM = end of result
		if pkt.Status&StatusEOM != 0 {
			return stats, nil
		}
	}
}

func (h *Handler) WriteError(ctx context.Context, client net.Conn, code string, message string) error {
	errorToken := BuildErrorToken(50000, 1, 16, message, "Argus", "", 0)

	// Done token
	doneToken := []byte{TokenDone, 0, 0, 0, 0, 0, 0, 0, 0}

	var data []byte
	data = append(data, errorToken...)
	data = append(data, doneToken...)

	pkt := &Packet{
		Type:   PacketReply,
		Status: StatusEOM,
		Data:   data,
	}
	return WritePacket(client, pkt)
}

func (h *Handler) Close() error {
	return nil
}

// --- helpers ---

func extractLogin7Username(data []byte) string {
	// Login7 packet: fixed header (94 bytes), then variable-length fields
	// Username is at offset ibUserName (uint16 offset at byte 48, uint16 length at byte 50)
	if len(data) < 94 {
		return ""
	}
	offset := int(data[48]) | int(data[49])<<8
	length := int(data[50]) | int(data[51])<<8

	if offset+length*2 > len(data) {
		return ""
	}

	return decodeUTF16LE(data[offset : offset+length*2])
}

func extractSQLBatch(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	// Skip ALL_HEADERS section
	totalLen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16 | int(data[3])<<24
	if totalLen > 0 && totalLen < len(data) {
		data = data[totalLen:]
	}
	return decodeUTF16LE(data)
}

func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}
	return string(utf16.Decode(u16))
}

func containsToken(data []byte, token byte) bool {
	for _, b := range data {
		if b == token {
			return true
		}
	}
	return false
}

func countTokens(data []byte, token byte) int {
	count := 0
	for _, b := range data {
		if b == token {
			count++
		}
	}
	return count
}

func encodePacketBytes(pkt *Packet) []byte {
	totalLen := headerSize + len(pkt.Data)
	buf := make([]byte, totalLen)
	buf[0] = pkt.Type
	buf[1] = pkt.Status
	buf[2] = byte(totalLen >> 8)
	buf[3] = byte(totalLen)
	copy(buf[headerSize:], pkt.Data)
	return buf
}
