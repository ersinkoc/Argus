package mongodb

import (
	"context"
	"fmt"
	"net"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/session"
)

// Handler implements protocol.Handler for MongoDB.
type Handler struct{}

// New creates a new MongoDB protocol handler.
func New() *Handler {
	return &Handler{}
}

func (h *Handler) Name() string { return "mongodb" }

// DetectProtocol checks for MongoDB wire protocol.
// MongoDB messages start with a 4-byte little-endian length.
// Hard to distinguish from other protocols by first bytes alone,
// so we rely on port-based configuration.
func (h *Handler) DetectProtocol(peek []byte) bool {
	return false // port-based only
}

// Handshake performs MongoDB authentication passthrough.
// MongoDB uses a challenge-response auth within OP_MSG commands,
// not a separate handshake phase. The first message from client
// is typically an "isMaster" or "hello" command.
func (h *Handler) Handshake(ctx context.Context, client, backend net.Conn) (*session.Info, error) {
	// MongoDB is request-response — client sends first command
	// Read first message from client (typically isMaster/hello)
	msg, err := ReadMessage(client)
	if err != nil {
		return nil, fmt.Errorf("reading MongoDB client hello: %w", err)
	}

	// Forward to backend
	if err := WriteMessage(backend, msg); err != nil {
		return nil, fmt.Errorf("forwarding MongoDB hello: %w", err)
	}

	// Read backend response
	resp, err := ReadMessage(backend)
	if err != nil {
		return nil, fmt.Errorf("reading MongoDB hello response: %w", err)
	}

	// Forward to client
	if err := WriteMessage(client, resp); err != nil {
		return nil, fmt.Errorf("forwarding MongoDB hello response: %w", err)
	}

	// Extract basic info (command name from first message)
	cmdName := ""
	if msg.Header.OpCode == OpMsg && len(msg.Payload) > 5 {
		_, sections, err := ParseOpMsg(msg.Payload)
		if err == nil && len(sections) > 0 {
			cmdName = ExtractCommandName(sections[0].Data)
		}
	}

	info := &session.Info{
		Username:   "mongodb_user", // actual auth happens in SASL commands
		Database:   "admin",
		AuthMethod: "mongodb",
		Parameters: map[string]string{"hello_cmd": cmdName},
	}

	return info, nil
}

// ReadCommand reads a MongoDB command from the client.
func (h *Handler) ReadCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
	msg, err := ReadMessage(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading MongoDB command: %w", err)
	}

	cmd := &inspection.Command{
		Type:       inspection.CommandUNKNOWN,
		Raw:        fmt.Sprintf("[mongodb %s]", OpCodeName(msg.Header.OpCode)),
		RiskLevel:  inspection.RiskNone,
		Confidence: 0.5,
	}

	// Extract command name from OP_MSG
	if msg.Header.OpCode == OpMsg && len(msg.Payload) > 5 {
		_, sections, err := ParseOpMsg(msg.Payload)
		if err == nil && len(sections) > 0 {
			cmdName := ExtractCommandName(sections[0].Data)
			cmd.Raw = cmdName
			cmd.Type = classifyMongoCommand(cmdName)
		}
	}

	// Encode full message for forwarding
	totalLen := 16 + len(msg.Payload)
	raw := make([]byte, totalLen)
	copy(raw, encodeHeader(msg))
	copy(raw[16:], msg.Payload)

	return cmd, raw, nil
}

func (h *Handler) ForwardCommand(ctx context.Context, rawMsg []byte, backend net.Conn) error {
	_, err := backend.Write(rawMsg)
	return err
}

func (h *Handler) ReadAndForwardResult(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
	stats := &protocol.ResultStats{}

	msg, err := ReadMessage(backend)
	if err != nil {
		return stats, fmt.Errorf("reading MongoDB result: %w", err)
	}

	stats.ByteCount = int64(msg.Header.MessageLength)

	if err := WriteMessage(client, msg); err != nil {
		return stats, fmt.Errorf("forwarding MongoDB result: %w", err)
	}

	return stats, nil
}

func (h *Handler) WriteError(ctx context.Context, client net.Conn, code string, message string) error {
	// Build error response as OP_MSG with {ok:0, errmsg: message}
	// Simplified — real implementation needs proper BSON encoding
	return nil
}

func (h *Handler) RebuildQuery(rawMsg []byte, newSQL string) []byte {
	return nil // MongoDB doesn't use SQL
}

func (h *Handler) Close() error {
	return nil
}

func classifyMongoCommand(cmd string) inspection.CommandType {
	switch cmd {
	case "find", "aggregate", "count", "distinct", "getMore":
		return inspection.CommandSELECT
	case "insert", "insertMany":
		return inspection.CommandINSERT
	case "update", "updateMany", "updateOne", "findAndModify":
		return inspection.CommandUPDATE
	case "delete", "deleteMany", "deleteOne":
		return inspection.CommandDELETE
	case "createCollection", "createIndexes", "drop", "dropDatabase", "dropIndexes", "renameCollection":
		return inspection.CommandDDL
	case "createUser", "dropUser", "grantRolesToUser", "revokeRolesFromUser":
		return inspection.CommandDCL
	case "ping", "isMaster", "hello", "ismaster", "buildInfo", "serverStatus", "hostInfo":
		return inspection.CommandADMIN
	default:
		return inspection.CommandUNKNOWN
	}
}

func encodeHeader(msg *Message) []byte {
	buf := make([]byte, 16)
	totalLen := 16 + len(msg.Payload)
	buf[0] = byte(totalLen)
	buf[1] = byte(totalLen >> 8)
	buf[2] = byte(totalLen >> 16)
	buf[3] = byte(totalLen >> 24)
	buf[4] = byte(msg.Header.RequestID)
	buf[5] = byte(msg.Header.RequestID >> 8)
	buf[6] = byte(msg.Header.RequestID >> 16)
	buf[7] = byte(msg.Header.RequestID >> 24)
	buf[8] = byte(msg.Header.ResponseTo)
	buf[9] = byte(msg.Header.ResponseTo >> 8)
	buf[10] = byte(msg.Header.ResponseTo >> 16)
	buf[11] = byte(msg.Header.ResponseTo >> 24)
	buf[12] = byte(msg.Header.OpCode)
	buf[13] = byte(msg.Header.OpCode >> 8)
	buf[14] = byte(msg.Header.OpCode >> 16)
	buf[15] = byte(msg.Header.OpCode >> 24)
	return buf
}
