package pg

import (
	"context"
	"fmt"
	"net"

	"github.com/ersinkoc/argus/internal/inspection"
)

// ReadQueryCommand reads a Query message from the client and inspects it.
func ReadQueryCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
	msg, err := ReadMessage(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading client message: %w", err)
	}

	switch msg.Type {
	case MsgQuery:
		// Query message: payload is null-terminated SQL string
		sql := extractSQL(msg.Payload)
		cmd := inspection.Classify(sql)
		return cmd, EncodeMessage(msg), nil

	case MsgTerminate:
		return nil, EncodeMessage(msg), nil

	default:
		// Forward unknown messages as-is
		cmd := &inspection.Command{
			Type:      inspection.CommandUNKNOWN,
			Raw:       fmt.Sprintf("[msg_type=%c]", msg.Type),
			RiskLevel: inspection.RiskNone,
		}
		return cmd, EncodeMessage(msg), nil
	}
}

// ForwardQuery sends raw message bytes to the backend.
func ForwardQuery(ctx context.Context, rawMsg []byte, backend net.Conn) error {
	_, err := backend.Write(rawMsg)
	return err
}

// extractSQL extracts the SQL string from a Query message payload.
func extractSQL(payload []byte) string {
	// Query payload is a null-terminated string
	for i, b := range payload {
		if b == 0 {
			return string(payload[:i])
		}
	}
	return string(payload)
}
