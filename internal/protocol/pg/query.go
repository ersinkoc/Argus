package pg

import (
	"context"
	"fmt"
	"net"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/metrics"
)

// ExtendedQueryBatch holds a batch of Extended Query messages read until Sync.
// The SQL comes from the Parse message; Bind/Execute/Describe/Close are forwarded.
type ExtendedQueryBatch struct {
	Messages []*Message // all messages in the batch (Parse, Bind, Describe, Execute, ..., Sync)
	SQL      string     // SQL from the Parse message (if present)
	HasParse bool
}

// ReadQueryCommand reads the next command from the client.
// It handles both Simple Query ('Q') and Extended Query (Parse/Bind/Execute/Sync) protocols.
func ReadQueryCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
	msg, err := ReadMessage(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading client message: %w", err)
	}

	switch msg.Type {
	case MsgQuery:
		// Simple Query: payload is null-terminated SQL string
		sql := extractSQL(msg.Payload)
		cmd := inspection.Classify(sql)
		metrics.ProtocolStats.PGQueries.Add(1)
		return cmd, EncodeMessage(msg), nil

	case MsgTerminate:
		return nil, EncodeMessage(msg), nil

	case MsgParse:
		// Extended Query: starts with Parse, collect until Sync
		batch, err := readExtendedBatch(ctx, client, msg)
		if err != nil {
			return nil, nil, err
		}
		metrics.ProtocolStats.PGExtended.Add(1)

		// Inspect the SQL from Parse
		cmd := &inspection.Command{
			Type:       inspection.CommandUNKNOWN,
			Raw:        batch.SQL,
			RiskLevel:  inspection.RiskNone,
			Confidence: 0.8, // lower confidence for prepared statements (no param values)
		}
		if batch.SQL != "" {
			cmd = inspection.Classify(batch.SQL)
			cmd.Confidence = 0.8
		}

		// Encode all messages as a single raw batch
		var rawBatch []byte
		for _, m := range batch.Messages {
			rawBatch = append(rawBatch, EncodeMessage(m)...)
		}
		return cmd, rawBatch, nil

	default:
		// Other messages: Bind without Parse (using cached statement),
		// Describe, Execute, Sync, Close, Flush — forward as-is
		if IsExtendedQueryMsg(msg.Type) {
			batch, err := readExtendedBatch(ctx, client, msg)
			if err != nil {
				return nil, nil, err
			}
			cmd := &inspection.Command{
				Type:       inspection.CommandUNKNOWN,
				Raw:        fmt.Sprintf("[extended_query stmt=%s]", batch.SQL),
				RiskLevel:  inspection.RiskNone,
				Confidence: 0.5,
			}
			var rawBatch []byte
			for _, m := range batch.Messages {
				rawBatch = append(rawBatch, EncodeMessage(m)...)
			}
			return cmd, rawBatch, nil
		}

		// Truly unknown message
		cmd := &inspection.Command{
			Type:      inspection.CommandUNKNOWN,
			Raw:       fmt.Sprintf("[msg_type=%c]", msg.Type),
			RiskLevel: inspection.RiskNone,
		}
		return cmd, EncodeMessage(msg), nil
	}
}

// readExtendedBatch collects all Extended Query messages until a Sync is received.
// The first message is already read and passed as `first`.
func readExtendedBatch(ctx context.Context, client net.Conn, first *Message) (*ExtendedQueryBatch, error) {
	batch := &ExtendedQueryBatch{
		Messages: []*Message{first},
	}

	// Extract SQL if first message is Parse
	if first.Type == MsgParse {
		batch.HasParse = true
		parsed, err := DecodeParse(first.Payload)
		if err == nil {
			batch.SQL = parsed.Query
		}
	}

	// Read until Sync ('S') or flush ('H')
	for {
		select {
		case <-ctx.Done():
			return batch, ctx.Err()
		default:
		}

		msg, err := ReadMessage(client)
		if err != nil {
			return batch, fmt.Errorf("reading extended query message: %w", err)
		}

		batch.Messages = append(batch.Messages, msg)

		// Extract SQL from Parse if we haven't seen one yet
		if msg.Type == MsgParse && !batch.HasParse {
			batch.HasParse = true
			parsed, err := DecodeParse(msg.Payload)
			if err == nil {
				batch.SQL = parsed.Query
			}
		}

		// Extract statement name from Bind for tracking
		if msg.Type == 'B' {
			bind, err := DecodeBind(msg.Payload)
			if err == nil && bind.StatementName != "" && batch.SQL == "" {
				// Bind references a named statement — SQL was in a previous Parse
				batch.SQL = "[prepared:" + bind.StatementName + "]"
			}
		}

		// Sync marks end of extended query batch
		// Note: 'S' is overloaded (Sync frontend / ParameterStatus backend)
		// In this context (reading from client), 'S' is always Sync
		if msg.Type == 'S' {
			return batch, nil
		}

		// Flush can also terminate a batch (partial execution)
		if msg.Type == MsgFlush {
			return batch, nil
		}

		// Terminate
		if msg.Type == MsgTerminate {
			return batch, nil
		}
	}
}

// ForwardQuery sends raw message bytes to the backend.
func ForwardQuery(ctx context.Context, rawMsg []byte, backend net.Conn) error {
	_, err := backend.Write(rawMsg)
	return err
}

// extractSQL extracts the SQL string from a Query message payload.
func extractSQL(payload []byte) string {
	for i, b := range payload {
		if b == 0 {
			return string(payload[:i])
		}
	}
	return string(payload)
}
