package pg

import (
	"context"
	"net"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/session"
)

// Handler implements the protocol.Handler interface for PostgreSQL.
type Handler struct{}

// New creates a new PostgreSQL protocol handler.
func New() *Handler {
	return &Handler{}
}

func (h *Handler) Name() string {
	return "postgresql"
}

// DetectProtocol checks if the initial bytes look like a PostgreSQL startup.
func (h *Handler) DetectProtocol(peek []byte) bool {
	if len(peek) < 8 {
		return false
	}
	// Check for protocol version 3.0: bytes 4-7 = 0x00 0x03 0x00 0x00
	if peek[4] == 0x00 && peek[5] == 0x03 && peek[6] == 0x00 && peek[7] == 0x00 {
		return true
	}
	// Check for SSLRequest: bytes 4-7 = 04 d2 16 2f (code 80877103)
	if peek[4] == 0x04 && peek[5] == 0xd2 && peek[6] == 0x16 && peek[7] == 0x2f {
		return true
	}
	return false
}

func (h *Handler) Handshake(ctx context.Context, client, backend net.Conn) (*session.Info, error) {
	return DoHandshake(ctx, client, backend)
}

func (h *Handler) ReadCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
	return ReadQueryCommand(ctx, client)
}

func (h *Handler) ForwardCommand(ctx context.Context, rawMsg []byte, backend net.Conn) error {
	return ForwardQuery(ctx, rawMsg, backend)
}

func (h *Handler) ReadAndForwardResult(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
	return ForwardResult(ctx, backend, client, pipeline)
}

func (h *Handler) WriteError(ctx context.Context, client net.Conn, code, message string) error {
	msg := BuildErrorResponse("ERROR", code, message)
	if err := WriteMessage(client, msg); err != nil {
		return err
	}
	// Send ReadyForQuery
	ready := BuildReadyForQuery('I') // 'I' = idle
	return WriteMessage(client, ready)
}

func (h *Handler) Close() error {
	return nil
}
