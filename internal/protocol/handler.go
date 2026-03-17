package protocol

import (
	"context"
	"net"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/session"
)

// Handler is the interface every database protocol adapter must implement.
type Handler interface {
	// Name returns the protocol identifier (e.g., "postgresql", "mysql")
	Name() string

	// DetectProtocol checks if the initial bytes match this protocol
	DetectProtocol(peek []byte) bool

	// Handshake performs the full authentication exchange
	Handshake(ctx context.Context, client net.Conn, backend net.Conn) (*session.Info, error)

	// ReadCommand reads and decodes the next command from the client
	ReadCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error)

	// ForwardCommand sends a command to the backend
	ForwardCommand(ctx context.Context, rawMsg []byte, backend net.Conn) error

	// ReadAndForwardResult reads results from backend and writes to client,
	// applying masking through the pipeline if provided
	ReadAndForwardResult(ctx context.Context, backend net.Conn, client net.Conn, pipeline *masking.Pipeline) (*ResultStats, error)

	// WriteError sends a protocol-native error message to the client
	WriteError(ctx context.Context, client net.Conn, code string, message string) error

	// Close performs any cleanup
	Close() error
}

// ResultStats holds statistics about a result set that was forwarded.
type ResultStats struct {
	RowCount    int64
	ByteCount   int64
	Truncated   bool
	MaskedCols  []string
}
