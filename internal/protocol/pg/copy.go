package pg

import (
	"context"
	"fmt"
	"net"
)

// COPY protocol message types
const (
	MsgCopyInResponse  byte = 'G' // backend → client: ready for COPY IN data
	MsgCopyOutResponse byte = 'H' // backend → client: COPY OUT starting
	MsgCopyData        byte = 'd' // bidirectional: data chunk
	MsgCopyDone        byte = 'c' // frontend → backend: COPY IN complete
	MsgCopyFail        byte = 'f' // frontend → backend: COPY IN failed
	MsgCopyBothResp    byte = 'W' // backend → client: COPY BOTH (replication)
)

// IsCopyMessage returns true if the message is part of the COPY protocol.
func IsCopyMessage(msgType byte) bool {
	switch msgType {
	case MsgCopyInResponse, MsgCopyOutResponse, MsgCopyData,
		MsgCopyDone, MsgCopyFail, MsgCopyBothResp:
		return true
	}
	return false
}

// HandleCopyIn handles COPY FROM STDIN flow.
// Backend has sent CopyInResponse — relay data from client to backend until CopyDone/CopyFail.
func HandleCopyIn(ctx context.Context, client, backend net.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := ReadMessage(client)
		if err != nil {
			return fmt.Errorf("reading COPY IN data: %w", err)
		}

		// Forward to backend
		if err := WriteMessage(backend, msg); err != nil {
			return fmt.Errorf("forwarding COPY IN data: %w", err)
		}

		switch msg.Type {
		case MsgCopyDone:
			// COPY complete — backend will send CommandComplete + ReadyForQuery
			return nil
		case MsgCopyFail:
			// Client aborted — backend will send ErrorResponse + ReadyForQuery
			return nil
		case MsgCopyData:
			// More data, continue
			continue
		default:
			return fmt.Errorf("unexpected message %c during COPY IN", msg.Type)
		}
	}
}

// HandleCopyOut handles COPY TO STDOUT flow.
// Backend has sent CopyOutResponse — relay data from backend to client until CopyDone.
func HandleCopyOut(ctx context.Context, backend, client net.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading COPY OUT data: %w", err)
		}

		// Forward to client
		if err := WriteMessage(client, msg); err != nil {
			return fmt.Errorf("forwarding COPY OUT data: %w", err)
		}

		switch msg.Type {
		case MsgCopyDone:
			// COPY complete — continue reading for CommandComplete + ReadyForQuery
			return nil
		case MsgCopyData:
			continue
		case MsgErrorResponse:
			return nil
		default:
			return fmt.Errorf("unexpected message %c during COPY OUT", msg.Type)
		}
	}
}
