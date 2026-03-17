package pg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/ersinkoc/argus/internal/session"
)

// HandshakeOpts configures the handshake behavior.
type HandshakeOpts struct {
	// ServerTLS is the TLS config for client-facing SSL upgrade.
	// If nil, SSLRequest gets 'N' response.
	ServerTLS *tls.Config
}

// DoHandshake performs the PostgreSQL authentication handshake.
// It acts as a man-in-the-middle:
//  1. Reads the client's startup message
//  2. Forwards it to the backend
//  3. Relays auth messages between client and backend
//  4. Returns session info on success
// DoHandshake performs the PostgreSQL authentication handshake.
func DoHandshake(ctx context.Context, client, backend net.Conn) (*session.Info, error) {
	return DoHandshakeWithOpts(ctx, client, backend, nil)
}

// DoHandshakeWithOpts performs handshake with options (e.g. TLS upgrade).
func DoHandshakeWithOpts(ctx context.Context, client, backend net.Conn, opts *HandshakeOpts) (*session.Info, error) {
	// Step 1: Read startup message from client
	startupData, err := ReadStartupMessage(client)
	if err != nil {
		return nil, fmt.Errorf("reading client startup: %w", err)
	}

	startup, err := ParseStartupMessage(startupData)
	if err != nil {
		return nil, fmt.Errorf("parsing startup message: %w", err)
	}

	// Handle SSL request
	if startup.IsSSLRequest {
		if opts != nil && opts.ServerTLS != nil {
			// Upgrade to TLS: respond 'S' and perform TLS handshake
			if _, err := client.Write([]byte{'S'}); err != nil {
				return nil, fmt.Errorf("writing SSL accept: %w", err)
			}
			tlsConn := tls.Server(client, opts.ServerTLS)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			// Replace client conn with TLS conn for subsequent reads
			client = tlsConn
		} else {
			// No TLS configured: respond 'N'
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("writing SSL reject: %w", err)
			}
		}
		// Client sends another startup message (over TLS or plain)
		startupData, err = ReadStartupMessage(client)
		if err != nil {
			return nil, fmt.Errorf("reading post-SSL startup: %w", err)
		}
		startup, err = ParseStartupMessage(startupData)
		if err != nil {
			return nil, fmt.Errorf("parsing post-SSL startup: %w", err)
		}
	}

	// Extract session info
	info := &session.Info{
		Username:   startup.Parameters["user"],
		Database:   startup.Parameters["database"],
		Parameters: startup.Parameters,
	}
	if info.Database == "" {
		info.Database = info.Username
	}

	// Step 2: Forward startup message to backend
	if err := WriteRawBytes(backend, startupData); err != nil {
		return nil, fmt.Errorf("forwarding startup to backend: %w", err)
	}

	// Step 3: Relay authentication exchange
	if err := relayAuth(ctx, client, backend, info); err != nil {
		return nil, err
	}

	return info, nil
}

// relayAuth relays authentication messages between client and backend.
func relayAuth(ctx context.Context, client, backend net.Conn, info *session.Info) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read message from backend
		msg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading backend auth message: %w", err)
		}

		switch msg.Type {
		case MsgAuth:
			authType, err := parseAuthType(msg.Payload)
			if err != nil {
				return err
			}

			switch authType {
			case AuthOK:
				// Authentication successful, forward to client
				if err := WriteMessage(client, msg); err != nil {
					return fmt.Errorf("forwarding AuthOK: %w", err)
				}
				info.AuthMethod = "ok"
				// Continue reading parameter status, backend key, ready for query
				return relayPostAuth(ctx, client, backend)

			case AuthCleartextPwd, AuthMD5Pwd, AuthSASL, AuthSASLContinue, AuthSASLFinal:
				// Forward auth request to client
				if err := WriteMessage(client, msg); err != nil {
					return fmt.Errorf("forwarding auth request: %w", err)
				}

				if authType == AuthCleartextPwd {
					info.AuthMethod = "cleartext"
				} else if authType == AuthMD5Pwd {
					info.AuthMethod = "md5"
				} else {
					info.AuthMethod = "sasl"
				}

				// For SASL final, auth is complete after forwarding
				if authType == AuthSASLFinal {
					continue
				}

				// Read client's response
				clientMsg, err := ReadMessage(client)
				if err != nil {
					return fmt.Errorf("reading client auth response: %w", err)
				}

				// Forward to backend
				if err := WriteMessage(backend, clientMsg); err != nil {
					return fmt.Errorf("forwarding client auth response: %w", err)
				}

			default:
				return fmt.Errorf("unsupported auth type: %d", authType)
			}

		case MsgErrorResponse:
			// Auth failed, forward error to client
			if err := WriteMessage(client, msg); err != nil {
				return fmt.Errorf("forwarding auth error: %w", err)
			}
			fields := ParseErrorResponse(msg.Payload)
			return fmt.Errorf("backend auth failed: %s", fields['M'])

		default:
			return fmt.Errorf("unexpected message type during auth: %c", msg.Type)
		}
	}
}

// relayPostAuth forwards parameter status, backend key data, and ready for query messages.
func relayPostAuth(ctx context.Context, client, backend net.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading post-auth message: %w", err)
		}

		// Forward all post-auth messages to client
		if err := WriteMessage(client, msg); err != nil {
			return fmt.Errorf("forwarding post-auth message: %w", err)
		}

		switch msg.Type {
		case MsgReadyForQuery:
			// Ready for queries, handshake complete
			return nil
		case MsgParameterStatus, MsgBackendKeyData, MsgNoticeResponse:
			// Continue reading
			continue
		case MsgErrorResponse:
			fields := ParseErrorResponse(msg.Payload)
			return fmt.Errorf("backend error during post-auth: %s", fields['M'])
		default:
			// Forward unknown messages
			continue
		}
	}
}

func parseAuthType(payload []byte) (int32, error) {
	if len(payload) < 4 {
		return 0, fmt.Errorf("auth payload too short")
	}
	return int32(payload[0])<<24 | int32(payload[1])<<16 | int32(payload[2])<<8 | int32(payload[3]), nil
}
