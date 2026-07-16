package pg

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/ersinkoc/argus/internal/scram"
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
//
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
				if info.AuthMethod == "" {
					info.AuthMethod = "ok"
				}
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

func ProxyAuthServer(ctx context.Context, client net.Conn, password string) error {
	if err := WriteMessage(client, &Message{
		Type: MsgAuth,
		Payload: append(
			[]byte{byte(AuthSASL >> 24), byte(AuthSASL >> 16), byte(AuthSASL >> 8), byte(AuthSASL)},
			append([]byte("SCRAM-SHA-256"), 0)...,
		),
	}); err != nil {
		return fmt.Errorf("sending SASL: %w", err)
	}

	resp, err := ReadMessage(client)
	if err != nil {
		return fmt.Errorf("reading SASL response: %w", err)
	}
	if resp.Type != MsgPassword {
		return fmt.Errorf("expected PasswordMessage, got %c", resp.Type)
	}

	pl := resp.Payload
	mEnd := 0
	for mEnd < len(pl) && pl[mEnd] != 0 {
		mEnd++
	}
	if string(pl[:mEnd]) != "SCRAM-SHA-256" {
		return fmt.Errorf("unsupported mechanism: %q", string(pl[:mEnd]))
	}
	cf := string(pl[mEnd+1:])

	srv := scram.NewServer(password)
	sf, err := srv.ServerFirst(cf)
	if err != nil {
		return fmt.Errorf("ServerFirst: %w", err)
	}

	if err := WriteMessage(client, &Message{
		Type: MsgAuth,
		Payload: append(
			[]byte{byte(AuthSASLContinue >> 24), byte(AuthSASLContinue >> 16), byte(AuthSASLContinue >> 8), byte(AuthSASLContinue)},
			[]byte(sf)...,
		),
	}); err != nil {
		return fmt.Errorf("sending SASL continue: %w", err)
	}

	fr, err := ReadMessage(client)
	if err != nil {
		return fmt.Errorf("reading client final: %w", err)
	}
	if fr.Type != MsgPassword {
		return fmt.Errorf("expected PasswordMessage, got %c", fr.Type)
	}

	sfinal, err := srv.ClientFinal(string(fr.Payload))
	if err != nil {
		WriteMessage(client, BuildErrorResponse("FATAL", "28P01", "password auth failed"))
		return fmt.Errorf("client auth failed: %w", err)
	}

	if err := WriteMessage(client, &Message{
		Type: MsgAuth,
		Payload: append(
			[]byte{byte(AuthSASLFinal >> 24), byte(AuthSASLFinal >> 16), byte(AuthSASLFinal >> 8), byte(AuthSASLFinal)},
			[]byte(sfinal)...,
		),
	}); err != nil {
		return fmt.Errorf("sending SASL final: %w", err)
	}

	if err := WriteMessage(client, &Message{
		Type: MsgAuth,
		Payload: []byte{byte(AuthOK >> 24), byte(AuthOK >> 16), byte(AuthOK >> 8), byte(AuthOK)},
	}); err != nil {
		return fmt.Errorf("sending AuthOK: %w", err)
	}
	return nil
}

func ProxyAuthClient(ctx context.Context, backend net.Conn, password string) error {
	ar, err := ReadMessage(backend)
	if err != nil {
		return fmt.Errorf("reading auth: %w", err)
	}
	if ar.Type != MsgAuth {
		return fmt.Errorf("expected Auth, got %c", ar.Type)
	}

	at := int32(ar.Payload[0])<<24 | int32(ar.Payload[1])<<16 |
		int32(ar.Payload[2])<<8 | int32(ar.Payload[3])

	switch at {
	case AuthOK:
		return nil
	case AuthCleartextPwd:
		return WriteMessage(backend, &Message{Type: MsgPassword, Payload: append([]byte(password), 0)})
	case AuthSASL:
		nonce, err := scram.GenerateNonce()
		if err != nil {
			return fmt.Errorf("nonce: %w", err)
		}
		cf := scram.ClientFirst("argus_proxy", nonce)
		sr := append([]byte("SCRAM-SHA-256"), 0)
		cl := len(cf)
		sr = append(sr, byte(cl>>24), byte(cl>>16), byte(cl>>8), byte(cl))
		sr = append(sr, []byte(cf)...)
		if err := WriteMessage(backend, &Message{Type: MsgPassword, Payload: sr}); err != nil {
			return fmt.Errorf("sending SASL initial: %w", err)
		}

		co, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading SASL continue: %w", err)
		}
		ca, err := parseAuthType(co.Payload)
		if err != nil || ca != AuthSASLContinue {
			return fmt.Errorf("expected SASL continue, got %d", ca)
		}
		srRaw := string(co.Payload[4:])
		sf, err := scram.ParseServerFirstMessage(srRaw)
		if err != nil {
			return fmt.Errorf("parsing server-first: %w", err)
		}
		cb := "c=" + base64.StdEncoding.EncodeToString([]byte("n,,")) + ",r=" + sf.Nonce
		pf := scram.ClientFinalProof(password, sf, cf, cb)
		cfinal := cb + ",p=" + base64.StdEncoding.EncodeToString(pf)
		if err := WriteMessage(backend, &Message{Type: MsgPassword, Payload: []byte(cfinal)}); err != nil {
			return fmt.Errorf("sending client final: %w", err)
		}

		fl, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading SASL final: %w", err)
		}
		fa, err := parseAuthType(fl.Payload)
		if err != nil || fa != AuthSASLFinal {
			return fmt.Errorf("expected SASL final, got %d", fa)
		}
		sfinal := string(fl.Payload[4:])
		bc := scram.ClientFirstMessageBare(cf)
		cnp := scram.ClientFinalMessageWithoutProof(cfinal)
		am := scram.AuthMessage(bc, srRaw) + cnp
		if err := scram.VerifyServerSignature(password, sf, am, sfinal); err != nil {
			return fmt.Errorf("server sig mismatch: %w", err)
		}
	}

	ok, err := ReadMessage(backend)
	if err != nil {
		return fmt.Errorf("reading AuthOK: %w", err)
	}
	if ok.Type == MsgAuth {
		oa, _ := parseAuthType(ok.Payload)
		if oa != AuthOK {
			return fmt.Errorf("expected AuthOK, got %d", oa)
		}
	}
	return nil
}
