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

type HandshakeOpts struct {
	ServerTLS *tls.Config
}

func DoHandshake(ctx context.Context, client, backend net.Conn) (*session.Info, error) {
	return DoHandshakeWithOpts(ctx, client, backend, nil)
}

func DoHandshakeWithOpts(ctx context.Context, client, backend net.Conn, opts *HandshakeOpts) (*session.Info, error) {
	sd, err := ReadStartupMessage(client)
	if err != nil {
		return nil, fmt.Errorf("reading client startup: %w", err)
	}
	su, err := ParseStartupMessage(sd)
	if err != nil {
		return nil, fmt.Errorf("parsing startup: %w", err)
	}
	if su.IsSSLRequest {
		if opts != nil && opts.ServerTLS != nil {
			if _, err := client.Write([]byte{'S'}); err != nil {
				return nil, fmt.Errorf("SSL accept: %w", err)
			}
			tlsConn := tls.Server(client, opts.ServerTLS)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			client = tlsConn
		} else {
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, fmt.Errorf("SSL reject: %w", err)
			}
		}
		sd, err = ReadStartupMessage(client)
		if err != nil {
			return nil, fmt.Errorf("reading post-SSL startup: %w", err)
		}
		su, err = ParseStartupMessage(sd)
		if err != nil {
			return nil, fmt.Errorf("parsing post-SSL startup: %w", err)
		}
	}
	info := &session.Info{
		Username:   su.Parameters["user"],
		Database:   su.Parameters["database"],
		Parameters: su.Parameters,
	}
	if info.Database == "" {
		info.Database = info.Username
	}
	if err := WriteRawBytes(backend, sd); err != nil {
		return nil, fmt.Errorf("forwarding startup: %w", err)
	}
	if err := relayAuth(ctx, client, backend, info); err != nil {
		return nil, err
	}
	return info, nil
}

func relayAuth(ctx context.Context, client, backend net.Conn, info *session.Info) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		msg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading backend auth: %w", err)
		}
		switch msg.Type {
		case MsgAuth:
			at, err := parseAuthType(msg.Payload)
			if err != nil {
				return err
			}
			switch at {
			case AuthOK:
				if err := WriteMessage(client, msg); err != nil {
					return fmt.Errorf("forwarding AuthOK: %w", err)
				}
				if info.AuthMethod == "" {
					info.AuthMethod = "ok"
				}
				return relayPostAuth(ctx, client, backend)
			case AuthCleartextPwd, AuthMD5Pwd, AuthSASL, AuthSASLContinue, AuthSASLFinal:
				if err := WriteMessage(client, msg); err != nil {
					return fmt.Errorf("forwarding auth: %w", err)
				}
				switch at {
				case AuthCleartextPwd:
					info.AuthMethod = "cleartext"
				case AuthMD5Pwd:
					info.AuthMethod = "md5"
				default:
					info.AuthMethod = "sasl"
				}
				if at == AuthSASLFinal {
					continue
				}
				cm, err := ReadMessage(client)
				if err != nil {
					return fmt.Errorf("reading client: %w", err)
				}
				if err := WriteMessage(backend, cm); err != nil {
					return fmt.Errorf("forwarding client: %w", err)
				}
			default:
				return fmt.Errorf("unsupported auth type: %d", at)
			}
		case MsgErrorResponse:
			if err := WriteMessage(client, msg); err != nil {
				return fmt.Errorf("forwarding error: %w", err)
			}
			f := ParseErrorResponse(msg.Payload)
			return fmt.Errorf("backend auth failed: %s", f['M'])
		default:
			return fmt.Errorf("unexpected: %c", msg.Type)
		}
	}
}

func relayPostAuth(ctx context.Context, client, backend net.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		msg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading: %w", err)
		}
		if err := WriteMessage(client, msg); err != nil {
			return fmt.Errorf("writing: %w", err)
		}
		switch msg.Type {
		case MsgReadyForQuery:
			return nil
		case MsgParameterStatus, MsgBackendKeyData, MsgNoticeResponse:
			continue
		case MsgErrorResponse:
			f := ParseErrorResponse(msg.Payload)
			return fmt.Errorf("error: %s", f['M'])
		default:
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

// ──────────────────────── Proxy Auth ────────────────────────

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
	r, err := ReadMessage(client)
	if err != nil {
		return fmt.Errorf("reading SASL: %w", err)
	}
	if r.Type != MsgPassword {
		return fmt.Errorf("expected PasswordMessage, got %c", r.Type)
	}
	pl := r.Payload
	me := 0
	for me < len(pl) && pl[me] != 0 {
		me++
	}
	if string(pl[:me]) != "SCRAM-SHA-256" {
		return fmt.Errorf("unsupported: %q", string(pl[:me]))
	}
	cf := string(pl[me+1:])
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
			return fmt.Errorf("sending SASL: %w", err)
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
		sf, err := scram.ParseSFMsg(srRaw)
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
		bc := scram.CFBare(cf)
		cnp := scram.CFNoProof(cfinal)
		am := scram.AuthMsg(bc, srRaw) + cnp
		if err := scram.VerifySig(password, sf, am, sfinal); err != nil {
			return fmt.Errorf("sig mismatch: %w", err)
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
