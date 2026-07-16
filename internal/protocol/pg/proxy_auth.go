package pg

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"

	"github.com/ersinkoc/argus/internal/scram"
)

// ProxyAuthServer authenticates the client as the server side of SASL/SCRAM-SHA-256.
func ProxyAuthServer(ctx context.Context, client net.Conn, password string) error {
	msg := buildAuthSASL("SCRAM-SHA-256")
	if err := WriteMessage(client, msg); err != nil {
		return fmt.Errorf("sending SASL request: %w", err)
	}

	initResp, err := ReadMessage(client)
	if err != nil {
		return fmt.Errorf("reading SASL initial response: %w", err)
	}
	if initResp.Type != MsgPassword {
		return fmt.Errorf("expected PasswordMessage, got %c", initResp.Type)
	}

	payload := initResp.Payload
	mechEnd := 0
	for mechEnd < len(payload) && payload[mechEnd] != 0 {
		mechEnd++
	}
	if string(payload[:mechEnd]) != "SCRAM-SHA-256" {
		return fmt.Errorf("unsupported SASL mechanism: %s", string(payload[:mechEnd]))
	}
	clientFirst := string(payload[mechEnd+1:])

	srv := scram.NewServer(password)
	serverFirst, err := srv.ServerFirst(clientFirst)
	if err != nil {
		return fmt.Errorf("processing client-first: %w", err)
	}

	if err := WriteMessage(client, buildAuthSASLContinue(serverFirst)); err != nil {
		return fmt.Errorf("sending SASL continue: %w", err)
	}

	clientFinalResp, err := ReadMessage(client)
	if err != nil {
		return fmt.Errorf("reading client SASL final: %w", err)
	}
	if clientFinalResp.Type != MsgPassword {
		return fmt.Errorf("expected PasswordMessage, got %c", clientFinalResp.Type)
	}

	serverFinal, err := srv.ClientFinal(string(clientFinalResp.Payload))
	if err != nil {
		WriteMessage(client, BuildErrorResponse("FATAL", "28P01", "password authentication failed"))
		return fmt.Errorf("client auth failed: %w", err)
	}

	if err := WriteMessage(client, buildAuthSASLFinal(serverFinal)); err != nil {
		return fmt.Errorf("sending SASL final: %w", err)
	}

	okMsg := &Message{Type: MsgAuth, Payload: make([]byte, 4)}
	if err := WriteMessage(client, okMsg); err != nil {
		return fmt.Errorf("sending auth OK: %w", err)
	}

	slog.Debug("proxy auth: client authenticated via SCRAM-SHA-256")
	return nil
}

// ProxyAuthClient authenticates to the PostgreSQL backend as SASL/SCRAM-SHA-256 client.
func ProxyAuthClient(ctx context.Context, backend net.Conn, password string) error {
	authReq, err := ReadMessage(backend)
	if err != nil {
		return fmt.Errorf("reading backend auth request: %w", err)
	}
	if authReq.Type != MsgAuth {
		return fmt.Errorf("expected Auth message, got %c", authReq.Type)
	}

	authType := int32(authReq.Payload[0])<<24 | int32(authReq.Payload[1])<<16 |
		int32(authReq.Payload[2])<<8 | int32(authReq.Payload[3])

	switch authType {
	case AuthSASL:
		clientNonce, err := scram.GenerateNonce()
		if err != nil {
			return fmt.Errorf("generating nonce: %w", err)
		}
		cf := scram.ClientFirst("argus_proxy", clientNonce)
		saslResp := append([]byte("SCRAM-SHA-256"), 0)
		saslResp = append(saslResp, []byte(cf)...)
		if err := WriteMessage(backend, &Message{Type: MsgPassword, Payload: saslResp}); err != nil {
			return fmt.Errorf("sending SASL initial: %w", err)
		}

		continueMsg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading SASL continue: %w", err)
		}
		continueAT, err := parseAuthType(continueMsg.Payload)
		if err != nil || continueAT != AuthSASLContinue {
			return fmt.Errorf("expected SASL continue, got %d", continueAT)
		}
		serverFirst := string(continueMsg.Payload[4:])
		sf, err := scram.ParseServerFirstMessage(serverFirst)
		if err != nil {
			return fmt.Errorf("parsing server-first: %w", err)
		}

		cfBare := "c=" + base64.StdEncoding.EncodeToString([]byte("n,,")) + ",r=" + sf.Nonce
		proof := scram.ClientFinalProof(password, sf, cf, cfBare)
		clientFinal := cfBare + ",p=" + base64.StdEncoding.EncodeToString(proof)
		if err := WriteMessage(backend, &Message{Type: MsgPassword, Payload: []byte(clientFinal)}); err != nil {
			return fmt.Errorf("sending client final: %w", err)
		}

		finalMsg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading SASL final: %w", err)
		}
		finalAT, err := parseAuthType(finalMsg.Payload)
		if err != nil || finalAT != AuthSASLFinal {
			return fmt.Errorf("expected SASL final, got %d", finalAT)
		}
		serverFinal := string(finalMsg.Payload[4:])
		bareCF := scram.ClientFirstMessageBare(cf)
		cfNoProof := scram.ClientFinalMessageWithoutProof(clientFinal)
		authMsg := scram.AuthMessage(bareCF, serverFirst) + cfNoProof
		if err := scram.VerifyServerSignature(password, sf, authMsg, serverFinal); err != nil {
			return fmt.Errorf("server sig mismatch: %w", err)
		}
		slog.Debug("proxy auth: backend server sig verified")
	}

	authOK, err := ReadMessage(backend)
	if err != nil {
		return fmt.Errorf("reading AuthOK: %w", err)
	}
	okAT, err := parseAuthType(authOK.Payload)
	if authOK.Type != MsgAuth || err != nil || okAT != AuthOK {
		return fmt.Errorf("expected AuthOK, got %c", authOK.Type)
	}
	return nil
}

// RelayPostAuthFromBackend forwards ParameterStatus/BackendKeyData/ReadyForQuery.
func RelayPostAuthFromBackend(backend, client net.Conn) error {
	for {
		msg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading post-auth: %w", err)
		}
		if err := WriteMessage(client, msg); err != nil {
			return fmt.Errorf("forwarding post-auth: %w", err)
		}
		switch msg.Type {
		case MsgReadyForQuery:
			return nil
		case MsgParameterStatus, MsgBackendKeyData, MsgNoticeResponse:
			continue
		case MsgErrorResponse:
			fields := ParseErrorResponse(msg.Payload)
			return fmt.Errorf("backend post-auth error: %s", fields['M'])
		}
	}
}

func buildAuthSASL(mechanisms ...string) *Message {
	var payload []byte
	payload = append(payload, byte(0), byte(0), byte(0), byte(AuthSASL))
	for _, m := range mechanisms {
		payload = append(payload, []byte(m)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0)
	return &Message{Type: MsgAuth, Payload: payload}
}

func buildAuthSASLContinue(serverFirst string) *Message {
	var payload []byte
	payload = append(payload, byte(0), byte(0), byte(0), byte(AuthSASLContinue))
	payload = append(payload, []byte(serverFirst)...)
	return &Message{Type: MsgAuth, Payload: payload}
}

func buildAuthSASLFinal(serverFinal string) *Message {
	var payload []byte
	payload = append(payload, byte(0), byte(0), byte(0), byte(AuthSASLFinal))
	payload = append(payload, []byte(serverFinal)...)
	return &Message{Type: MsgAuth, Payload: payload}
}
