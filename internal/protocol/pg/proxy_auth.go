package pg

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"

	"github.com/ersinkoc/argus/internal/scram"
)

// ProxyAuthServer authenticates the client as the server side of the
// PostgreSQL SASL/SCRAM-SHA-256 handshake.
//
// The client has already sent the startup message. This function:
//  1. Sends AuthenticationSASL with SCRAM-SHA-256 mechanism
//  2. Reads SASLInitialResponse from client (PasswordMessage)
//  3. Sends AuthenticationSASLContinue with server-first-message
//  4. Reads SASLFinal from client (PasswordMessage)
//  5. Validates client proof against the password
//  6. Sends AuthenticationSASLFinal (server signature)
//  7. Sends AuthenticationOK
//
// Does NOT send ParameterStatus/BackendKeyData/ReadyForQuery —
// those come from the real backend and must be relayed separately.
func ProxyAuthServer(ctx context.Context, client net.Conn, password string) error {
	// Step 1: Send AuthenticationSASL with SCRAM-SHA-256
	saslMsg := buildAuthSASL("SCRAM-SHA-256")
	if err := WriteMessage(client, saslMsg); err != nil {
		return fmt.Errorf("sending SASL request: %w", err)
	}

	// Step 2: Read SASLInitialResponse from client
	initResp, err := ReadMessage(client)
	if err != nil {
		return fmt.Errorf("reading SASL initial response: %w", err)
	}
	if initResp.Type != MsgPassword {
		return fmt.Errorf("expected PasswordMessage, got type %c", initResp.Type)
	}

	payload := initResp.Payload
	mechEnd := 0
	for mechEnd < len(payload) && payload[mechEnd] != 0 {
		mechEnd++
	}
	mechanism := string(payload[:mechEnd])
	clientFirst := string(payload[mechEnd+1:])

	if mechanism != "SCRAM-SHA-256" {
		return fmt.Errorf("unsupported SASL mechanism: %s", mechanism)
	}

	// Step 3: Create SCRAM server, generate server-first-message
	srv := scram.NewServer(password)
	serverFirst, err := srv.ServerFirst(clientFirst)
	if err != nil {
		return fmt.Errorf("processing client-first-message: %w", err)
	}

	continueMsg := buildAuthSASLContinue(serverFirst)
	if err := WriteMessage(client, continueMsg); err != nil {
		return fmt.Errorf("sending SASL continue: %w", err)
	}

	// Step 4: Read SASLFinal from client
	clientFinalResp, err := ReadMessage(client)
	if err != nil {
		return fmt.Errorf("reading client SASL final: %w", err)
	}
	if clientFinalResp.Type != MsgPassword {
		return fmt.Errorf("expected PasswordMessage, got type %c", clientFinalResp.Type)
	}
	clientFinal := string(clientFinalResp.Payload)

	// Step 5: Validate client proof
	serverFinal, err := srv.ClientFinal(clientFinal)
	if err != nil {
		WriteMessage(client, BuildErrorResponse("FATAL", "28P01", "password authentication failed"))
		return fmt.Errorf("client authentication failed: %w", err)
	}

	// Step 6: Send AuthenticationSASLFinal (with server signature)
	finalMsg := buildAuthSASLFinal(serverFinal)
	if err := WriteMessage(client, finalMsg); err != nil {
		return fmt.Errorf("sending SASL final: %w", err)
	}

	// Step 7: Send AuthenticationOK
	okMsg := &Message{Type: MsgAuth, Payload: make([]byte, 4)} // AuthOK=0
	if err := WriteMessage(client, okMsg); err != nil {
		return fmt.Errorf("sending auth ok: %w", err)
	}

	slog.Debug("proxy auth: client authenticated via SCRAM-SHA-256")
	return nil
}

// ProxyAuthClient authenticates to the PostgreSQL backend as the client side
// of the SASL/SCRAM-SHA-256 handshake. It only authenticates to the backend
// without sending anything to the client. After successful auth, call
// RelayPostAuthFromBackend to forward ParameterStatus/BackendKeyData/RFQ.
//
// Flow:
//  1. Reads SASL auth request from backend
//  2. Sends SASLInitialResponse with client-first-message
//  3. Reads SASLContinue from backend
//  4. Sends SASLFinal with computed client proof
//  5. Reads SASLFinal from backend (verifies server signature)
//  6. Reads AuthOK from backend
func ProxyAuthClient(ctx context.Context, backend net.Conn, password string) error {
	authReq, err := ReadMessage(backend)
	if err != nil {
		return fmt.Errorf("reading backend auth request: %w", err)
	}
	if authReq.Type != MsgAuth {
		return fmt.Errorf("expected Auth message, got type %c", authReq.Type)
	}

	authType := int32(authReq.Payload[0])<<24 | int32(authReq.Payload[1])<<16 |
		int32(authReq.Payload[2])<<8 | int32(authReq.Payload[3])

	switch authType {
	case AuthSASL:
		mechanisms := string(authReq.Payload[4:])
		slog.Debug("backend SASL mechanisms", "mechanisms", mechanisms)

		clientNonce, err := scram.GenerateNonce()
		if err != nil {
			return fmt.Errorf("generating nonce: %w", err)
		}

		cf := scram.ClientFirst("argus_proxy", clientNonce)

		// SASLInitialResponse: mechanism\0client-first-message
		saslResp := append([]byte("SCRAM-SHA-256"), 0)
		saslResp = append(saslResp, []byte(cf)...)
		if err := WriteMessage(backend, &Message{Type: MsgPassword, Payload: saslResp}); err != nil {
			return fmt.Errorf("sending SASL initial: %w", err)
		}

		// Read SASLContinue
		continueMsg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading SASL continue: %w", err)
		}
		continueAuthType, err := parseAuthType(continueMsg.Payload)
		if err != nil {
			return fmt.Errorf("parsing auth type: %w", err)
		}
		if continueAuthType != AuthSASLContinue {
			return fmt.Errorf("expected SASL continue, got auth type %d", continueAuthType)
		}

		serverFirst := string(continueMsg.Payload[4:])
		sf, err := scram.ParseServerFirstMessage(serverFirst)
		if err != nil {
			return fmt.Errorf("parsing server-first: %w", err)
		}

		// Compute and send client proof
		clientFinalBare := "c=" + base64.StdEncoding.EncodeToString([]byte("n,,")) +
			",r=" + sf.Nonce
		proof := scram.ClientFinalProof(password, sf, cf, clientFinalBare)
		clientFinal := clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof)

		if err := WriteMessage(backend, &Message{Type: MsgPassword, Payload: []byte(clientFinal)}); err != nil {
			return fmt.Errorf("sending client final: %w", err)
		}

		// Read SASLFinal, verify server signature
		finalMsg, err := ReadMessage(backend)
		if err != nil {
			return fmt.Errorf("reading SASL final: %w", err)
		}
		finalAuthType, err := parseAuthType(finalMsg.Payload)
		if err != nil {
			return fmt.Errorf("parsing auth type: %w", err)
		}
		if finalAuthType != AuthSASLFinal {
			return fmt.Errorf("expected SASL final, got auth type %d", finalAuthType)
		}

		serverFinal := string(finalMsg.Payload[4:])
		bareCF := scram.ClientFirstMessageBare(cf)
		cfNoProof := scram.ClientFinalMessageWithoutProof(clientFinal)
		authMsg := scram.AuthMessage(bareCF, serverFirst) + cfNoProof

		if err := scram.VerifyServerSignature(password, sf, authMsg, serverFinal); err != nil {
			return fmt.Errorf("server signature mismatch: %w", err)
		}
		slog.Debug("proxy auth: backend server signature verified")

	default:
		return fmt.Errorf("unsupported backend auth type: %d", authType)
	}

	// Read AuthOK
	authOK, err := ReadMessage(backend)
	if err != nil {
		return fmt.Errorf("reading AuthOK: %w", err)
	}
	okAuthType, okErr := parseAuthType(authOK.Payload)
	if authOK.Type != MsgAuth || okErr != nil || okAuthType != AuthOK {
		if okErr != nil {
			return fmt.Errorf("expected AuthOK, got type=%c (parse error: %v)", authOK.Type, okErr)
		}
		return fmt.Errorf("expected AuthOK, got type=%c auth=%d", authOK.Type, okAuthType)
	}

	return nil
}

// RelayPostAuthFromBackend relays the post-authentication messages from the
// backend to the client: ParameterStatus, BackendKeyData, ReadyForQuery.
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
		default:
			continue
		}
	}
}

// --- Auth message builders ---

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
