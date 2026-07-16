package pg

import (
	"fmt"
	"net"
)

func buildAuthSASL(mechanisms ...string) *Message {
	var payload []byte
	payload = append(payload, byte(AuthSASL>>24), byte(AuthSASL>>16), byte(AuthSASL>>8), byte(AuthSASL))
	for _, m := range mechanisms {
		payload = append(payload, []byte(m)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0)
	return &Message{Type: MsgAuth, Payload: payload}
}

func buildAuthSASLContinue(serverFirst string) *Message {
	var payload []byte
	payload = append(payload, byte(AuthSASLContinue>>24), byte(AuthSASLContinue>>16), byte(AuthSASLContinue>>8), byte(AuthSASLContinue))
	payload = append(payload, []byte(serverFirst)...)
	return &Message{Type: MsgAuth, Payload: payload}
}

func buildAuthSASLFinal(serverFinal string) *Message {
	var payload []byte
	payload = append(payload, byte(AuthSASLFinal>>24), byte(AuthSASLFinal>>16), byte(AuthSASLFinal>>8), byte(AuthSASLFinal))
	payload = append(payload, []byte(serverFinal)...)
	return &Message{Type: MsgAuth, Payload: payload}
}

func RelayPostAuthFromBackend(backend, client net.Conn) error {
	for {
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
			fields := ParseErrorResponse(msg.Payload)
			return fmt.Errorf("post-auth error: %s", fields['M'])
		}
	}
}
