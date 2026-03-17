package pg

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestRelayPostAuthWithNotice(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		msg := BuildStartupMessage(map[string]string{"user": "u", "database": "d"})
		clientConn.Write(msg)
		for {
			m, err := ReadMessage(clientConn)
			if err != nil || m.Type == MsgReadyForQuery { return }
		}
	}()

	go func() {
		ReadStartupMessage(backendConn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		// Send a notice before ReadyForQuery
		noticePayload := []byte{'S'}
		noticePayload = append(noticePayload, []byte("WARNING")...)
		noticePayload = append(noticePayload, 0, 'M')
		noticePayload = append(noticePayload, []byte("test notice")...)
		noticePayload = append(noticePayload, 0, 0)
		WriteMessage(backendConn, &Message{Type: MsgNoticeResponse, Payload: noticePayload})

		// Multiple ParameterStatus
		for _, kv := range [][2]string{{"server_version", "16"}, {"client_encoding", "UTF8"}, {"TimeZone", "UTC"}} {
			ps := append([]byte(kv[0]), 0)
			ps = append(ps, []byte(kv[1])...)
			ps = append(ps, 0)
			WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
		}

		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake with notice: %v", err)
	}
	if info.Username != "u" {
		t.Errorf("username = %q", info.Username)
	}
}

func TestDoHandshakeDefaultDatabase(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	// No database specified — should default to username
	go func() {
		msg := BuildStartupMessage(map[string]string{"user": "myuser"})
		clientConn.Write(msg)
		for {
			m, err := ReadMessage(clientConn)
			if err != nil || m.Type == MsgReadyForQuery { return }
		}
	}()

	go func() {
		ReadStartupMessage(backendConn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatal(err)
	}
	if info.Database != "myuser" {
		t.Errorf("database should default to username: got %q", info.Database)
	}
}

func TestReadMessageLargePayload(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Send a message with reasonable payload
	go func() {
		payload := make([]byte, 1000)
		for i := range payload { payload[i] = 'X' }
		WriteMessage(clientConn, &Message{Type: 'T', Payload: payload})
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	msg, err := ReadMessage(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Payload) != 1000 {
		t.Errorf("payload len = %d, want 1000", len(msg.Payload))
	}
}

func TestHandlerDetectProtocolShortData(t *testing.T) {
	h := New()
	if h.DetectProtocol([]byte{1, 2, 3}) {
		t.Error("short data should not detect")
	}
	if h.DetectProtocol(nil) {
		t.Error("nil should not detect")
	}
}
