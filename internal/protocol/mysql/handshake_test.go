package mysql

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHandlerHandshakeAuthSwitch(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	// Backend: greeting → read response → auth switch (0xFE) → read client → OK
	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "test"))
		ReadPacket(backendConn) // client response

		// Auth switch request (0xFE)
		var switchPayload []byte
		switchPayload = append(switchPayload, 0xFE)
		switchPayload = append(switchPayload, []byte("mysql_native_password")...)
		switchPayload = append(switchPayload, 0)
		switchPayload = append(switchPayload, make([]byte, 20)...) // auth data
		switchPayload = append(switchPayload, 0)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: switchPayload})

		ReadPacket(backendConn) // client auth switch response
		WritePacket(backendConn, BuildOKPacket(4, 0, 0))
	}()

	// Client: read greeting → send response → read switch → send auth → read OK
	go func() {
		ReadPacket(clientConn) // greeting

		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user1")...)
		payload = append(payload, 0)
		payload = append(payload, 0) // auth len
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})

		ReadPacket(clientConn) // auth switch
		WritePacket(clientConn, &Packet{SequenceID: 3, Payload: make([]byte, 20)}) // auth response
		ReadPacket(clientConn) // OK
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake auth switch: %v", err)
	}
	if info.Username != "user1" {
		t.Errorf("username = %q", info.Username)
	}
}

func TestHandlerHandshakeAuthFail(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "test"))
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildErrPacket(2, 1045, "Access denied"))
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("bad")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // error
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("should fail on auth error")
	}
}

func TestHandlerHandshakeFastAuth(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	// Backend: greeting → response → fast auth success (0x01 0x04) → OK
	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "test"))
		ReadPacket(backendConn)
		// Fast auth success
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x04}})
		WritePacket(backendConn, BuildOKPacket(3, 0, 0))
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("fast")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // fast auth (0x01 0x04)
		ReadPacket(clientConn) // OK
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Fast auth: %v", err)
	}
	if info.Username != "fast" {
		t.Errorf("username = %q", info.Username)
	}
}
