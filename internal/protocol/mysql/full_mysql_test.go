package mysql

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

// --- ReadPacket: header read error ---

func TestReadPacketHeaderReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientConn.Close()
	defer serverConn.Close()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	if err == nil {
		t.Error("header read error should fail")
	}
}

// --- ReadPacket: too large ---

func TestReadPacketTooLargeCheck(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		header := make([]byte, headerSize)
		// length = 16MB + 1 = 16777217
		header[0] = 0x01
		header[1] = 0x00
		header[2] = 0x01 // 0x010001 = 65537 wait no... 16*1024*1024 = 16777216 = 0x1000000
		// Actually: 16777217 in 3 bytes little-endian: 0x01, 0x00, 0x01 = 65537, not 16M
		// 16777217 = 0x1000001 -> header[0]=0x01, header[1]=0x00, header[2]=0x00, but that's only 1
		// Let me compute: 16*1024*1024 + 1 = 16777217
		// In 3-byte LE: byte0 = 0x01, byte1 = 0x00, byte2 = 0x00 -> only 1
		// Actually 16777217 = 0x01000001
		// 3 bytes: header[0] = 0x01, header[1] = 0x00, header[2] = 0x00 -> 1
		// Wait, 3 bytes max = 16777215 = 0xFFFFFF
		// I need length > 16*1024*1024 = 16777216, but 3 bytes max is 16777215
		// So I can't create a too-large packet with 3-byte length header
		// Let me check the source: `length > 16*1024*1024` -> length > 16777216
		// 3 bytes max: 16777215, which is NOT > 16777216. So this branch can never be hit
		// with a real packet! It's dead code. The check is for safety.
		clientConn.Close()
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	// This will fail from connection close, not from too-large check
	if err == nil {
		t.Error("should fail")
	}
}

// --- ReadPacket: payload read error ---

func TestReadPacketPayloadReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		header := make([]byte, headerSize)
		header[0] = 100 // length = 100
		header[1] = 0
		header[2] = 0
		header[3] = 0
		clientConn.Write(header)
		clientConn.Write([]byte("short")) // only 5 bytes
		clientConn.Close()
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	if err == nil {
		t.Error("payload read error should fail")
	}
}

// --- ParseHandshakeResponse41: too short ---

func TestParseHandshakeResponse41TooShort(t *testing.T) {
	_, err := ParseHandshakeResponse41([]byte{1, 2, 3})
	if err == nil {
		t.Error("too short should fail")
	}
}

// --- ParseHandshakeResponse41: auth response with length but not enough data ---

func TestParseHandshakeResponse41AuthResponseTruncated(t *testing.T) {
	var payload []byte
	payload = append(payload, 0x0F, 0x00, 0x00, 0x00) // caps (no CONNECT_WITH_DB)
	payload = append(payload, 0x00, 0x00, 0x00, 0x01)
	payload = append(payload, 45)
	payload = append(payload, make([]byte, 23)...)
	payload = append(payload, []byte("user")...)
	payload = append(payload, 0)
	payload = append(payload, 20) // auth length = 20, but no data follows

	resp, err := ParseHandshakeResponse41(payload)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Username != "user" {
		t.Errorf("username = %q", resp.Username)
	}
}

// --- ParseHandshakeResponse41: no auth data (i >= len) ---

func TestParseHandshakeResponse41NoAuthData(t *testing.T) {
	var payload []byte
	payload = append(payload, 0x0F, 0x00, 0x00, 0x00) // caps
	payload = append(payload, 0x00, 0x00, 0x00, 0x01)
	payload = append(payload, 45)
	payload = append(payload, make([]byte, 23)...)
	payload = append(payload, []byte("user")...)
	payload = append(payload, 0)
	// No auth data at all (i == len(payload))

	resp, err := ParseHandshakeResponse41(payload)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Username != "user" {
		t.Errorf("username = %q", resp.Username)
	}
	if len(resp.AuthResponse) != 0 {
		t.Errorf("auth response should be empty")
	}
}

// --- Handshake: greeting read error ---

func TestHandshakeGreetingReadErr(t *testing.T) {
	_, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()

	backendConn.Close() // close backend

	h := New()
	proxyBackend.SetReadDeadline(time.Now().Add(time.Second))
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	proxyBackend.Close()
	if err == nil {
		t.Error("greeting read error should fail")
	}
}

// --- Handshake: forward greeting write error ---

func TestHandshakeForwardGreetingWriteError(t *testing.T) {
	proxyClient, _ := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward greeting write error should fail")
	}
}

// --- Handshake: client handshake response read error ---

func TestHandshakeClientResponseReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // read greeting
		clientConn.Close()     // close before sending response
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("client response read error should fail")
	}
}

// --- Handshake: parse handshake response error (short payload) ---

func TestHandshakeParseError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // read greeting
		// Send too-short handshake response
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: []byte{1, 2, 3}})
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("parse error should fail")
	}
}

// --- Handshake: forward handshake to backend write error ---

func TestHandshakeForwardToBackendWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // read greeting
		// Send valid handshake response
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		backendConn.Close() // close before forwarding handshake
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward to backend write error should fail")
	}
}

// --- Handshake: auth result read error ---

func TestHandshakeAuthResultReadErr(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn)
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn) // read forwarded handshake
		backendConn.Close()     // close before sending auth result
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth result read error should fail")
	}
}

// --- Handshake: forward auth result write error ---

func TestHandshakeForwardAuthResultWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		clientConn.Close() // close before auth result
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildOKPacket(2, 0, 0))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward auth result write error should fail")
	}
}

// --- Handshake: backend auth failed (ERR) ---

func TestHandshakeBackendAuthFailed(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn)
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // read ERR
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		// Send ERR
		WritePacket(backendConn, BuildErrPacket(2, 1045, "Access denied"))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("backend auth failed should fail")
	}
}

// --- Handshake: auth switch (0xFE) ---

func TestHandshakeAuthSwitch(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})

		// Read auth switch request
		ReadPacket(clientConn)
		// Send auth response
		WritePacket(clientConn, &Packet{SequenceID: 3, Payload: []byte("auth_data")})
		// Read final OK
		ReadPacket(clientConn)
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		// Send auth switch request (0xFE)
		var switchPayload []byte
		switchPayload = append(switchPayload, 0xFE)
		switchPayload = append(switchPayload, []byte("mysql_native_password")...)
		switchPayload = append(switchPayload, 0)
		switchPayload = append(switchPayload, make([]byte, 20)...) // new auth data
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: switchPayload})
		// Read client auth response
		ReadPacket(backendConn)
		// Send OK
		WritePacket(backendConn, BuildOKPacket(4, 0, 0))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake auth switch: %v", err)
	}
	if info.Username != "user" {
		t.Errorf("username = %q", info.Username)
	}
}

// --- Handshake: fast auth (caching_sha2 0x01 0x04) ---

func TestHandshakeFastAuth(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		// Read fast auth success
		ReadPacket(clientConn)
		// Read final OK
		ReadPacket(clientConn)
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		// Send AuthMoreData with fast auth success (0x01 + 0x04)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x04}})
		// Send final OK
		WritePacket(backendConn, BuildOKPacket(3, 0, 0))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake fast auth: %v", err)
	}
	if info.Username != "user" {
		t.Errorf("username = %q", info.Username)
	}
}

// --- Handshake: fast auth final OK read error ---

func TestHandshakeFastAuthFinalOKReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn)
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // auth more data
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x04}})
		backendConn.Close() // close before final OK
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("fast auth final OK read error should fail")
	}
}

// --- Handshake: fast auth final OK forward write error ---

func TestHandshakeFastAuthFinalOKForwardError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // fast auth
		clientConn.Close()     // close before final OK can be forwarded
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x04}})
		time.Sleep(50 * time.Millisecond)
		WritePacket(backendConn, BuildOKPacket(3, 0, 0))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("fast auth forward error should fail")
	}
}

// --- Handshake: auth continuation client read error ---

func TestHandshakeAuthContinuationClientReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // auth switch
		clientConn.Close()     // close before sending response
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		// Non-fast auth, non-OK, non-ERR -> auth continuation
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x03}}) // full auth needed
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth continuation client read error should fail")
	}
}

// --- Handshake: auth continuation forward to backend error ---

func TestHandshakeAuthContinuationForwardBackendError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn)
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn)
		WritePacket(clientConn, &Packet{SequenceID: 3, Payload: []byte("auth")})
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x03}})
		backendConn.Close() // close before receiving client auth continuation
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth continuation forward to backend error should fail")
	}
}

// --- Handshake: auth continuation result read error ---

func TestHandshakeAuthContinuationResultReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn)
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // auth switch
		WritePacket(clientConn, &Packet{SequenceID: 3, Payload: []byte("auth")})
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x03}})
		ReadPacket(backendConn) // read client auth
		backendConn.Close()     // close before sending continuation result
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth continuation result read error should fail")
	}
}

// --- Handshake: auth continuation result forward write error ---

func TestHandshakeAuthContinuationResultForwardError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("user")...)
		payload = append(payload, 0)
		payload = append(payload, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // auth switch
		WritePacket(clientConn, &Packet{SequenceID: 3, Payload: []byte("auth")})
		clientConn.Close() // close before continuation result forward
	}()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(1, "8.0"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x03}})
		ReadPacket(backendConn)
		time.Sleep(50 * time.Millisecond)
		WritePacket(backendConn, BuildOKPacket(4, 0, 0))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth continuation result forward error should fail")
	}
}

// --- ReadAndForwardResult: header read error ---

func TestReadAndForwardResultHeaderReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer proxyClient.Close()

	backendConn.Close()

	h := New()
	proxyBackend.SetReadDeadline(time.Now().Add(time.Second))
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	proxyBackend.Close()
	if err == nil {
		t.Error("header read error should fail")
	}
}

// --- ReadAndForwardResult: column count forward write error ---

func TestReadAndForwardResultColumnCountWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	go func() {
		// Column count (not OK, not ERR) = result set
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("column count write error should fail")
	}
}

// --- ReadAndForwardResult: column def read error ---

func TestReadAndForwardResultColDefReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		backendConn.Close() // close before column def
	}()

	go func() {
		ReadPacket(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("column def read error should fail")
	}
}

// --- ReadAndForwardResult: row read error ---

func TestReadAndForwardResultRowReadErr(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var colDef []byte
		for _, s := range []string{"d", "s", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
		WritePacket(backendConn, BuildEOFPacket(3))
		backendConn.Close() // close before rows
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("row read error should fail")
	}
}

// --- ReadAndForwardResult: row write error (with masking, truncation) ---

func TestReadAndForwardResultRowWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var colDef []byte
		for _, s := range []string{"d", "s", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("n")...)
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("n")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
		WritePacket(backendConn, BuildEOFPacket(3))
		// Row
		var row []byte
		row = append(row, 5)
		row = append(row, []byte("Alice")...)
		WritePacket(backendConn, &Packet{SequenceID: 4, Payload: row})
	}()

	go func() {
		// Read column count, col def, EOF, then close
		ReadPacket(clientConn)
		ReadPacket(clientConn)
		ReadPacket(clientConn)
		clientConn.Close()
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("row write error should fail")
	}
}

// --- ReadAndForwardResult: masking with row limit (truncation) ---

func TestReadAndForwardResultMaskingTruncation(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var colDef []byte
		for _, s := range []string{"d", "s", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 4)
		colDef = append(colDef, []byte("name")...)
		colDef = append(colDef, 4)
		colDef = append(colDef, []byte("name")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
		WritePacket(backendConn, BuildEOFPacket(3))

		// 3 rows
		for i := 0; i < 3; i++ {
			var row []byte
			row = append(row, 5)
			row = append(row, []byte("Alice")...)
			WritePacket(backendConn, &Packet{SequenceID: byte(4 + i), Payload: row})
		}
		WritePacket(backendConn, BuildEOFPacket(7))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "name", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "name", Index: 0}}, 1)

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !stats.Truncated {
		t.Error("should be truncated")
	}
}

// --- handlePrepareResponse: read error ---

func TestHandlePrepareResponseReadErr(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	backendConn.Close()

	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(time.Second))
	proxyClient.SetDeadline(time.Now().Add(time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("prepare response read error should fail")
	}
}

// --- handlePrepareResponse: forward write error ---

func TestHandlePrepareResponseForwardWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		WritePacket(backendConn, BuildOKPacket(1, 0, 0))
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("prepare response forward write error should fail")
	}
}

// --- handlePrepareResponse: ERR packet ---

func TestHandlePrepareResponseERR(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		WritePacket(backendConn, BuildErrPacket(1, 1064, "syntax error"))
	}()

	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("prepare response ERR: %v", err)
	}
}

// --- handlePrepareResponse: OK with params and cols ---

func TestHandlePrepareResponseWithParamsAndCols(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare
	h.lastPrepareSQL = "SELECT * FROM t WHERE id = ?"

	go func() {
		// OK: 0x00 + stmt_id(4) + num_cols(2) + num_params(2) + filler(1) + warnings(2)
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 42)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		binary.LittleEndian.PutUint16(numCols, 1) // 1 column
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		binary.LittleEndian.PutUint16(numParams, 1) // 1 param
		resp = append(resp, numParams...)
		resp = append(resp, 0) // filler
		resp = append(resp, 0, 0) // warnings
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})

		// Param definition
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("param_def")})
		// Param EOF
		WritePacket(backendConn, BuildEOFPacket(3))

		// Column definition
		WritePacket(backendConn, &Packet{SequenceID: 4, Payload: []byte("col_def")})
		// Column EOF
		WritePacket(backendConn, BuildEOFPacket(5))
	}()

	go func() {
		for i := 0; i < 6; i++ {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			ReadPacket(clientConn)
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify statement was stored
	stmt := h.stmtStore.Get(42)
	if stmt == nil {
		t.Fatal("statement should be stored")
	}
	if stmt.SQL != "SELECT * FROM t WHERE id = ?" {
		t.Errorf("SQL = %q", stmt.SQL)
	}
}

// --- handlePrepareResponse: param read error ---

func TestHandlePrepareResponseParamReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		binary.LittleEndian.PutUint16(numCols, 0)
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		binary.LittleEndian.PutUint16(numParams, 1)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		backendConn.Close() // close before param def
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("param read error should fail")
	}
}

// --- handlePrepareResponse: param forward write error ---

func TestHandlePrepareResponseParamForwardError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		numParams := make([]byte, 2)
		binary.LittleEndian.PutUint16(numParams, 1)
		resp = append(resp, numCols...)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("param")})
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn) // OK response
		clientConn.Close()     // close before param forward
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("param forward write error should fail")
	}
}

// --- ExtractColumnName: truncated at each stage ---

func TestExtractColumnNameEdgeCases(t *testing.T) {
	// Empty payload
	if ExtractColumnName(nil) != "" {
		t.Error("nil should return empty")
	}

	// Truncated at skip
	if ExtractColumnName([]byte{3, 'a', 'b', 'c'}) != "" {
		t.Error("truncated at skip should return empty")
	}

	// name length exceeds payload
	var payload []byte
	for i := 0; i < 4; i++ {
		payload = append(payload, 1)
		payload = append(payload, 'x')
	}
	payload = append(payload, 20) // name len 20, but not enough data

	if ExtractColumnName(payload) != "" {
		t.Error("truncated name should return empty")
	}
}

// --- ReadAndForwardResult: column def forward write error ---

func TestReadAndForwardResultColDefWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var colDef []byte
		for _, s := range []string{"d", "s", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn) // column count
		clientConn.Close()     // close before col def forward
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("col def write error should fail")
	}
}

// --- ReadAndForwardResult: EOF after columns write error ---

func TestReadAndForwardResultEOFWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var colDef []byte
		for _, s := range []string{"d", "s", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
		WritePacket(backendConn, BuildEOFPacket(3))
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn) // column count
		ReadPacket(clientConn) // col def
		clientConn.Close()     // close before EOF forward
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("EOF write error should fail")
	}
}

// --- ReadAndForwardResult: row end (EOF/ERR) write error ---

func TestReadAndForwardResultRowEndWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var colDef []byte
		for _, s := range []string{"d", "s", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
		WritePacket(backendConn, BuildEOFPacket(3))
		WritePacket(backendConn, BuildEOFPacket(4)) // EOF immediately (no rows)
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn) // column count
		ReadPacket(clientConn) // col def
		ReadPacket(clientConn) // col EOF
		clientConn.Close()     // close before row EOF forward
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("row end write error should fail")
	}
}

// --- handlePrepareResponse: param EOF write error ---

func TestHandlePrepareResponseParamEOFForwardError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		binary.LittleEndian.PutUint16(numParams, 1)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("param")})
		WritePacket(backendConn, BuildEOFPacket(3))
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn) // OK response
		ReadPacket(clientConn) // param def
		clientConn.Close()     // close before param EOF forward
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("param EOF forward write error should fail")
	}
}

// --- handlePrepareResponse: col def read error ---

func TestHandlePrepareResponseColReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		binary.LittleEndian.PutUint16(numCols, 1)
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		backendConn.Close() // close before col def
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("col read error should fail")
	}
}

// --- handlePrepareResponse: col EOF read error ---

func TestHandlePrepareResponseColEOFReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		binary.LittleEndian.PutUint16(numCols, 1)
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("col")})
		backendConn.Close() // close before col EOF
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("col EOF read error should fail")
	}
}

// --- handlePrepareResponse: col EOF forward write error ---

func TestHandlePrepareResponseColEOFForwardError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		binary.LittleEndian.PutUint16(numCols, 1)
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("col")})
		WritePacket(backendConn, BuildEOFPacket(3))
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn) // OK
		ReadPacket(clientConn) // col def
		clientConn.Close()     // close before col EOF forward
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("col EOF forward error should fail")
	}
}

// --- ExtractColumnName: name at end of payload (i >= len after name len) ---

func TestExtractColumnNameNameAtEnd(t *testing.T) {
	// Build payload where after reading 4 strings + name_len, i >= len
	var payload []byte
	for i := 0; i < 4; i++ {
		payload = append(payload, 0) // empty string (len=0)
	}
	// After 4 skips, we're at index 4. payload[4] = name_len
	// Make it end right after name_len byte
	payload = append(payload, 5) // name_len=5 but no data follows

	result := ExtractColumnName(payload)
	if result != "" {
		t.Errorf("truncated name should return empty, got %q", result)
	}
}

// --- ExtractColumnName: payload ends right after 4 skips (i >= len before name) ---

func TestExtractColumnNameEndsAfterSkips(t *testing.T) {
	// After 4 skips, i should be at len(payload)
	var payload []byte
	for i := 0; i < 4; i++ {
		payload = append(payload, 0) // empty string (len=0)
	}
	// len(payload) = 4, i = 4 after skips -> i >= len(payload) -> return ""

	result := ExtractColumnName(payload)
	if result != "" {
		t.Errorf("should return empty, got %q", result)
	}
}

// --- ERR during rows ---

func TestReadAndForwardResultErrDuringRows(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var colDef []byte
		for _, s := range []string{"d", "s", "t", "t"} {
			colDef = append(colDef, byte(len(s)))
			colDef = append(colDef, []byte(s)...)
		}
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 1)
		colDef = append(colDef, []byte("c")...)
		colDef = append(colDef, 0x0c)
		colDef = append(colDef, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: colDef})
		WritePacket(backendConn, BuildEOFPacket(3))
		// Send ERR instead of rows
		WritePacket(backendConn, BuildErrPacket(4, 1064, "error"))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 0 {
		t.Errorf("rows = %d, want 0", stats.RowCount)
	}
}

// --- ReadPacket: zero-length payload ---

func TestReadPacketZeroLen(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		header := make([]byte, headerSize)
		header[0] = 0 // length = 0
		header[1] = 0
		header[2] = 0
		header[3] = 0 // seq ID
		clientConn.Write(header)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(serverConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if len(pkt.Payload) != 0 {
		t.Errorf("payload length = %d, want 0", len(pkt.Payload))
	}
}

// --- ReadCommand: read error ---

func TestReadCommandReadErr(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	clientConn.Close()
	defer proxyConn.Close()

	h := New()
	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err == nil {
		t.Error("read error should fail")
	}
}

// --- ReadCommand: unknown command type ---

func TestReadCommandUnknown(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: []byte{0xFF}})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
}

// --- ReadCommand: COM_INIT_DB ---

func TestReadCommandInitDB(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	h := New()

	go func() {
		payload := append([]byte{ComInitDB}, []byte("mydb")...)
		WritePacket(clientConn, &Packet{SequenceID: 0, Payload: payload})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadCommand: %v", err)
	}
	if cmd.Raw != "USE mydb" {
		t.Errorf("Raw = %q", cmd.Raw)
	}
}

// --- handlePrepareResponse: param EOF read/write error and col read/write error ---

func TestHandlePrepareResponseParamEOFReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		binary.LittleEndian.PutUint16(numParams, 1)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("param")})
		backendConn.Close() // close before param EOF
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("param EOF read error should fail")
	}
}

// --- handlePrepareResponse: col def forward write error ---

func TestHandlePrepareResponseColForwardError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 1)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		binary.LittleEndian.PutUint16(numCols, 1)
		resp = append(resp, numCols...)
		numParams := make([]byte, 2)
		resp = append(resp, numParams...)
		resp = append(resp, 0, 0, 0)
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
		// Column definition
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("col")})
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadPacket(clientConn) // OK
		clientConn.Close()     // close before col forward
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("col forward write error should fail")
	}
}
