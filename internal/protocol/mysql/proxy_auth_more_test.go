package mysql

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProxyAuthServerAndValidate(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	secret := "proxy-shared-secret"

	// Client: read greeting → extract scramble → send HandshakeResponse41
	go func() {
		g, err := ReadPacket(clientConn)
		if err != nil {
			return
		}
		scramble := extractScramble(g.Payload)
		ar := mysqlNativePassword(secret, scramble)
		WritePacket(clientConn, buildClientResponse("alice", "appdb", ar))
		ReadPacket(clientConn) // OK after validation
	}()

	serverConn.SetDeadline(time.Now().Add(3 * time.Second))

	h, err := ProxyAuthServer(serverConn)
	if err != nil {
		t.Fatalf("ProxyAuthServer: %v", err)
	}
	if h.Response.Username != "alice" {
		t.Errorf("username = %q", h.Response.Username)
	}
	if h.Response.Database != "appdb" {
		t.Errorf("database = %q", h.Response.Database)
	}
	if err := h.ValidateClientSecret(serverConn, secret); err != nil {
		t.Fatalf("ValidateClientSecret: %v", err)
	}
	WritePacket(serverConn, BuildOKPacket(2, 0, 0))
}

func TestProxyAuthServerGreetingWriteError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientConn.Close()
	serverConn.Close()

	if _, err := ProxyAuthServer(serverConn); err == nil {
		t.Fatal("should fail writing greeting to closed conn")
	}
}

func TestProxyAuthServerHandshakeReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	// Client: consume greeting, then close without responding
	go func() {
		ReadPacket(clientConn)
		clientConn.Close()
	}()

	serverConn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := ProxyAuthServer(serverConn); err == nil {
		t.Fatal("should fail reading handshake response")
	}
}

func TestProxyAuthServerParseError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Client: consume greeting, then send a too-short handshake response
	go func() {
		ReadPacket(clientConn)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: []byte{0x01, 0x02}})
	}()

	serverConn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := ProxyAuthServer(serverConn); err == nil {
		t.Fatal("should fail parsing short handshake response")
	}
}

func TestProxyAuthClientOK(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	// Backend: greeting → read response → OK
	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		rp, err := ReadPacket(backendConn)
		if err != nil {
			return
		}
		resp, err := ParseHandshakeResponse41(rp.Payload)
		if err != nil || resp.Username != "svc" || resp.Database != "orders" {
			WritePacket(backendConn, BuildErrPacket(2, 1045, "Access denied"))
			return
		}
		WritePacket(backendConn, BuildOKPacket(2, 0, 0))
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := ProxyAuthClient(proxyConn, "svc", "orders", "backend-pass"); err != nil {
		t.Fatalf("ProxyAuthClient: %v", err)
	}
}

func TestProxyAuthClientAuthError(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildErrPacket(2, 1045, "Access denied"))
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	err := ProxyAuthClient(proxyConn, "svc", "", "wrong")
	if err == nil {
		t.Fatal("should fail on ERR packet")
	}
	if !strings.Contains(err.Error(), "1045") {
		t.Errorf("error should carry code 1045, got %v", err)
	}
}

func TestProxyAuthClientEmptyResult(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: nil})
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := ProxyAuthClient(proxyConn, "svc", "", "pw"); err == nil {
		t.Fatal("should fail on empty result payload")
	}
}

func TestProxyAuthClientUnexpectedMarker(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x42}})
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	err := ProxyAuthClient(proxyConn, "svc", "", "pw")
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("should fail on unexpected marker, got %v", err)
	}
}

func TestProxyAuthClientGreetingReadError(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	backendConn.Close()
	defer proxyConn.Close()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := ProxyAuthClient(proxyConn, "svc", "", "pw"); err == nil {
		t.Fatal("should fail reading greeting from closed conn")
	}
}

func TestProxyAuthClientHandshakeWriteError(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()

	// Backend: send greeting, then close before the client can respond.
	// net.Pipe writes are synchronous, so the greeting is fully consumed
	// before Close and the client's handshake write hits a closed pipe.
	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		backendConn.Close()
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	err := ProxyAuthClient(proxyConn, "svc", "", "pw")
	if err == nil || !strings.Contains(err.Error(), "writing handshake") {
		t.Fatalf("should fail writing handshake response, got %v", err)
	}
}

func TestProxyAuthClientResultReadError(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		backendConn.Close()
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := ProxyAuthClient(proxyConn, "svc", "", "pw"); err == nil {
		t.Fatal("should fail reading auth result")
	}
}

func TestProxyAuthClientMoreDataNativeHash(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	got := make(chan []byte, 1)
	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x02}})
		rp, err := ReadPacket(backendConn)
		if err != nil {
			got <- nil
			return
		}
		got <- rp.Payload
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := ProxyAuthClient(proxyConn, "svc", "", "pw"); err != nil {
		t.Fatalf("more-data native hash: %v", err)
	}
	if payload := <-got; len(payload) != 20 {
		t.Errorf("scrambled hash length = %d, want 20", len(payload))
	}
}

func TestProxyAuthClientMoreDataCleartext(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	got := make(chan []byte, 1)
	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x03}})
		rp, err := ReadPacket(backendConn)
		if err != nil {
			got <- nil
			return
		}
		got <- rp.Payload
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	if err := ProxyAuthClient(proxyConn, "svc", "", "cleartext-pw"); err != nil {
		t.Fatalf("more-data cleartext: %v", err)
	}
	if payload := <-got; !bytes.Equal(payload, append([]byte("cleartext-pw"), 0)) {
		t.Errorf("cleartext payload = %x", payload)
	}
}

func TestProxyAuthClientMoreDataUnexpectedStage(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x09}})
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	err := ProxyAuthClient(proxyConn, "svc", "", "pw")
	if err == nil || !strings.Contains(err.Error(), "unexpected stage") {
		t.Fatalf("should fail on unexpected auth stage, got %v", err)
	}
}

func TestProxyAuthClientMoreDataTooShort(t *testing.T) {
	proxyConn, backendConn := net.Pipe()
	defer proxyConn.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(7, "8.0.35"))
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01}})
	}()

	proxyConn.SetDeadline(time.Now().Add(3 * time.Second))

	err := ProxyAuthClient(proxyConn, "svc", "", "pw")
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("should fail on truncated more-data packet, got %v", err)
	}
}

func TestBuildClientResponseNoDatabase(t *testing.T) {
	ar := mysqlNativePassword("pw", make([]byte, 20))
	pkt := buildClientResponse("bob", "", ar)

	resp, err := ParseHandshakeResponse41(pkt.Payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Username != "bob" {
		t.Errorf("username = %q", resp.Username)
	}
	if resp.Database != "" {
		t.Errorf("database = %q, want empty", resp.Database)
	}
	if resp.CapabilityFlags&clientConnectWithDB != 0 {
		t.Error("CONNECT_WITH_DB must not be set without a database")
	}
	if !bytes.Equal(resp.AuthResponse, ar) {
		t.Errorf("auth response = %x", resp.AuthResponse)
	}
}

func TestExtractScrambleTooShort(t *testing.T) {
	if s := extractScramble(make([]byte, 10)); s != nil {
		t.Errorf("short payload should yield nil, got %x", s)
	}
}

func TestExtractScrambleVersionOverrun(t *testing.T) {
	// 45-byte payload whose server version consumes so much that the
	// cursor lands past the end after the fixed-width fields.
	payload := []byte{10}
	payload = append(payload, bytes.Repeat([]byte{'x'}, 30)...)
	payload = append(payload, 0)
	payload = append(payload, make([]byte, 13)...) // pad to 45 bytes
	if len(payload) != 45 {
		t.Fatalf("test payload length = %d, want 45", len(payload))
	}
	if s := extractScramble(payload); s != nil {
		t.Errorf("overrun payload should yield nil, got %x", s)
	}
}

func TestExtractScrambleZeroAuthDataLen(t *testing.T) {
	// adl byte of 0 forces the pl<0 fallback (12) which is then clamped
	// to the remaining payload length.
	payload := []byte{10, 'v', 0}                    // version
	payload = append(payload, 1, 0, 0, 0)            // connection ID
	payload = append(payload, []byte("ABCDEFGH")...) // scramble part 1
	payload = append(payload, make([]byte, 8)...)    // filler, caps, charset, status, caps hi
	payload = append(payload, 0)                     // auth data length = 0
	payload = append(payload, make([]byte, 45-len(payload))...)
	if len(payload) != 45 {
		t.Fatalf("test payload length = %d, want 45", len(payload))
	}
	s := extractScramble(payload)
	if len(s) != 19 {
		t.Fatalf("scramble length = %d, want 19 (8 + clamped 11)", len(s))
	}
	if !bytes.Equal(s[:8], []byte("ABCDEFGH")) {
		t.Errorf("scramble part 1 = %q", s[:8])
	}
}

func TestExtractScrambleUnterminatedVersion(t *testing.T) {
	// A greeting whose server-version string never NUL-terminates used to
	// slice past the payload end and panic.
	payload := append([]byte{10}, bytes.Repeat([]byte{'x'}, 44)...)
	if len(payload) != 45 {
		t.Fatalf("test payload length = %d, want 45", len(payload))
	}
	if s := extractScramble(payload); s != nil {
		t.Errorf("unterminated version should yield nil, got %x", s)
	}
}

func TestExtractScrambleAuthLenAtLastByte(t *testing.T) {
	// When the auth-data-length byte is the final payload byte, the cursor
	// lands past the end after the 10-byte reserved skip; this used to panic.
	payload := []byte{10}
	payload = append(payload, bytes.Repeat([]byte{'v'}, 22)...) // version
	payload = append(payload, 0)                                // NUL
	payload = append(payload, 1, 0, 0, 0)                       // connection ID
	payload = append(payload, []byte("ABCDEFGH")...)            // scramble part 1
	payload = append(payload, make([]byte, 8)...)               // filler..caps hi
	payload = append(payload, 0)                                // adl as last byte
	if len(payload) != 45 {
		t.Fatalf("test payload length = %d, want 45", len(payload))
	}
	s := extractScramble(payload)
	if !bytes.Equal(s, []byte("ABCDEFGH")) {
		t.Errorf("scramble = %q, want part 1 only", s)
	}
}

func TestConstTimeEqBranches(t *testing.T) {
	if constTimeEq([]byte{1, 2}, []byte{1, 2, 3}) {
		t.Error("length mismatch should not be equal")
	}
	if constTimeEq([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("differing bytes should not be equal")
	}
	if !constTimeEq(nil, nil) {
		t.Error("nil slices should be equal")
	}
}

func TestValidateClientSecretNilStates(t *testing.T) {
	var h *ProxyHandshake
	if err := h.ValidateClientSecret(nil, "secret"); err == nil {
		t.Error("nil handshake should be rejected")
	}
	h = &ProxyHandshake{}
	if err := h.ValidateClientSecret(nil, "secret"); err == nil {
		t.Error("nil response should be rejected")
	}
}

func TestValidateClientSecretDenialWriteError(t *testing.T) {
	scramble := []byte("01234567890123456789")
	h := &ProxyHandshake{
		Response: &HandshakeResponse{AuthResponse: mysqlNativePassword("right", scramble)},
		scramble: scramble,
	}

	clientConn, serverConn := net.Pipe()
	clientConn.Close()
	serverConn.Close()

	err := h.ValidateClientSecret(serverConn, "wrong")
	if err == nil {
		t.Fatal("wrong secret with closed conn should error")
	}
	if !strings.Contains(err.Error(), "writing access denied") {
		t.Errorf("expected denial write error, got %v", err)
	}
}
