package pg

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/scram"
)

// pipePair returns a connected net.Pipe pair with deadlines applied to both
// ends so a broken test fails fast instead of hanging.
func pipePair(t *testing.T, d time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(d)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}

// saslInitialPayload builds a protocol-correct SASLInitialResponse:
// mechanism NUL int32-length client-first.
func saslInitialPayload(mechanism, clientFirst string) []byte {
	payload := append([]byte(mechanism), 0)
	n := len(clientFirst)
	payload = append(payload, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return append(payload, []byte(clientFirst)...)
}

// authTypeOf extracts the big-endian auth type from an Auth message payload.
func authTypeOf(t *testing.T, msg *Message) int32 {
	t.Helper()
	if msg.Type != MsgAuth {
		t.Fatalf("expected MsgAuth, got %c", msg.Type)
	}
	at, err := parseAuthType(msg.Payload)
	if err != nil {
		t.Fatalf("parseAuthType: %v", err)
	}
	return at
}

// buildAuthMsg builds an Auth ('R') message with the given auth type and body.
func buildAuthMsg(at int32, body string) *Message {
	payload := []byte{byte(at >> 24), byte(at >> 16), byte(at >> 8), byte(at)}
	payload = append(payload, []byte(body)...)
	return &Message{Type: MsgAuth, Payload: payload}
}

// --- ProxyAuthServer <-> ProxyAuthClient loopback ---

func TestProxyAuthLoopbackSuccess(t *testing.T) {
	serverSide, clientSide := pipePair(t, 5*time.Second)

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- ProxyAuthServer(context.Background(), serverSide, "secret")
	}()

	if err := ProxyAuthClient(context.Background(), clientSide, "secret"); err != nil {
		t.Fatalf("ProxyAuthClient: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("ProxyAuthServer: %v", err)
	}
}

func TestProxyAuthLoopbackWrongPassword(t *testing.T) {
	serverSide, clientSide := pipePair(t, 5*time.Second)

	srvErr := make(chan error, 1)
	go func() {
		srvErr <- ProxyAuthServer(context.Background(), serverSide, "correct")
	}()

	cliErr := ProxyAuthClient(context.Background(), clientSide, "wrong")
	if cliErr == nil {
		t.Error("client should fail with wrong password")
	}
	if err := <-srvErr; err == nil {
		t.Error("server should reject wrong password")
	} else if !strings.Contains(err.Error(), "client auth failed") {
		t.Errorf("unexpected server error: %v", err)
	}
}

// --- ProxyAuthServer error branches ---

func TestProxyAuthServerReadInitialError(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		// Consume the AuthSASL request, then close without answering.
		ReadMessage(clientSide)
		clientSide.Close()
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "reading SASL") {
		t.Errorf("expected reading SASL error, got %v", err)
	}
}

func TestProxyAuthServerNonPasswordInitial(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		ReadMessage(clientSide)
		WriteMessage(clientSide, &Message{Type: MsgQuery, Payload: []byte("SELECT 1\x00")})
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "expected PasswordMessage") {
		t.Errorf("expected PasswordMessage error, got %v", err)
	}
}

func TestProxyAuthServerUnsupportedMechanism(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		ReadMessage(clientSide)
		payload := append([]byte("PLAIN"), 0)
		payload = append(payload, []byte("whatever")...)
		WriteMessage(clientSide, &Message{Type: MsgPassword, Payload: payload})
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected unsupported mechanism error, got %v", err)
	}
}

func TestProxyAuthServerMissingNonce(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		ReadMessage(clientSide)
		// Valid mechanism but a client-first without any r= nonce attribute.
		WriteMessage(clientSide, &Message{Type: MsgPassword, Payload: saslInitialPayload("SCRAM-SHA-256", "n,,n=user")})
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "ServerFirst") {
		t.Errorf("expected ServerFirst error, got %v", err)
	}
}

func TestProxyAuthServerInitialResponseTooShort(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		ReadMessage(clientSide)
		// Mechanism followed by fewer than 4 length bytes.
		payload := append([]byte("SCRAM-SHA-256"), 0, 0, 0)
		WriteMessage(clientSide, &Message{Type: MsgPassword, Payload: payload})
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "SASL initial response too short") {
		t.Errorf("expected too-short error, got %v", err)
	}
}

func TestProxyAuthServerInitialResponseLengthMismatch(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		ReadMessage(clientSide)
		payload := append([]byte("SCRAM-SHA-256"), 0)
		payload = append(payload, 0, 0, 0, 99) // claims 99 bytes
		payload = append(payload, []byte("n,,n=user,r=nonce")...)
		WriteMessage(clientSide, &Message{Type: MsgPassword, Payload: payload})
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "does not match payload") {
		t.Errorf("expected length mismatch error, got %v", err)
	}
}

func TestProxyAuthServerReadFinalError(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		ReadMessage(clientSide) // AuthSASL
		WriteMessage(clientSide, &Message{Type: MsgPassword, Payload: saslInitialPayload("SCRAM-SHA-256", "n,,n=user,r=clientnonce")})
		ReadMessage(clientSide) // SASL continue
		clientSide.Close()      // die before sending client-final
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "reading client final") {
		t.Errorf("expected reading client final error, got %v", err)
	}
}

func TestProxyAuthServerNonPasswordFinal(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)

	go func() {
		ReadMessage(clientSide) // AuthSASL
		WriteMessage(clientSide, &Message{Type: MsgPassword, Payload: saslInitialPayload("SCRAM-SHA-256", "n,,n=user,r=clientnonce")})
		ReadMessage(clientSide) // SASL continue
		WriteMessage(clientSide, &Message{Type: MsgTerminate, Payload: nil})
	}()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "expected PasswordMessage") {
		t.Errorf("expected PasswordMessage error, got %v", err)
	}
}

func TestProxyAuthServerSendSASLError(t *testing.T) {
	serverSide, clientSide := pipePair(t, 2*time.Second)
	clientSide.Close()
	serverSide.Close()

	err := ProxyAuthServer(context.Background(), serverSide, "pw")
	if err == nil || !strings.Contains(err.Error(), "sending SASL") {
		t.Errorf("expected sending SASL error, got %v", err)
	}
}

// --- ProxyAuthClient error branches ---

func TestProxyAuthClientAuthOKImmediate(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthMsg(AuthOK, ""))
	}()

	if err := ProxyAuthClient(context.Background(), proxySide, "pw"); err != nil {
		t.Errorf("AuthOK should succeed immediately: %v", err)
	}
}

func TestProxyAuthClientReadAuthError(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)
	backendSide.Close()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "reading auth") {
		t.Errorf("expected reading auth error, got %v", err)
	}
}

func TestProxyAuthClientNonAuthMessage(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, &Message{Type: MsgNoticeResponse, Payload: []byte{0}})
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "expected Auth") {
		t.Errorf("expected Auth error, got %v", err)
	}
}

func TestProxyAuthClientCleartext(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	done := make(chan *Message, 1)
	go func() {
		WriteMessage(backendSide, buildAuthMsg(AuthCleartextPwd, ""))
		pm, err := ReadMessage(backendSide)
		if err != nil {
			done <- nil
			return
		}
		done <- pm
	}()

	if err := ProxyAuthClient(context.Background(), proxySide, "hunter2"); err != nil {
		t.Fatalf("cleartext auth: %v", err)
	}
	pm := <-done
	if pm == nil {
		t.Fatal("backend did not receive password message")
	}
	if pm.Type != MsgPassword {
		t.Errorf("expected PasswordMessage, got %c", pm.Type)
	}
	if string(pm.Payload) != "hunter2\x00" {
		t.Errorf("unexpected password payload: %q", string(pm.Payload))
	}
}

func TestProxyAuthClientUnhandledTypeThenAuthOK(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		// MD5 is not handled by the switch; client falls through to reading AuthOK.
		WriteMessage(backendSide, buildAuthMsg(AuthMD5Pwd, "salt"))
		WriteMessage(backendSide, buildAuthMsg(AuthOK, ""))
	}()

	if err := ProxyAuthClient(context.Background(), proxySide, "pw"); err != nil {
		t.Errorf("unhandled type followed by AuthOK should succeed: %v", err)
	}
}

func TestProxyAuthClientUnexpectedFinalAuthType(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthMsg(AuthMD5Pwd, "salt"))
		WriteMessage(backendSide, buildAuthMsg(AuthCleartextPwd, ""))
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "expected AuthOK") {
		t.Errorf("expected AuthOK error, got %v", err)
	}
}

func TestProxyAuthClientNonAuthAfterUnhandledType(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthMsg(AuthMD5Pwd, "salt"))
		// Non-Auth message after the switch is tolerated (returns nil).
		WriteMessage(backendSide, &Message{Type: MsgParameterStatus, Payload: []byte("k\x00v\x00")})
	}()

	if err := ProxyAuthClient(context.Background(), proxySide, "pw"); err != nil {
		t.Errorf("non-Auth trailing message should be tolerated: %v", err)
	}
}

func TestProxyAuthClientReadAuthOKError(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthMsg(AuthMD5Pwd, "salt"))
		backendSide.Close()
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "reading AuthOK") {
		t.Errorf("expected reading AuthOK error, got %v", err)
	}
}

// readSASLInitial reads the client's SASLInitialResponse from conn and
// returns the embedded client-first message (mechanism and length stripped).
func readSASLInitial(t *testing.T, conn net.Conn) string {
	t.Helper()
	msg, err := ReadMessage(conn)
	if err != nil {
		t.Errorf("reading SASL initial: %v", err)
		return ""
	}
	if msg.Type != MsgPassword {
		t.Errorf("expected PasswordMessage, got %c", msg.Type)
		return ""
	}
	pl := msg.Payload
	i := 0
	for i < len(pl) && pl[i] != 0 {
		i++
	}
	if string(pl[:i]) != "SCRAM-SHA-256" {
		t.Errorf("unexpected mechanism: %q", string(pl[:i]))
		return ""
	}
	if len(pl) < i+5 {
		t.Errorf("SASL initial too short: %d bytes", len(pl))
		return ""
	}
	return string(pl[i+5:]) // skip NUL + 4-byte length
}

func TestProxyAuthClientNotSASLContinue(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthSASL("SCRAM-SHA-256"))
		readSASLInitial(t, backendSide)
		// Reply with AuthOK instead of SASLContinue.
		WriteMessage(backendSide, buildAuthMsg(AuthOK, ""))
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "expected SASL continue") {
		t.Errorf("expected SASL continue error, got %v", err)
	}
}

func TestProxyAuthClientBadServerFirst(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthSASL("SCRAM-SHA-256"))
		readSASLInitial(t, backendSide)
		// SASLContinue with an unparseable server-first (no salt/iter).
		WriteMessage(backendSide, buildAuthSASLContinue("garbage"))
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "parsing server-first") {
		t.Errorf("expected parsing server-first error, got %v", err)
	}
}

func TestProxyAuthClientReadContinueError(t *testing.T) {
	backendSide, proxySide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthSASL("SCRAM-SHA-256"))
		readSASLInitial(t, backendSide)
		backendSide.Close()
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "reading SASL continue") {
		t.Errorf("expected reading SASL continue error, got %v", err)
	}
}

func TestProxyAuthClientNotSASLFinal(t *testing.T) {
	backendSide, proxySide := pipePair(t, 3*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthSASL("SCRAM-SHA-256"))
		cf := readSASLInitial(t, backendSide)
		srv := scram.NewServer("pw")
		sf, err := srv.ServerFirst(cf)
		if err != nil {
			t.Errorf("ServerFirst: %v", err)
			return
		}
		WriteMessage(backendSide, buildAuthSASLContinue(sf))
		ReadMessage(backendSide) // client-final
		// Reply with AuthOK instead of SASLFinal.
		WriteMessage(backendSide, buildAuthMsg(AuthOK, ""))
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "expected SASL final") {
		t.Errorf("expected SASL final error, got %v", err)
	}
}

func TestProxyAuthClientReadFinalError(t *testing.T) {
	backendSide, proxySide := pipePair(t, 3*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthSASL("SCRAM-SHA-256"))
		cf := readSASLInitial(t, backendSide)
		srv := scram.NewServer("pw")
		sf, err := srv.ServerFirst(cf)
		if err != nil {
			t.Errorf("ServerFirst: %v", err)
			return
		}
		WriteMessage(backendSide, buildAuthSASLContinue(sf))
		ReadMessage(backendSide) // client-final
		backendSide.Close()
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "reading SASL final") {
		t.Errorf("expected reading SASL final error, got %v", err)
	}
}

func TestProxyAuthClientServerSigMismatch(t *testing.T) {
	backendSide, proxySide := pipePair(t, 3*time.Second)

	go func() {
		WriteMessage(backendSide, buildAuthSASL("SCRAM-SHA-256"))
		cf := readSASLInitial(t, backendSide)
		srv := scram.NewServer("pw")
		sf, err := srv.ServerFirst(cf)
		if err != nil {
			t.Errorf("ServerFirst: %v", err)
			return
		}
		WriteMessage(backendSide, buildAuthSASLContinue(sf))
		ReadMessage(backendSide) // client-final
		// Forge a server-final with a wrong (but valid base64) signature.
		WriteMessage(backendSide, buildAuthSASLFinal("v=AAAA"))
	}()

	err := ProxyAuthClient(context.Background(), proxySide, "pw")
	if err == nil || !strings.Contains(err.Error(), "sig mismatch") {
		t.Errorf("expected sig mismatch error, got %v", err)
	}
}

// --- RelayPostAuthFromBackend ---

func TestRelayPostAuthFromBackendSuccess(t *testing.T) {
	backendSide, proxyBackend := pipePair(t, 3*time.Second)
	proxyClient, clientSide := pipePair(t, 3*time.Second)

	go func() {
		WriteMessage(backendSide, &Message{Type: MsgParameterStatus, Payload: []byte("server_version\x0016.0\x00")})
		WriteMessage(backendSide, &Message{Type: MsgBackendKeyData, Payload: []byte{0, 0, 0, 1, 0, 0, 0, 2}})
		WriteMessage(backendSide, &Message{Type: MsgNoticeResponse, Payload: []byte{0}})
		// Unknown type exercises the default branch (relay and continue).
		WriteMessage(backendSide, &Message{Type: MsgNoData, Payload: nil})
		WriteMessage(backendSide, BuildReadyForQuery('I'))
	}()

	var got []byte
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for i := 0; i < 5; i++ {
			msg, err := ReadMessage(clientSide)
			if err != nil {
				return
			}
			got = append(got, msg.Type)
		}
	}()

	if err := RelayPostAuthFromBackend(proxyBackend, proxyClient); err != nil {
		t.Fatalf("RelayPostAuthFromBackend: %v", err)
	}
	<-clientDone
	want := string([]byte{MsgParameterStatus, MsgBackendKeyData, MsgNoticeResponse, MsgNoData, MsgReadyForQuery})
	if string(got) != want {
		t.Errorf("relayed message types = %q, want %q", string(got), want)
	}
}

func TestRelayPostAuthFromBackendErrorResponse(t *testing.T) {
	backendSide, proxyBackend := pipePair(t, 2*time.Second)
	proxyClient, clientSide := pipePair(t, 2*time.Second)

	go func() {
		WriteMessage(backendSide, BuildErrorResponse("FATAL", "28000", "no pg_hba.conf entry"))
	}()
	go func() {
		ReadMessage(clientSide)
	}()

	err := RelayPostAuthFromBackend(proxyBackend, proxyClient)
	if err == nil || !strings.Contains(err.Error(), "no pg_hba.conf entry") {
		t.Errorf("expected post-auth error with backend message, got %v", err)
	}
}

func TestRelayPostAuthFromBackendReadError(t *testing.T) {
	backendSide, proxyBackend := pipePair(t, 2*time.Second)
	proxyClient, _ := pipePair(t, 2*time.Second)
	backendSide.Close()

	err := RelayPostAuthFromBackend(proxyBackend, proxyClient)
	if err == nil || !strings.Contains(err.Error(), "reading") {
		t.Errorf("expected reading error, got %v", err)
	}
}

func TestRelayPostAuthFromBackendWriteError(t *testing.T) {
	backendSide, proxyBackend := pipePair(t, 2*time.Second)
	proxyClient, clientSide := pipePair(t, 2*time.Second)
	clientSide.Close()
	proxyClient.Close()

	go func() {
		WriteMessage(backendSide, BuildReadyForQuery('I'))
	}()

	err := RelayPostAuthFromBackend(proxyBackend, proxyClient)
	if err == nil || !strings.Contains(err.Error(), "writing") {
		t.Errorf("expected writing error, got %v", err)
	}
}
