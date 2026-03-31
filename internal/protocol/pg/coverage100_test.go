package pg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

// --- BuildSimpleQuery coverage ---

func TestBuildSimpleQuery(t *testing.T) {
	msg := BuildSimpleQuery("SELECT 1")
	if msg.Type != MsgQuery {
		t.Errorf("type = %c, want Q", msg.Type)
	}
	// Payload should be "SELECT 1\0"
	expected := append([]byte("SELECT 1"), 0)
	if string(msg.Payload) != string(expected) {
		t.Errorf("payload = %q, want %q", msg.Payload, expected)
	}
}

// --- DoHandshakeWithOpts: SSL 'S' accept + TLS handshake path ---

func selfSignedTLSConfig() *tls.Config {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func TestDoHandshakeWithOptsSSLAcceptTLS(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	tlsCfg := selfSignedTLSConfig()
	opts := &HandshakeOpts{ServerTLS: tlsCfg}

	go func() {
		// Client: send SSL request
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], SSLRequestCode)
		clientConn.Write(sslReq)

		// Read 'S' response
		buf := make([]byte, 1)
		clientConn.Read(buf)
		if buf[0] != 'S' {
			return
		}

		// Upgrade to TLS
		tlsClient := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsClient.Handshake(); err != nil {
			return
		}

		// Send real startup over TLS
		startup := BuildStartupMessage(map[string]string{"user": "ssl_user", "database": "ssldb"})
		tlsClient.Write(startup)

		// Read auth messages
		for {
			tlsClient.SetReadDeadline(time.Now().Add(2 * time.Second))
			msg, err := ReadMessage(tlsClient)
			if err != nil || msg.Type == MsgReadyForQuery {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		ReadStartupMessage(backendConn)

		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	proxyClient.SetDeadline(time.Now().Add(5 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(5 * time.Second))

	info, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, opts)
	if err != nil {
		t.Fatalf("DoHandshakeWithOpts with TLS: %v", err)
	}
	if info.Username != "ssl_user" {
		t.Errorf("username = %q, want ssl_user", info.Username)
	}
}

// --- DoHandshakeWithOpts: SSL accept write error ---

func TestDoHandshakeWithOptsSSLAcceptWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	go func() {
		// Send SSL request then close immediately
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], SSLRequestCode)
		clientConn.Write(sslReq)
		clientConn.Close() // close before we can write 'S'
	}()

	time.Sleep(50 * time.Millisecond)

	tlsCfg := selfSignedTLSConfig()
	opts := &HandshakeOpts{ServerTLS: tlsCfg}

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, opts)
	proxyClient.Close()
	if err == nil {
		t.Error("SSL accept write to closed conn should fail")
	}
}

// --- DoHandshakeWithOpts: TLS handshake failure ---

func TestDoHandshakeWithOptsTLSHandshakeFailure(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	go func() {
		// Send SSL request
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], SSLRequestCode)
		clientConn.Write(sslReq)

		// Read 'S' response
		buf := make([]byte, 1)
		clientConn.Read(buf)

		// Send garbage instead of TLS ClientHello
		clientConn.Write([]byte("this is not a TLS handshake"))
		clientConn.Close()
	}()

	tlsCfg := selfSignedTLSConfig()
	opts := &HandshakeOpts{ServerTLS: tlsCfg}

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, opts)
	proxyClient.Close()
	if err == nil {
		t.Error("bad TLS handshake should fail")
	}
}

// --- DoHandshakeWithOpts: SSL reject ('N') write error ---

func TestDoHandshakeWithOptsSSLRejectWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	go func() {
		// Send SSL request then close
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], SSLRequestCode)
		clientConn.Write(sslReq)
		clientConn.Close()
	}()

	time.Sleep(50 * time.Millisecond)

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	proxyClient.Close()
	if err == nil {
		t.Error("SSL reject write to closed conn should fail")
	}
}

// --- DoHandshakeWithOpts: post-SSL startup read error ---

func TestDoHandshakeWithOptsPostSSLStartupReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	go func() {
		// Send SSL request
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], SSLRequestCode)
		clientConn.Write(sslReq)

		// Read 'N' response
		buf := make([]byte, 1)
		clientConn.Read(buf)

		// Close without sending another startup
		clientConn.Close()
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	proxyClient.Close()
	if err == nil {
		t.Error("post-SSL startup read from closed conn should fail")
	}
}

// --- DoHandshakeWithOpts: post-SSL startup parse error ---

func TestDoHandshakeWithOptsPostSSLStartupParseError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	go func() {
		// Send SSL request
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], SSLRequestCode)
		clientConn.Write(sslReq)

		// Read 'N' response
		buf := make([]byte, 1)
		clientConn.Read(buf)

		// Send too-short startup message (length says 5, but only 1 byte payload = total 5)
		msg := make([]byte, 5)
		binary.BigEndian.PutUint32(msg[0:4], 5) // length = 5
		msg[4] = 0xFF                            // 1 byte payload
		clientConn.Write(msg)
		clientConn.Close()
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	proxyClient.Close()
	if err == nil {
		t.Error("post-SSL startup parse error should fail")
	}
}

// --- relayAuth: forwarding AuthOK write error ---

func TestRelayAuthForwardAuthOKWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		// Close client before AuthOK arrives
		clientConn.Close()
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send AuthOK — but client is closed so forward will fail
		time.Sleep(100 * time.Millisecond)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("forwarding AuthOK to closed client should fail")
	}
}

// --- relayAuth: forwarding client auth response to backend write error ---

func TestRelayAuthForwardClientResponseWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)

		// Read cleartext auth request
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(clientConn)

		// Send password response
		WriteMessage(clientConn, &Message{Type: MsgPassword, Payload: []byte("secret")})
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send cleartext password request
		authPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(authPayload, uint32(AuthCleartextPwd))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authPayload})

		// Close backend before receiving client password
		time.Sleep(100 * time.Millisecond)
		backendConn.Close()
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("forwarding client auth response to closed backend should fail")
	}
}

// --- relayAuth: auth payload too short ---

func TestRelayAuthPayloadTooShort(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		for {
			clientConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send auth message with too-short payload (< 4 bytes)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: []byte{0, 0}})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("short auth payload should fail")
	}
}

// --- relayAuth: error response forwarding write error ---

func TestRelayAuthErrorResponseForwardWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		clientConn.Close() // close before error arrives
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		time.Sleep(100 * time.Millisecond)
		// Send error response
		errMsg := BuildErrorResponse("FATAL", "28000", "auth failed")
		WriteMessage(backendConn, errMsg)
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("forwarding auth error to closed client should fail")
	}
}

// --- relayAuth: backend read error ---

func TestRelayAuthBackendReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		for {
			clientConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)
		backendConn.Close() // close without sending auth
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("backend read error during auth should fail")
	}
}

// --- relayPostAuth: forwarding post-auth message write error ---

func TestRelayPostAuthWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)

		// Read AuthOK then close
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(clientConn) // AuthOK
		clientConn.Close()      // close before ParameterStatus
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// AuthOK
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		time.Sleep(100 * time.Millisecond)
		// ParameterStatus — should fail to write to closed client
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("forwarding post-auth message to closed client should fail")
	}
}

// --- relayPostAuth: backend read error ---

func TestRelayPostAuthBackendReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send AuthOK
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		// Close backend during post-auth
		backendConn.Close()
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("backend read error during post-auth should fail")
	}
}

// --- ParseStartupMessage: key without value (valEnd reaches end) ---

func TestParseStartupMessageKeyWithoutValue(t *testing.T) {
	// Build message: length + version + key\0 + value-no-null-terminator
	var data []byte
	lenBuf := make([]byte, 4)
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, 0x00030000) // v3.0
	data = append(data, lenBuf...)
	data = append(data, versionBuf...)
	data = append(data, []byte("user")...)
	data = append(data, 0) // key null term
	data = append(data, []byte("test")...)
	// No null terminator for value — valEnd == len(payload)
	binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}
	if startup.Parameters["user"] != "test" {
		t.Errorf("user = %q, want test", startup.Parameters["user"])
	}
}

// --- ParseStartupMessage: key reaches end without null (keyEnd >= len) ---

func TestParseStartupMessageKeyNoNull(t *testing.T) {
	// Build message where key has no null terminator
	var data []byte
	lenBuf := make([]byte, 4)
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, 0x00030000)
	data = append(data, lenBuf...)
	data = append(data, versionBuf...)
	data = append(data, []byte("user")...) // key without null
	binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}
	// Should have no parameters — key parse breaks
	if len(startup.Parameters) != 0 {
		t.Errorf("parameters = %v, want empty", startup.Parameters)
	}
}

// --- ParseRowDescription: truncated at column metadata ---

func TestParseRowDescriptionTruncatedMeta(t *testing.T) {
	// Column name is fine but metadata is truncated
	var payload []byte
	payload = append(payload, 0, 1) // 1 column
	payload = append(payload, []byte("col")...)
	payload = append(payload, 0)    // null term
	// Only 10 bytes of metadata instead of 18
	payload = append(payload, make([]byte, 10)...)

	_, err := ParseRowDescription(payload)
	if err == nil {
		t.Error("truncated column metadata should fail")
	}
}

// --- ParseDataRow: truncated at field length ---

func TestParseDataRowTruncatedFieldLength(t *testing.T) {
	// 1 field but not enough bytes for length
	var payload []byte
	payload = append(payload, 0, 1) // 1 field
	payload = append(payload, 0, 0) // only 2 bytes, need 4 for length

	_, err := ParseDataRow(payload)
	if err == nil {
		t.Error("truncated field length should fail")
	}
}

// --- DecodeParse: no parameter data (valid, returns msg with query only) ---

func TestDecodeParseNoParams(t *testing.T) {
	// stmt_name\0 + query\0 (no param count)
	var payload []byte
	payload = append(payload, []byte("stmt")...)
	payload = append(payload, 0)
	payload = append(payload, []byte("SELECT 1")...)
	payload = append(payload, 0)
	// No num_params — should return with no params

	msg, err := DecodeParse(payload)
	if err != nil {
		t.Fatalf("DecodeParse: %v", err)
	}
	if msg.StatementName != "stmt" {
		t.Errorf("stmt name = %q", msg.StatementName)
	}
	if msg.Query != "SELECT 1" {
		t.Errorf("query = %q", msg.Query)
	}
	if len(msg.ParamOIDs) != 0 {
		t.Errorf("params = %v", msg.ParamOIDs)
	}
}

// --- DecodeBind: no null terminator for statement name ---

func TestDecodeBindNoStmtTerminator(t *testing.T) {
	// portal\0 + stmt (no null terminator)
	var payload []byte
	payload = append(payload, 0)                        // empty portal
	payload = append(payload, []byte("my_statement")...) // no null term
	_, err := DecodeBind(payload)
	if err == nil {
		t.Error("missing stmt name terminator should fail")
	}
}

// --- ReadQueryCommand: Terminate message ---

func TestReadQueryCommandTerminate(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		WriteMessage(clientConn, &Message{Type: MsgTerminate, Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	cmd, rawMsg, err := ReadQueryCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadQueryCommand: %v", err)
	}
	if cmd != nil {
		t.Error("terminate should return nil command")
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg should not be empty")
	}
}

// --- ReadQueryCommand: read error ---

func TestReadQueryCommandReadError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	clientConn.Close()
	defer proxyConn.Close()

	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err := ReadQueryCommand(context.Background(), proxyConn)
	if err == nil {
		t.Error("read from closed conn should fail")
	}
}

// --- readExtendedBatch: Terminate message during batch ---

func TestReadExtendedBatchTerminateMsg(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		// Send Bind followed by Terminate (not Sync)
		var bindPayload []byte
		bindPayload = append(bindPayload, 0)  // portal
		bindPayload = append(bindPayload, 0)  // stmt
		bindPayload = append(bindPayload, 0, 0) // format codes
		bindPayload = append(bindPayload, 0, 0) // params
		bindPayload = append(bindPayload, 0, 0) // result formats
		WriteMessage(clientConn, &Message{Type: 'B', Payload: bindPayload})
		WriteMessage(clientConn, &Message{Type: MsgTerminate, Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	first, _ := ReadMessage(proxyConn)
	batch, err := readExtendedBatch(context.Background(), proxyConn, first)
	if err != nil {
		t.Fatalf("readExtendedBatch: %v", err)
	}
	// Should terminate with Terminate message
	if len(batch.Messages) != 2 {
		t.Errorf("messages = %d, want 2", len(batch.Messages))
	}
}

// --- readExtendedBatch: Flush terminates batch ---

func TestReadExtendedBatchFlush(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		var parsePayload []byte
		parsePayload = append(parsePayload, 0)
		parsePayload = append(parsePayload, []byte("SELECT 1")...)
		parsePayload = append(parsePayload, 0)
		parsePayload = append(parsePayload, 0, 0)
		WriteMessage(clientConn, &Message{Type: MsgParse, Payload: parsePayload})
		WriteMessage(clientConn, &Message{Type: MsgFlush, Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	first, _ := ReadMessage(proxyConn)
	batch, err := readExtendedBatch(context.Background(), proxyConn, first)
	if err != nil {
		t.Fatalf("readExtendedBatch: %v", err)
	}
	if batch.SQL != "SELECT 1" {
		t.Errorf("SQL = %q", batch.SQL)
	}
}

// --- readExtendedBatch: read error ---

func TestReadExtendedBatchReadError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer proxyConn.Close()

	go func() {
		var parsePayload []byte
		parsePayload = append(parsePayload, 0)
		parsePayload = append(parsePayload, []byte("SELECT 1")...)
		parsePayload = append(parsePayload, 0)
		parsePayload = append(parsePayload, 0, 0)
		WriteMessage(clientConn, &Message{Type: MsgParse, Payload: parsePayload})
		clientConn.Close() // close before Sync
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	first, _ := ReadMessage(proxyConn)
	_, err := readExtendedBatch(context.Background(), proxyConn, first)
	if err == nil {
		t.Error("read error during batch should fail")
	}
}

// --- readExtendedBatch: Bind with empty statement and no SQL ---

func TestReadExtendedBatchBindEmptyStmt(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		// Bind with empty portal and empty statement
		var bindPayload []byte
		bindPayload = append(bindPayload, 0)    // empty portal
		bindPayload = append(bindPayload, 0)    // empty stmt
		bindPayload = append(bindPayload, 0, 0) // format codes
		bindPayload = append(bindPayload, 0, 0) // params
		bindPayload = append(bindPayload, 0, 0) // result formats
		WriteMessage(clientConn, &Message{Type: 'B', Payload: bindPayload})
		WriteMessage(clientConn, &Message{Type: 'S', Payload: nil}) // Sync
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	first, _ := ReadMessage(proxyConn)
	batch, err := readExtendedBatch(context.Background(), proxyConn, first)
	if err != nil {
		t.Fatalf("readExtendedBatch: %v", err)
	}
	// Empty statement name, SQL should remain empty
	if batch.SQL != "" {
		t.Errorf("SQL = %q, want empty", batch.SQL)
	}
}

// --- ForwardResult: CopyIn handle error (after successful write of CopyInResponse) ---

func TestForwardResultCopyInHandleError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()

	go func() {
		// Send CopyInResponse
		WriteMessage(backendConn, &Message{Type: MsgCopyInResponse, Payload: []byte{0, 0, 1, 0, 0}})
	}()

	go func() {
		// Client reads CopyInResponse then closes
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(clientConn) // CopyInResponse
		clientConn.Close()      // close so HandleCopyIn fails
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("CopyIn handle error should fail")
	}
}

// --- ForwardResult: CopyOut handle error (after successful write of CopyOutResponse) ---

func TestForwardResultCopyOutHandleError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()

	go func() {
		// Send CopyOutResponse, then close backend so HandleCopyOut fails
		WriteMessage(backendConn, &Message{Type: MsgCopyOutResponse, Payload: []byte{0, 0, 1, 0, 0}})
		backendConn.Close()
	}()

	go func() {
		// Client reads all forwarded messages
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("CopyOut handle error should fail")
	}
}

// --- ForwardResult: masked DataRow write error ---

func TestForwardResultMaskedDataRowWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		// RowDescription
		var rd []byte
		rd = append(rd, 0, 1)
		rd = append(rd, []byte("email")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})

		// DataRow
		WriteMessage(backendConn, BuildDataRow([][]byte{[]byte("alice@test.com")}))
	}()

	go func() {
		// Read RowDescription then close
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(clientConn)
		clientConn.Close()
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "email", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "email", Index: 0}}, 0)

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err == nil {
		t.Error("masked DataRow write error should fail")
	}
}

// --- ForwardResult: unparseable DataRow forwarding write error with masking ---

func TestForwardResultDataRowParseErrorWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		var rd []byte
		rd = append(rd, 0, 1)
		rd = append(rd, []byte("email")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})

		// Malformed DataRow
		WriteMessage(backendConn, &Message{Type: MsgDataRow, Payload: []byte{0xFF}})
	}()

	go func() {
		// Read RowDescription then close
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(clientConn)
		clientConn.Close()
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "email", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "email", Index: 0}}, 0)

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err == nil {
		t.Error("DataRow parse error + write error should fail")
	}
}

// --- ForwardResult: RowDescription write error with masking pipeline ---

func TestForwardResultRowDescWriteErrorWithPipeline(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	go func() {
		var rd []byte
		rd = append(rd, 0, 1)
		rd = append(rd, []byte("email")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	rules := []policy.MaskingRule{{Column: "email", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "email", Index: 0}}, 0)

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err == nil {
		t.Error("RowDescription write error with pipeline should fail")
	}
}

// --- ForwardResult: RowDescription parse error write error (no pipeline but bad RD) ---

func TestForwardResultRowDescParseErrorWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	go func() {
		// Malformed RowDescription
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: []byte{0xFF}})
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	rules := []policy.MaskingRule{{Column: "x", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, nil, 0)

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err == nil {
		t.Error("RowDescription parse + write error should fail")
	}
}

// --- ForwardResult: unknown message write error ---

func TestForwardResultUnknownMsgWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	go func() {
		WriteMessage(backendConn, &Message{Type: 'Y', Payload: []byte{1, 2, 3}})
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("unknown message write error should fail")
	}
}

// --- ParseStartupMessage: too short ---

func TestParseStartupMessageTooShort(t *testing.T) {
	_, err := ParseStartupMessage([]byte{0, 0, 0})
	if err == nil {
		t.Error("too short startup should fail")
	}
}

// --- ParseStartupMessage: empty key (key == "") triggers break ---

func TestParseStartupMessageEmptyKey(t *testing.T) {
	var data []byte
	lenBuf := make([]byte, 4)
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, 0x00030000)
	data = append(data, lenBuf...)
	data = append(data, versionBuf...)
	// key "user" + value "test"
	data = append(data, []byte("user")...)
	data = append(data, 0)
	data = append(data, []byte("test")...)
	data = append(data, 0)
	// Empty key (just null byte) -> break
	data = append(data, 0)
	// Extra trailing data
	data = append(data, 0)
	binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}
	if startup.Parameters["user"] != "test" {
		t.Errorf("user = %q", startup.Parameters["user"])
	}
}

// --- ParseStartupMessage: valEnd > len(payload) — impossible in normal flow but construct it ---

func TestParseStartupMessageValEndOverflow(t *testing.T) {
	// Build a message where value has no null terminator and valEnd reaches exactly len
	var data []byte
	lenBuf := make([]byte, 4)
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, 0x00030000)
	data = append(data, lenBuf...)
	data = append(data, versionBuf...)
	data = append(data, []byte("k")...)
	data = append(data, 0)
	// Value without null terminator at the end
	data = append(data, []byte("v")...)
	// Add another null then empty key to terminate
	data = append(data, 0)
	data = append(data, 0) // empty key -> break
	binary.BigEndian.PutUint32(data[0:4], uint32(len(data)))

	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}
	if startup.Parameters["k"] != "v" {
		t.Errorf("k = %q", startup.Parameters["k"])
	}
}

// --- DoHandshakeWithOpts: first startup parse error ---

func TestDoHandshakeWithOptsStartupParseError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, proxyBackend := net.Pipe()
	defer proxyBackend.Close()

	go func() {
		// Send a startup message that is valid length but too short to parse (< 8 bytes data)
		msg := make([]byte, 5)
		binary.BigEndian.PutUint32(msg[0:4], 5)
		msg[4] = 0
		clientConn.Write(msg)
		clientConn.Close()
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	proxyClient.Close()
	if err == nil {
		t.Error("startup parse error should fail")
	}
}

// --- DecodeParse: name has no null terminator ---

func TestDecodeParseNameNoNull(t *testing.T) {
	// Payload is just bytes without any null terminator
	_, err := DecodeParse([]byte("stmtname"))
	if err == nil {
		t.Error("name without null should fail")
	}
}

// --- DecodeBind: portal name has no null terminator ---

func TestDecodeBindPortalNoNull(t *testing.T) {
	_, err := DecodeBind([]byte("portalname"))
	if err == nil {
		t.Error("portal without null should fail")
	}
}

// --- ReadQueryCommand: extended query (non-Parse) with readExtendedBatch error ---

func TestReadQueryCommandExtendedNonParseError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer proxyConn.Close()

	go func() {
		// Send Bind (extended query, non-Parse) then close so readExtendedBatch fails
		var bindPayload []byte
		bindPayload = append(bindPayload, 0) // portal
		bindPayload = append(bindPayload, 0) // stmt
		bindPayload = append(bindPayload, 0, 0)
		bindPayload = append(bindPayload, 0, 0)
		bindPayload = append(bindPayload, 0, 0)
		WriteMessage(clientConn, &Message{Type: 'B', Payload: bindPayload})
		clientConn.Close() // close before Sync
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := ReadQueryCommand(context.Background(), proxyConn)
	if err == nil {
		t.Error("extended non-Parse with read error should fail")
	}
}

// --- readExtendedBatch: Bind with named statement (no SQL from Parse) ---

func TestReadExtendedBatchBindNamedStmtNoSQL(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		// Send Execute + Bind with named stmt + Sync (no Parse)
		var execPayload []byte
		execPayload = append(execPayload, 0)    // portal
		execPayload = append(execPayload, 0, 0, 0, 0) // max rows

		// Bind with named statement
		var bindPayload []byte
		bindPayload = append(bindPayload, 0)                    // portal ""
		bindPayload = append(bindPayload, []byte("my_stmt")...) // named stmt
		bindPayload = append(bindPayload, 0)
		bindPayload = append(bindPayload, 0, 0) // format codes
		bindPayload = append(bindPayload, 0, 0) // params
		bindPayload = append(bindPayload, 0, 0) // result formats

		WriteMessage(clientConn, &Message{Type: 'E', Payload: execPayload})
		WriteMessage(clientConn, &Message{Type: 'B', Payload: bindPayload})
		WriteMessage(clientConn, &Message{Type: 'S', Payload: nil}) // Sync
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	first, _ := ReadMessage(proxyConn)
	batch, err := readExtendedBatch(context.Background(), proxyConn, first)
	if err != nil {
		t.Fatalf("readExtendedBatch: %v", err)
	}
	// Should have SQL from bind reference
	if batch.SQL != "[prepared:my_stmt]" {
		t.Errorf("SQL = %q, want [prepared:my_stmt]", batch.SQL)
	}
}

// --- ParseRowDescription: nameEnd reaches end without null ---

func TestParseRowDescriptionNameNoNull(t *testing.T) {
	var payload []byte
	payload = append(payload, 0, 1) // 1 column
	payload = append(payload, []byte("col_name")...) // no null terminator

	_, err := ParseRowDescription(payload)
	if err == nil {
		t.Error("name without null terminator should fail")
	}
}

// --- relayAuth: context cancel before reading backend ---
// We need to cancel the context between loop iterations so the select picks ctx.Done()

func TestRelayAuthContextCancelDirect(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		for {
			clientConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send cleartext auth challenge
		authPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(authPayload, uint32(AuthCleartextPwd))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authPayload})

		// Read client password (forwarded from proxy)
		ReadMessage(backendConn)

		// Cancel the context before sending next auth message
		cancel()
		// Give the select a chance to check ctx.Done
		time.Sleep(50 * time.Millisecond)

		// Send another auth challenge (won't be processed since ctx cancelled)
		authPayload2 := make([]byte, 4)
		binary.BigEndian.PutUint32(authPayload2, uint32(AuthCleartextPwd))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authPayload2})
	}()

	go func() {
		// Wait for proxy to forward auth request to client
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadMessage(clientConn) // Read auth challenge
		// Send password
		WriteMessage(clientConn, &Message{Type: MsgPassword, Payload: []byte("secret")})
	}()

	proxyClient.SetDeadline(time.Now().Add(5 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := DoHandshakeWithOpts(ctx, proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("context cancel during relayAuth should return error")
	}
}

// --- relayPostAuth: context cancel between iterations ---

func TestRelayPostAuthContextCancelDirect(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		// Send ParameterStatus
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})

		// Cancel the context, then delay sending more messages
		cancel()
		time.Sleep(50 * time.Millisecond)

		// Send another message — but ctx should be cancelled
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
	}()

	proxyClient.SetDeadline(time.Now().Add(5 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(5 * time.Second))

	_, err := DoHandshakeWithOpts(ctx, proxyClient, proxyBackend, nil)
	if err == nil {
		t.Error("context cancel during relayPostAuth should return error")
	}
}

// --- readExtendedBatch: context cancel between messages ---
// We cancel the context before the second read. The select checks ctx.Done() before calling ReadMessage.

func TestReadExtendedBatchContextCancelDirect(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// Immediately cancel the context
	cancel()

	// The first message (Parse) is already in hand — not read from conn.
	// The next iteration will check ctx.Done() in the select.
	var parsePayload []byte
	parsePayload = append(parsePayload, 0)
	parsePayload = append(parsePayload, []byte("SELECT 1")...)
	parsePayload = append(parsePayload, 0)
	parsePayload = append(parsePayload, 0, 0)
	first := &Message{Type: MsgParse, Payload: parsePayload}

	// No writes to clientConn — the batch read loop will hit the cancelled ctx
	// before ReadMessage because there's nothing to read, so select will pick ctx.Done().
	// But actually, the code does `select { case <-ctx.Done(): ... default: }` then reads.
	// With a cancelled context, the select should always pick ctx.Done().

	batch, err := readExtendedBatch(ctx, proxyConn, first)
	if err == nil {
		t.Error("cancelled context should return error from readExtendedBatch")
	}
	_ = batch
}

// --- ReadQueryCommand: extended query starting with non-Parse (e.g. Describe) ---

func TestReadQueryCommandDescribeExtended(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		// Send Describe + Sync
		var descPayload []byte
		descPayload = append(descPayload, 'S') // describe type: statement
		descPayload = append(descPayload, 0)   // empty name
		WriteMessage(clientConn, &Message{Type: 'D', Payload: descPayload})
		WriteMessage(clientConn, &Message{Type: 'S', Payload: nil}) // Sync
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, rawMsg, err := ReadQueryCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("ReadQueryCommand: %v", err)
	}
	if cmd == nil {
		t.Fatal("cmd should not be nil")
	}
	if len(rawMsg) == 0 {
		t.Error("rawMsg empty")
	}
}
