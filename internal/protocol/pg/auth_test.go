package pg

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestDoHandshakeWithSSLReject(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	// Client: send SSLRequest, then startup
	go func() {
		// SSLRequest
		sslReq := make([]byte, 8)
		binary.BigEndian.PutUint32(sslReq[0:4], 8)
		binary.BigEndian.PutUint32(sslReq[4:8], SSLRequestCode)
		clientConn.Write(sslReq)

		// Read 'N' response
		buf := make([]byte, 1)
		clientConn.Read(buf)

		// Send real startup
		msg := BuildStartupMessage(map[string]string{"user": "ssluser", "database": "ssldb"})
		clientConn.Write(msg)

		// Read auth + params + ReadyForQuery
		for {
			m, err := ReadMessage(clientConn)
			if err != nil || m.Type == MsgReadyForQuery { return }
		}
	}()

	// Backend
	go func() {
		ReadStartupMessage(backendConn) // startup (not SSL)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16.0")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := DoHandshakeWithOpts(context.Background(), proxyClient, proxyBackend, nil)
	if err != nil {
		t.Fatalf("Handshake with SSL reject: %v", err)
	}
	if info.Username != "ssluser" {
		t.Errorf("username = %q", info.Username)
	}
}

func TestRelayAuthCleartextPassword(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	// Client: send startup, handle auth
	go func() {
		msg := BuildStartupMessage(map[string]string{"user": "authuser", "database": "authdb"})
		clientConn.Write(msg)

		// Read AuthCleartextPassword request
		m, _ := ReadMessage(clientConn)
		_ = m // auth request

		// Send password
		pwd := append([]byte("mypassword"), 0)
		WriteMessage(clientConn, &Message{Type: MsgPassword, Payload: pwd})

		// Read remaining auth messages
		for {
			m, err := ReadMessage(clientConn)
			if err != nil || m.Type == MsgReadyForQuery { return }
		}
	}()

	// Backend: request cleartext password, verify, send OK
	go func() {
		ReadStartupMessage(backendConn)

		// Request cleartext password (AuthType = 3)
		authReq := make([]byte, 4)
		binary.BigEndian.PutUint32(authReq, uint32(AuthCleartextPwd))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authReq})

		// Read password from proxy
		ReadMessage(backendConn)

		// Send AuthOK
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		// Post-auth
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16.0")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake with cleartext auth: %v", err)
	}
	if info.Username != "authuser" {
		t.Errorf("username = %q", info.Username)
	}
	if info.AuthMethod != "cleartext" {
		t.Errorf("auth method = %q, want cleartext", info.AuthMethod)
	}
}

func TestRelayAuthMD5Password(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		msg := BuildStartupMessage(map[string]string{"user": "md5user", "database": "db"})
		clientConn.Write(msg)

		// Read MD5 auth request
		ReadMessage(clientConn)

		// Send MD5 password response
		WriteMessage(clientConn, &Message{Type: MsgPassword, Payload: []byte("md5hash\x00")})

		for {
			m, err := ReadMessage(clientConn)
			if err != nil || m.Type == MsgReadyForQuery { return }
		}
	}()

	go func() {
		ReadStartupMessage(backendConn)

		// MD5 auth request (type 5 + 4 bytes salt)
		authReq := make([]byte, 8)
		binary.BigEndian.PutUint32(authReq, uint32(AuthMD5Pwd))
		authReq[4] = 0x01; authReq[5] = 0x02; authReq[6] = 0x03; authReq[7] = 0x04 // salt
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authReq})

		ReadMessage(backendConn) // password response

		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16.0")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("MD5 auth: %v", err)
	}
	if info.AuthMethod != "md5" {
		t.Errorf("auth = %q, want md5", info.AuthMethod)
	}
}

func TestRelayAuthBackendError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		msg := BuildStartupMessage(map[string]string{"user": "baduser", "database": "db"})
		clientConn.Write(msg)
		// Read error
		ReadMessage(clientConn)
	}()

	go func() {
		ReadStartupMessage(backendConn)
		// Send error response
		errMsg := BuildErrorResponse("FATAL", "28P01", "password authentication failed")
		WriteMessage(backendConn, errMsg)
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("should fail on auth error")
	}
}
