package mssql

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
)

func TestBuildProxyLogin7(t *testing.T) {
	n := make([]byte, 32)
	for i := range n {
		n[i] = byte(i)
	}
	p := BuildProxyLogin7("test_user", "test_pass", n)
	if p == nil || p.Type != PacketTDS7Login {
		t.Fatal("invalid")
	}
	if len(p.Data) < 94 {
		t.Fatal("too short")
	}
	u := extractLogin7Username(p.Data)
	if u != "test_user" {
		t.Fatalf("username = %q", u)
	}
}

func TestBuildProxyPreLoginResponse(t *testing.T) {
	d := BuildProxyPreLoginResponse([]byte{1, 2, 3, 4})
	if d == nil || len(d) < 8 {
		t.Fatal("invalid")
	}
}

func TestProxyAuthServerWithTDSTLS(t *testing.T) {
	clientSide, relayClient := net.Pipe()
	defer clientSide.Close()
	defer relayClient.Close()
	serverTransportConn, relayServer := net.Pipe()
	defer serverTransportConn.Close()
	defer relayServer.Close()

	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range []net.Conn{clientSide, relayClient, serverTransportConn, relayServer} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	go relayODBCStyleTLSHandshake(t, relayServer, relayClient)

	cert := proxyAuthTestCertificate(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	errs := make(chan error, 2)
	result := make(chan *ProxyLogin, 1)
	secured := make(chan net.Conn, 1)

	go func() {
		conn, login, err := ProxyAuthServer(context.Background(), serverTransportConn, tlsCfg, true)
		if err == nil {
			secured <- conn
			result <- login
		}
		errs <- err
	}()
	go func() {
		if err := WritePacket(clientSide, &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: BuildPreLoginResponse().Data}); err != nil {
			errs <- err
			return
		}
		resp, err := ReadPacket(clientSide)
		if err != nil {
			errs <- err
			return
		}
		if resp.Type != PacketReply || len(resp.Data) == 0 || !preloginHasEncryptionValue(resp.Data, 0x00) {
			errs <- errInvalidPreloginTestResponse
			return
		}
		tlsClient := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
		if err := tlsClient.HandshakeContext(context.Background()); err != nil {
			errs <- err
			return
		}
		if err := WritePacket(tlsClient, BuildProxyLogin7("client-handle", "client-only-secret", nil)); err != nil {
			errs <- err
			return
		}
		errs <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("tds tls proxy auth path: %v", err)
		}
	}
	login := <-result
	if login.Username != "client-handle" {
		t.Fatalf("username = %q, want client-handle", login.Username)
	}
	if err := login.ValidateClientSecret("client-only-secret"); err != nil {
		t.Fatalf("ValidateClientSecret: %v", err)
	}
	if securedConn := <-secured; securedConn != serverTransportConn {
		t.Fatal("expected ProxyAuthServer to return the raw client connection after Login7 TLS")
	}
}

func TestObfuscateTDSPassword(t *testing.T) {
	plain := toUTF16LE("test")
	obfuscated := obfuscateTDSPassword(plain)
	if len(obfuscated) != len(plain) {
		t.Fatalf("length = %d, want %d", len(obfuscated), len(plain))
	}
	for i, value := range obfuscated {
		decoded := value ^ 0xA5
		decoded = (decoded << 4) | (decoded >> 4)
		if decoded != plain[i] {
			t.Fatalf("byte %d did not round-trip", i)
		}
	}
}

func TestProxyLoginValidateClientSecret(t *testing.T) {
	secret := "client-only-secret"
	packet := BuildProxyLogin7("client-handle", secret, nil)
	login := &ProxyLogin{Username: "client-handle", login: packet.Data}
	if err := login.ValidateClientSecret(secret); err != nil {
		t.Fatalf("correct secret rejected: %v", err)
	}
	if err := login.ValidateClientSecret("wrong-secret"); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if err := login.ValidateClientSecret(""); err == nil {
		t.Fatal("empty secret accepted")
	}
}

var errInvalidPreloginTestResponse = tls.RecordHeaderError{Msg: "invalid prelogin response"}

func preloginHasEncryptionValue(data []byte, want byte) bool {
	for i := 0; i < len(data); {
		token := data[i]
		if token == 0xFF {
			break
		}
		if i+5 > len(data) {
			return false
		}
		offset := int(binary.BigEndian.Uint16(data[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
		if token == 0x01 && length == 1 && offset < len(data) {
			return data[offset] == want
		}
		i += 5
	}
	return false
}

func proxyAuthTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mssql-proxy-auth-test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}
