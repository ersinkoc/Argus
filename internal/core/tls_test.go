package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/config"
)

// makeCASigned generates a CA key+cert, signs a leaf cert with it, and writes all to dir.
// Returns (serverCert, serverKey, clientCert, clientKey, caFile).
func makeCASigned(t *testing.T, dir string) (string, string, string, string, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.crt")
	writeTLSPEM(t, caFile, "CERTIFICATE", caDER)

	sign := func(name string, serial int64) (certFile, keyFile string) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certFile = filepath.Join(dir, name+".crt")
		keyFile = filepath.Join(dir, name+".key")
		writeTLSPEM(t, certFile, "CERTIFICATE", der)
		keyDER, _ := x509.MarshalECPrivateKey(k)
		writeTLSPEM(t, keyFile, "EC PRIVATE KEY", keyDER)
		return
	}

	serverCert, serverKey := sign("server", 2)
	clientCert, clientKey := sign("client", 3)
	return serverCert, serverKey, clientCert, clientKey, caFile
}

func writeTLSPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func TestMakeServerTLSConfig_Disabled(t *testing.T) {
	cfg, err := MakeServerTLSConfig(config.TLSConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Fatal("expected nil config when disabled")
	}
}

func TestMakeServerTLSConfig_Basic(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "s.crt")
	keyFile := filepath.Join(dir, "s.key")
	generateTestCert(t, certFile, keyFile) // uses existing helper from certreload_test.go

	cfg, err := MakeServerTLSConfig(config.TLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs != nil {
		t.Error("expected nil ClientCAs when client_auth is false")
	}
}

func TestMakeServerTLSConfig_mTLS(t *testing.T) {
	dir := t.TempDir()
	serverCert, serverKey, _, _, caFile := makeCASigned(t, dir)

	cfg, err := MakeServerTLSConfig(config.TLSConfig{
		Enabled:      true,
		CertFile:     serverCert,
		KeyFile:      serverKey,
		ClientAuth:   true,
		ClientCAFile: caFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("expected non-nil ClientCAs")
	}
}

func TestMakeServerTLSConfig_mTLS_MissingCAFile(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "s.crt")
	keyFile := filepath.Join(dir, "s.key")
	generateTestCert(t, certFile, keyFile)

	_, err := MakeServerTLSConfig(config.TLSConfig{
		Enabled:      true,
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientAuth:   true,
		ClientCAFile: filepath.Join(dir, "nonexistent.crt"),
	})
	if err == nil {
		t.Fatal("expected error for missing client CA file")
	}
}

func TestMakeServerTLSConfig_mTLS_BadCAFile(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "s.crt")
	keyFile := filepath.Join(dir, "s.key")
	generateTestCert(t, certFile, keyFile)

	badCA := filepath.Join(dir, "bad.crt")
	if err := os.WriteFile(badCA, []byte("not valid PEM"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := MakeServerTLSConfig(config.TLSConfig{
		Enabled:      true,
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientAuth:   true,
		ClientCAFile: badCA,
	})
	if err == nil {
		t.Fatal("expected error for invalid client CA PEM")
	}
}

func TestMakeClientTLSConfig_Disabled(t *testing.T) {
	cfg, err := MakeClientTLSConfig(config.TLSConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil {
		t.Fatal("expected nil config when disabled")
	}
}

func TestMakeClientTLSConfig_WithCA(t *testing.T) {
	dir := t.TempDir()
	_, _, _, _, caFile := makeCASigned(t, dir)

	cfg, err := MakeClientTLSConfig(config.TLSConfig{
		Enabled: true,
		CAFile:  caFile,
		Verify:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil {
		t.Error("expected non-nil RootCAs")
	}
	if cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false when verify=true")
	}
}

func TestMakeClientTLSConfig_InsecureSkipVerify(t *testing.T) {
	cfg, err := MakeClientTLSConfig(config.TLSConfig{
		Enabled: true,
		Verify:  false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true when verify=false")
	}
}

func TestMTLS_Handshake(t *testing.T) {
	dir := t.TempDir()
	serverCert, serverKey, clientCert, clientKey, caFile := makeCASigned(t, dir)

	serverTLS, err := MakeServerTLSConfig(config.TLSConfig{
		Enabled:      true,
		CertFile:     serverCert,
		KeyFile:      serverKey,
		ClientAuth:   true,
		ClientCAFile: caFile,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- conn.(*tls.Conn).Handshake()
		conn.Close()
	}()

	clientCertPair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates: []tls.Certificate{clientCertPair},
		RootCAs:      caPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := <-errCh; err != nil {
		t.Errorf("server handshake error: %v", err)
	}
}

func TestMTLS_RejectsClientWithoutCert(t *testing.T) {
	dir := t.TempDir()
	serverCert, serverKey, _, _, caFile := makeCASigned(t, dir)

	serverTLS, err := MakeServerTLSConfig(config.TLSConfig{
		Enabled:      true,
		CertFile:     serverCert,
		KeyFile:      serverKey,
		ClientAuth:   true,
		ClientCAFile: caFile,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrCh <- nil
			return
		}
		serverErrCh <- conn.(*tls.Conn).Handshake()
		conn.Close()
	}()

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	// Client without certificate — either the dial fails or the server rejects it.
	conn, dialErr := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs: caPool,
	})
	serverErr := <-serverErrCh

	if dialErr == nil {
		conn.Close()
	}
	if dialErr == nil && serverErr == nil {
		t.Fatal("expected TLS handshake to fail without client cert")
	}
}
