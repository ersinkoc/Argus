package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	// Generate self-signed cert
	generateTestCert(t, certFile, keyFile)

	reloader, err := NewCertReloader(certFile, keyFile, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}

	// GetCertificate
	cert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("cert should not be nil")
	}

	// TLSConfig
	tlsCfg := reloader.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("TLSConfig should not be nil")
	}
	if tlsCfg.GetCertificate == nil {
		t.Error("GetCertificate should be set")
	}

	// Start and stop
	reloader.Start()
	time.Sleep(150 * time.Millisecond)
	reloader.Stop()
}

func TestCertReloaderInvalidCert(t *testing.T) {
	_, err := NewCertReloader("/nonexistent/cert.pem", "/nonexistent/key.pem", 0)
	if err == nil {
		t.Error("should fail with invalid cert files")
	}
}

func generateTestCert(t *testing.T, certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyOut.Close()
}
