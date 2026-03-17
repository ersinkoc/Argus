package core

import (
	"testing"

	"github.com/ersinkoc/argus/internal/config"
)

func TestMakeServerTLSConfigDisabled(t *testing.T) {
	cfg := config.TLSConfig{Enabled: false}
	tlsCfg, err := MakeServerTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		t.Error("disabled TLS should return nil config")
	}
}

func TestMakeClientTLSConfigDisabled(t *testing.T) {
	cfg := config.TLSConfig{Enabled: false}
	tlsCfg, err := MakeClientTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		t.Error("disabled TLS should return nil config")
	}
}

func TestMakeClientTLSConfigNoVerify(t *testing.T) {
	cfg := config.TLSConfig{Enabled: true, Verify: false}
	tlsCfg, err := MakeClientTLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("should skip verify")
	}
}

func TestMakeClientTLSConfigInvalidCA(t *testing.T) {
	cfg := config.TLSConfig{Enabled: true, CAFile: "/nonexistent/ca.crt", Verify: true}
	_, err := MakeClientTLSConfig(cfg)
	if err == nil {
		t.Error("should fail with invalid CA file")
	}
}

func TestMakeServerTLSConfigInvalidCert(t *testing.T) {
	cfg := config.TLSConfig{Enabled: true, CertFile: "/nonexistent/cert.crt", KeyFile: "/nonexistent/key.pem"}
	_, err := MakeServerTLSConfig(cfg)
	if err == nil {
		t.Error("should fail with invalid cert files")
	}
}

func TestListenerStop(t *testing.T) {
	l := NewListener(config.ListenerConfig{Address: "127.0.0.1:0", Protocol: "postgresql"})
	err := l.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	l.Stop() // should not hang
}
