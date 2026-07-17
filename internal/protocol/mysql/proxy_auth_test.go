package mysql

import (
	"encoding/binary"
	"net"
	"testing"
)

func constTimeEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func TestMySQLNativePassword(t *testing.T) {
	p := "testpass"
	s := []byte("test-scramble-bytes!")
	a := mysqlNativePassword(p, s)
	if len(a) != 20 {
		t.Fatalf("expected 20, got %d", len(a))
	}
	a2 := mysqlNativePassword(p, s)
	if !constTimeEq(a, a2) {
		t.Fatal("not deterministic")
	}
}

func TestBuildProxyGreeting(t *testing.T) {
	s := make([]byte, 20)
	p := buildProxyGreeting(s)
	if p == nil || p.SequenceID != 0 {
		t.Fatal("invalid greeting")
	}
	serverVersionEnd := 1
	for serverVersionEnd < len(p.Payload) && p.Payload[serverVersionEnd] != 0 {
		serverVersionEnd++
	}
	capabilityOffset := serverVersionEnd + 1 + 4 + 8 + 1
	lower := uint32(binary.LittleEndian.Uint16(p.Payload[capabilityOffset : capabilityOffset+2]))
	upper := uint32(binary.LittleEndian.Uint16(p.Payload[capabilityOffset+5 : capabilityOffset+7]))
	capabilities := lower | upper<<16
	if capabilities&0x00000800 != 0 {
		t.Fatal("proxy greeting must not advertise TLS")
	}
	if capabilities&clientProtocol41 == 0 || capabilities&clientPluginAuth == 0 {
		t.Fatalf("required capabilities missing: 0x%08x", capabilities)
	}
}

func TestExtractScramble(t *testing.T) {
	p := BuildHandshakeV10(1, "8.0.35")
	s := extractScramble(p.Payload)
	if len(s) < 20 {
		t.Fatalf("too short: %d", len(s))
	}
}

func TestProxyHandshakeValidateClientSecret(t *testing.T) {
	scramble := []byte("01234567890123456789")
	secret := "client-only-secret"
	handshake := &ProxyHandshake{
		Response: &HandshakeResponse{AuthResponse: mysqlNativePassword(secret, scramble)},
		scramble: scramble,
	}
	if err := handshake.ValidateClientSecret(nil, secret); err != nil {
		t.Fatalf("correct secret rejected: %v", err)
	}
	if err := handshake.ValidateClientSecret(nil, ""); err == nil {
		t.Fatal("empty secret accepted")
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		done <- handshake.ValidateClientSecret(server, "wrong-secret")
	}()
	packet, err := ReadPacket(client)
	if err != nil {
		t.Fatalf("read denial packet: %v", err)
	}
	if len(packet.Payload) == 0 || packet.Payload[0] != 0xFF {
		t.Fatalf("denial payload = %x", packet.Payload)
	}
	if err := <-done; err == nil {
		t.Fatal("wrong secret accepted")
	}
}
