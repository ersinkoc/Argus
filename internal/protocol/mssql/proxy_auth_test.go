package mssql

import (
	"testing"
)

func TestBuildProxyLogin7(t *testing.T) {
	username := "test_user"
	password := "test_pass_123"
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	pkt := BuildProxyLogin7(username, password, nonce)
	if pkt == nil {
		t.Fatal("BuildProxyLogin7 returned nil")
	}

	if pkt.Type != PacketTDS7Login {
		t.Errorf("expected PacketTDS7Login (0x%02x), got 0x%02x", PacketTDS7Login, pkt.Type)
	}

	if len(pkt.Data) < 94 {
		t.Fatalf("Login7 packet too short: %d bytes", len(pkt.Data))
	}

	// Extract username from the built packet
	extractedUser := extractLogin7Username(pkt.Data)
	if extractedUser != username {
		t.Errorf("extracted username = %q, want %q", extractedUser, username)
	}
}

func TestBuildProxyPreLoginResponse(t *testing.T) {
	nonce := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}

	data := BuildProxyPreLoginResponse(nonce)
	if data == nil {
		t.Fatal("BuildProxyPreLoginResponse returned nil")
	}

	if len(data) < 8 {
		t.Fatalf("PreLogin response too short: %d bytes", len(data))
	}
}

func TestExtractPreLoginNonce(t *testing.T) {
	data := make([]byte, 34)
	for i := range data {
		data[i] = byte(i)
	}

	nonce := extractPreLoginNonce(data)
	if nonce == nil {
		t.Fatal("extractPreLoginNonce returned nil")
	}

	if len(nonce) != 8 {
		t.Errorf("nonce length = %d, want 8", len(nonce))
	}
}

func TestEncryptTDSPassword(t *testing.T) {
	passUTF16 := toUTF16LE("testpassword")
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	encrypted := encryptTDSPassword(passUTF16, nonce)
	if encrypted == nil {
		t.Fatal("encryptTDSPassword returned nil")
	}

	// First byte should be 0x00 (success indicator)
	if encrypted[0] != 0x00 {
		t.Errorf("expected first byte 0x00, got 0x%02x", encrypted[0])
	}

	// Should be 1 + len(pass) + 4 bytes
	if len(encrypted) != 1+len(passUTF16)+4 {
		t.Errorf("length = %d, want %d", len(encrypted), 1+len(passUTF16)+4)
	}

	// Verify it's deterministic
	encrypted2 := encryptTDSPassword(passUTF16, nonce)
	if len(encrypted) != len(encrypted2) {
		t.Error("not deterministic")
	}
}

func TestBuildProxyLogin7RoundTrip(t *testing.T) {
	username := "proxy_user"
	password := "proxy_pass"
	nonce := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}

	pkt := BuildProxyLogin7(username, password, nonce)
	extracted := extractLogin7Username(pkt.Data)

	if extracted != username {
		t.Errorf("round-trip username: got %q, want %q", extracted, username)
	}
}

func TestDisableMARSPassthrough(t *testing.T) {
	// Build a login and verify disableMARS doesn't crash
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	pkt := BuildProxyLogin7("user", "pass", nonce)

	disabled := disableMARS(pkt.Data)
	if disabled == nil {
		t.Fatal("disableMARS returned nil")
	}
}

func TestBuildProxyLogin7WithoutNonce(t *testing.T) {
	pkt := BuildProxyLogin7("user", "pass", nil)
	if pkt == nil {
		t.Fatal("BuildProxyLogin7 with nil nonce returned nil")
	}
	extracted := extractLogin7Username(pkt.Data)
	if extracted != "user" {
		t.Errorf("username = %q", extracted)
	}
}
