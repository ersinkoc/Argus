package mssql

import (
	"testing"
)

func TestExtractLogin7Username(t *testing.T) {
	// Build minimal Login7 with username at offset 48
	data := make([]byte, 100)
	// Username offset at bytes 48-49 (little-endian), length at 50-51
	usernameUTF16 := toUTF16LE("admin")
	offset := 94 // after fixed header
	data[48] = byte(offset)
	data[49] = byte(offset >> 8)
	data[50] = 5 // length = 5 chars
	data[51] = 0
	copy(data[offset:], usernameUTF16)

	username := extractLogin7Username(data)
	if username != "admin" {
		t.Errorf("username = %q, want 'admin'", username)
	}
}

func TestExtractLogin7UsernameTooShort(t *testing.T) {
	username := extractLogin7Username([]byte{1, 2, 3})
	if username != "" {
		t.Error("short data should return empty")
	}
}

func TestContainsTokenFull(t *testing.T) {
	data := []byte{TokenEnvChange, TokenLoginAck, TokenDone}

	if !containsToken(data, TokenLoginAck) {
		t.Error("should find LoginAck")
	}
	if !containsToken(data, TokenDone) {
		t.Error("should find Done")
	}
	if containsToken(data, TokenRow) {
		t.Error("should not find Row")
	}
}

func TestReadAllPacketsBasic(t *testing.T) {
	// This tests the function signature — full test needs pipe
	// Just verify it compiles and is accessible
	_ = ReadAllPackets
}

func TestBuildPreLoginResponseContent(t *testing.T) {
	pkt := BuildPreLoginResponse()
	if len(pkt.Data) < 20 {
		t.Error("pre-login response should have substantial data")
	}
	// Should contain VERSION token (0x00) and ENCRYPTION token (0x01)
	hasVersion := false
	hasEncryption := false
	for _, b := range pkt.Data[:10] {
		if b == 0x00 {
			hasVersion = true
		}
		if b == 0x01 {
			hasEncryption = true
		}
	}
	if !hasVersion {
		t.Error("should have VERSION token")
	}
	if !hasEncryption {
		t.Error("should have ENCRYPTION token")
	}
}

func TestDecodeUTF16LESliceOddLength(t *testing.T) {
	// Odd length should be handled
	data := []byte{'H', 0, 'i', 0, 'x'} // 5 bytes, odd
	result := decodeUTF16LESlice(data)
	if result != "Hi" {
		t.Errorf("got %q, want 'Hi'", result)
	}
}

func TestToUTF16LERoundtrip(t *testing.T) {
	original := "Hello World"
	encoded := toUTF16LE(original)
	decoded := decodeUTF16LESlice(encoded)
	if decoded != original {
		t.Errorf("roundtrip: %q != %q", decoded, original)
	}
}

func TestPacketStatusFlags(t *testing.T) {
	if StatusEOM != 0x01 {
		t.Error("EOM should be 0x01")
	}
	if StatusNormal != 0x00 {
		t.Error("Normal should be 0x00")
	}
}

func TestPacketTypes(t *testing.T) {
	types := map[byte]string{
		PacketSQLBatch:  "SQLBatch",
		PacketPreLogin:  "PreLogin",
		PacketTDS7Login: "TDS7Login",
		PacketReply:     "Reply",
	}
	for typ, name := range types {
		if typ == 0 {
			t.Errorf("%s should not be 0", name)
		}
	}
}
