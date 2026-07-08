package auth

import (
	"encoding/base64"
	"testing"
)

// --- base64URLDecode: all padding branches ---

func TestBase64URLDecodeModZero(t *testing.T) {
	// len(s) % 4 == 0 — no padding needed
	encoded := base64.URLEncoding.EncodeToString([]byte("abcd"))
	result, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "abcd" {
		t.Errorf("got %q", result)
	}
}

func TestBase64URLDecodeModOne(t *testing.T) {
	// len(s) % 4 == 1 — this shouldn't normally happen but test it
	// base64 with padding removed can be mod 2 or 3, not mod 1
	// We just test that it doesn't panic
	_, _ = base64URLDecode("x")
}

func TestBase64URLDecodeModTwo(t *testing.T) {
	// len(s) % 4 == 2 — needs "=="
	raw := []byte("a")
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw)
	result, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "a" {
		t.Errorf("got %q", result)
	}
}

func TestBase64URLDecodeModThree(t *testing.T) {
	// len(s) % 4 == 3 — needs "="
	raw := []byte("ab")
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw)
	result, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "ab" {
		t.Errorf("got %q", result)
	}
}

func TestBase64URLDecodeInvalid(t *testing.T) {
	_, err := base64URLDecode("!!!invalid!!!")
	if err == nil {
		t.Error("invalid base64 should fail")
	}
}

// --- parseLDAPResultCode: more branches ---

func TestParseLDAPResultCodeMalformed(t *testing.T) {
	// Too short for any parsing
	if parseLDAPResultCode([]byte{0x30}) != -1 {
		t.Error("single byte should return -1")
	}
	// Just the sequence tag + short length but no content
	if parseLDAPResultCode([]byte{0x30, 0x02, 0x00, 0x00}) != -1 {
		t.Error("malformed should return -1")
	}
}
