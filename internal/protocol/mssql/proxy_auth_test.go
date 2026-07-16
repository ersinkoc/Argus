package mssql

import "testing"

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

func TestEncryptTDSPassword(t *testing.T) {
	n := make([]byte, 32)
	for i := range n {
		n[i] = byte(i + 1)
	}
	e := encryptTDSPassword(toUTF16LE("test"), n)
	if len(e) != 32 {
		t.Fatalf("expected 32, got %d", len(e))
	}
	e2 := encryptTDSPassword(toUTF16LE("test"), nil)
	if len(e2) != 32 {
		t.Fatal("nil nonce failed")
	}
}
