package mysql

import "testing"

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
}

func TestExtractScramble(t *testing.T) {
	p := BuildHandshakeV10(1, "8.0.35")
	s := extractScramble(p.Payload)
	if len(s) < 20 {
		t.Fatalf("too short: %d", len(s))
	}
}
