package session

import (
	"net"
	"testing"
)

func TestKillByPrincipal(t *testing.T) {
	m := NewManager(0, 0)
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	c3, _ := net.Pipe()
	m.Create(&Info{Username: "mpk_a", Principal: "key:aaa"}, c1)
	m.Create(&Info{Username: "mpk_a2", Principal: "key:aaa"}, c2)
	m.Create(&Info{Username: "mp_x", Principal: "user:42"}, c3)

	if n := m.KillByPrincipal("key:aaa"); n != 2 {
		t.Fatalf("expected 2 killed, got %d", n)
	}
	if m.Count() != 1 {
		t.Fatalf("expected 1 session left, got %d", m.Count())
	}
	if n := m.KillByPrincipal(""); n != 0 {
		t.Fatalf("empty principal should kill nothing, got %d", n)
	}
}
