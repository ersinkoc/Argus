package pool

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPoolReleaseExpired(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { for { c, _ := ln.Accept(); if c != nil { _ = c } } }()

	p := NewPool(ln.Addr().String(), 5, 0, 1*time.Millisecond, 5*time.Second, 0) // 1ms lifetime

	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Millisecond) // exceed lifetime
	p.Release(conn)                    // should close, not return to idle

	stats := p.Stats()
	if stats.Idle != 0 {
		t.Errorf("expired conn should not go to idle: idle=%d", stats.Idle)
	}
	p.Close()
}

func TestSharedPoolCheckHealth(t *testing.T) {
	p := NewSharedPool("127.0.0.1:1", 5, time.Hour, time.Second, 0)
	p.checkHealth() // port 1 unhealthy
	// Should not panic
	p.Close()
}
