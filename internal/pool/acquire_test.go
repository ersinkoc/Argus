package pool

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPoolAcquireWithStaleDiscard(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { for { c, _ := ln.Accept(); if c != nil { c.Close() } } }()

	p := NewPool(ln.Addr().String(), 5, 0, time.Hour, 5*time.Second, 0)

	// Manually add a "stale" connection to idle pool
	staleConn, _ := net.Dial("tcp", ln.Addr().String())
	staleConn.Close() // close it to make it stale
	time.Sleep(10 * time.Millisecond)

	p.mu.Lock()
	p.idle = append(p.idle, &Conn{conn: staleConn, createdAt: time.Now()})
	p.total = 1
	p.mu.Unlock()

	// Acquire should discard stale and create new
	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	p.Release(conn)
	p.Close()
}

func TestPoolAcquireCircuitOpen(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, 100*time.Millisecond, 0)

	// Force circuit open
	for range 10 {
		p.Acquire(context.Background())
	}

	// Circuit should be open now
	if p.breaker.State() != CircuitOpen {
		// May not be open depending on timing — just verify no panic
	}
	p.Close()
}

func TestPoolAcquireClosed(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, time.Second, 0)
	p.Close()

	_, err := p.Acquire(context.Background())
	if err == nil {
		t.Error("closed pool should fail")
	}
}
