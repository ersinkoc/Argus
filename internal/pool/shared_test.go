package pool

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSharedPoolBasic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // keep open
		}
	}()

	p := NewSharedPool(ln.Addr().String(), 5, time.Hour, 5*time.Second, 0)

	// Acquire
	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	stats := p.Stats()
	if stats.Active != 1 {
		t.Errorf("active = %d, want 1", stats.Active)
	}

	// Release
	p.Release(conn)

	stats = p.Stats()
	if stats.Idle != 1 {
		t.Errorf("idle = %d, want 1", stats.Idle)
	}

	// Re-acquire should reuse
	conn2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire 2: %v", err)
	}
	p.Release(conn2)

	// Total should still be 1 (reused)
	stats = p.Stats()
	if stats.Total != 1 {
		t.Errorf("total = %d, want 1 (connection reused)", stats.Total)
	}

	p.Close()
}

func TestSharedPoolWaiters(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	// Pool with max 1 connection
	p := NewSharedPool(ln.Addr().String(), 1, time.Hour, 5*time.Second, 0)

	conn1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}

	// Second acquire should block
	var conn2 *Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		conn2, err = p.Acquire(context.Background())
		if err != nil {
			t.Errorf("Acquire 2: %v", err)
		}
	}()

	// Release conn1 — should wake up waiter
	time.Sleep(50 * time.Millisecond)
	p.Release(conn1)

	wg.Wait()
	if conn2 == nil {
		t.Error("conn2 should not be nil after waiter gets connection")
	}
	p.Release(conn2)
	p.Close()
}

func TestSharedPoolContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	p := NewSharedPool(ln.Addr().String(), 1, time.Hour, 5*time.Second, 0)

	// Take the only connection
	conn1, _ := p.Acquire(context.Background())

	// Try to acquire with short context
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = p.Acquire(ctx)
	if err == nil {
		t.Error("should fail with context timeout")
	}

	p.Release(conn1)
	p.Close()
}
