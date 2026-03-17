package pool

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPoolAcquireRelease(t *testing.T) {
	// Start a test TCP server
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
			conn.Close()
		}
	}()

	p := NewPool(ln.Addr().String(), 5, 1, time.Hour, 5*time.Second, 0)

	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	stats := p.Stats()
	if stats.Active != 1 {
		t.Errorf("active = %d, want 1", stats.Active)
	}
	if stats.Total != 1 {
		t.Errorf("total = %d, want 1", stats.Total)
	}

	p.Release(conn)

	stats = p.Stats()
	if stats.Active != 0 {
		t.Errorf("active after release = %d, want 0", stats.Active)
	}
	if stats.Idle != 1 {
		t.Errorf("idle after release = %d, want 1", stats.Idle)
	}

	p.Close()
}

func TestPoolMaxConnections(t *testing.T) {
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
			// keep connections open
			_ = conn
		}
	}()

	p := NewPool(ln.Addr().String(), 2, 0, time.Hour, 5*time.Second, 0)

	conn1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}

	conn2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire 2: %v", err)
	}

	// Third should fail (max = 2)
	_, err = p.Acquire(context.Background())
	if err == nil {
		t.Error("Acquire 3 should fail (connection limit)")
	}

	p.Release(conn1)
	p.Release(conn2)
	p.Close()
}

func TestPoolClosed(t *testing.T) {
	p := NewPool("127.0.0.1:0", 5, 0, time.Hour, 5*time.Second, 0)
	p.Close()

	_, err := p.Acquire(context.Background())
	if err == nil {
		t.Error("Acquire on closed pool should fail")
	}
}

func TestPoolStats(t *testing.T) {
	p := NewPool("127.0.0.1:5432", 10, 1, time.Hour, 5*time.Second, 0)
	stats := p.Stats()

	if stats.Max != 10 {
		t.Errorf("max = %d, want 10", stats.Max)
	}
	if stats.Target != "127.0.0.1:5432" {
		t.Errorf("target = %q", stats.Target)
	}
	if !stats.Healthy {
		t.Error("should be healthy initially")
	}
}
