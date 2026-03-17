package pool

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPoolSetConnectFunc(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, time.Second, 0)
	called := false
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		called = true
		return net.Dial("tcp", "127.0.0.1:1")
	})
	p.Acquire(context.Background()) // will fail but exercises the path
	if !called {
		t.Error("custom connect func should be called")
	}
	p.Close()
}

func TestPoolCheckHealth(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { for { c, _ := ln.Accept(); if c != nil { c.Close() } } }()

	p := NewPool(ln.Addr().String(), 5, 0, time.Hour, time.Second, 100*time.Millisecond)
	p.Start()
	time.Sleep(200 * time.Millisecond)
	if !p.IsHealthy() {
		t.Error("should be healthy")
	}
	p.Close()
}

func TestPoolCheckHealthUnhealthy(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, time.Second, 0)
	p.checkHealth()
	if p.IsHealthy() {
		t.Error("port 1 should be unhealthy")
	}
	p.Close()
}

func TestConnNetConn(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { _ = c } }()

	nc, _ := net.Dial("tcp", ln.Addr().String())
	c := &Conn{conn: nc, createdAt: time.Now()}
	if c.NetConn() == nil {
		t.Error("NetConn should not be nil")
	}
	c.Close()
}

func TestSharedPoolSetConnectFunc(t *testing.T) {
	p := NewSharedPool("127.0.0.1:1", 5, time.Hour, time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		return nil, nil
	})
	p.Close()
}

func TestSharedPoolStartAndHealth(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { for { c, _ := ln.Accept(); if c != nil { c.Close() } } }()

	p := NewSharedPool(ln.Addr().String(), 5, time.Hour, time.Second, 200*time.Millisecond)
	p.Start()
	time.Sleep(300 * time.Millisecond)
	p.Close()
}

func TestCheckAllTargets(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { for { c, _ := ln.Accept(); if c != nil { c.Close() } } }()

	results := CheckAllTargets([]string{ln.Addr().String(), "127.0.0.1:1"}, time.Second)
	if len(results) != 2 {
		t.Errorf("results = %d, want 2", len(results))
	}
	healthy := 0
	for _, r := range results {
		if r.Healthy { healthy++ }
	}
	if healthy != 1 {
		t.Errorf("healthy = %d, want 1", healthy)
	}
}

func TestFmtFloat(t *testing.T) {
	if fmtFloat(5.0) != "5" {
		t.Errorf("5.0 = %q", fmtFloat(5.0))
	}
	if fmtFloat(5.5) != "5.5" {
		t.Errorf("5.5 = %q", fmtFloat(5.5))
	}
	if fmtFloat(0) != "0" {
		t.Errorf("0 = %q", fmtFloat(0))
	}
}

func TestCircuitBreakerDefaults(t *testing.T) {
	cb := NewCircuitBreaker(0, 0)
	if cb.threshold != 5 {
		t.Errorf("default threshold = %d, want 5", cb.threshold)
	}
	if cb.resetTimeout != 30*time.Second {
		t.Errorf("default reset = %v", cb.resetTimeout)
	}
}
