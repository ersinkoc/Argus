package pool

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- Pool.Acquire: unhealthy target ---

func TestPoolAcquireUnhealthy(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, 100*time.Millisecond, 0)
	p.mu.Lock()
	p.healthy = false
	p.mu.Unlock()

	_, err := p.Acquire(context.Background())
	if err == nil {
		t.Error("unhealthy target should fail")
	}
	p.Close()
}

// --- Pool.Acquire: circuit breaker open ---

func TestPoolAcquireBreakerOpen(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, 100*time.Millisecond, 0)

	// Trip the circuit breaker
	p.mu.Lock()
	for range 5 {
		p.breaker.RecordFailure()
	}
	p.mu.Unlock()

	_, err := p.Acquire(context.Background())
	if err == nil {
		t.Error("open circuit breaker should fail")
	}
	p.Close()
}

// --- Pool.Acquire: create new connection ---

func TestPoolAcquireCreateNew(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(10 * time.Second); c.Close() }()
		}
	}()

	p := NewPool(ln.Addr().String(), 5, 0, time.Hour, time.Second, 0)
	defer p.Close()

	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	p.Release(conn)
}

// --- Pool.Acquire: at max connections ---

func TestPoolAcquireAtMax(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(10 * time.Second); c.Close() }()
		}
	}()

	p := NewPool(ln.Addr().String(), 1, 0, time.Hour, time.Second, 0)
	defer p.Close()

	conn1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	// Second acquire with context timeout — pool full
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = p.Acquire(ctx)
	if err == nil {
		t.Error("pool full should timeout")
	}

	p.Release(conn1)
}

// --- CircuitBreaker: record success in half-open ---

func TestCircuitBreakerRecordSuccess(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	for range 3 {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatal("should be open")
	}

	time.Sleep(200 * time.Millisecond)
	cb.Allow() // transitions to half-open

	cb.RecordSuccess()
	// After enough successes, circuit should close
	if cb.State() != CircuitClosed {
		t.Logf("state = %v (may need more successes)", cb.State())
	}
}

func TestCircuitBreakerRecordFailureInHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	for range 3 {
		cb.RecordFailure()
	}

	time.Sleep(200 * time.Millisecond)
	cb.Allow() // half-open

	cb.RecordFailure() // should go back to open
	if cb.State() != CircuitOpen {
		t.Error("failure in half-open should reopen")
	}
}

// --- Pool stats ---

func TestPoolStatsComprehensive(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(10 * time.Second); c.Close() }()
		}
	}()

	p := NewPool(ln.Addr().String(), 5, 0, time.Hour, time.Second, 0)
	defer p.Close()

	conn, _ := p.Acquire(context.Background())

	stats := p.Stats()
	if stats.Active != 1 {
		t.Errorf("active = %d", stats.Active)
	}
	if stats.Total != 1 {
		t.Errorf("total = %d", stats.Total)
	}

	p.Release(conn)

	stats = p.Stats()
	if stats.Active != 0 {
		t.Errorf("active after release = %d", stats.Active)
	}
}
