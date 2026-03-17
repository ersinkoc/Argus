package pool

import (
	"context"
	"testing"
	"time"
)

func TestPoolCircuitBreakerIntegration(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, 100*time.Millisecond, 0)

	// Port 1 should fail — circuit breaker should record failures
	for i := 0; i < 6; i++ {
		_, err := p.Acquire(context.Background())
		if err == nil {
			t.Fatal("should fail to connect to port 1")
		}
	}

	// Circuit should be open after 5 failures
	if p.breaker.State() != CircuitOpen {
		t.Errorf("breaker state = %v, want open", p.breaker.State())
	}

	p.Close()
}

func TestPoolWarmupFailure(t *testing.T) {
	// Warmup to unreachable target should not panic
	p := NewPool("127.0.0.1:1", 5, 3, time.Hour, 100*time.Millisecond, 0)
	p.Start()
	time.Sleep(200 * time.Millisecond) // let warmup attempt
	p.Close()
}

func TestPoolRelease(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, time.Second, 0)
	// Create a fake conn
	c := &Conn{createdAt: time.Now()}
	p.mu.Lock()
	p.active = 1
	p.total = 1
	p.mu.Unlock()

	p.Release(c) // should return to idle

	stats := p.Stats()
	if stats.Idle != 1 {
		t.Errorf("idle = %d, want 1", stats.Idle)
	}

	p.Close()
}

func TestPoolRemove(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, time.Second, 0)
	c := &Conn{createdAt: time.Now()}
	p.mu.Lock()
	p.active = 1
	p.total = 1
	p.mu.Unlock()

	p.Remove(c)

	stats := p.Stats()
	if stats.Total != 0 {
		t.Errorf("total = %d, want 0", stats.Total)
	}

	p.Close()
}

func TestConnExpired(t *testing.T) {
	c := &Conn{createdAt: time.Now().Add(-2 * time.Hour)}
	if !c.isExpired(time.Hour) {
		t.Error("should be expired")
	}
	if c.isExpired(0) {
		t.Error("0 lifetime = never expire")
	}
}

func TestConnCreatedAt(t *testing.T) {
	now := time.Now()
	c := &Conn{createdAt: now}
	if c.CreatedAt() != now {
		t.Error("CreatedAt mismatch")
	}
}
