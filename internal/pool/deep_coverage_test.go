package pool

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- SharedPool.Acquire error paths ---

func TestSharedPoolAcquireClosed(t *testing.T) {
	sp := NewSharedPool("127.0.0.1:1", 5, time.Hour, 100*time.Millisecond, 0)
	sp.Close()

	_, err := sp.Acquire(context.Background())
	if err == nil {
		t.Error("closed pool should fail")
	}
}

func TestSharedPoolAcquireCreateError(t *testing.T) {
	// Unreachable address — createConn will fail
	sp := NewSharedPool("127.0.0.1:1", 5, time.Hour, 100*time.Millisecond, 0)
	defer sp.Close()

	_, err := sp.Acquire(context.Background())
	if err == nil {
		t.Error("unreachable address should fail")
	}
}

func TestSharedPoolAcquireContextCancel(t *testing.T) {
	// Pool at max capacity with no idle connections
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

	sp := NewSharedPool(ln.Addr().String(), 1, time.Hour, time.Second, 0)
	defer sp.Close()

	// Acquire the only slot
	conn1, err := sp.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// Second acquire with short timeout — should block then cancel
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = sp.Acquire(ctx)
	if err == nil {
		t.Error("should fail on context cancel")
	}

	sp.Release(conn1)
}

func TestSharedPoolReleaseToWaiter(t *testing.T) {
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

	sp := NewSharedPool(ln.Addr().String(), 1, time.Hour, time.Second, 0)
	defer sp.Close()

	// Acquire the only slot
	conn1, err := sp.Acquire(context.Background())
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// Start a waiter goroutine
	done := make(chan error, 1)
	go func() {
		conn2, err := sp.Acquire(context.Background())
		if err != nil {
			done <- err
			return
		}
		sp.Release(conn2)
		done <- nil
	}()

	// Give the waiter time to register
	time.Sleep(100 * time.Millisecond)

	// Release — should go to the waiter
	sp.Release(conn1)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("waiter should succeed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("waiter timed out")
	}
}

func TestSharedPoolReleaseExpired(t *testing.T) {
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

	sp := NewSharedPool(ln.Addr().String(), 5, 1*time.Millisecond, time.Second, 0) // 1ms lifetime
	defer sp.Close()

	conn, err := sp.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	time.Sleep(10 * time.Millisecond) // let it expire

	// Release expired connection — should be discarded
	sp.Release(conn)
}

// --- Histogram edge cases ---

func TestHistogramPercentileOverflow(t *testing.T) {
	h := NewHistogram([]float64{100, 500, 1000})

	// All observations exceed the highest bucket
	for range 10 {
		h.Observe(5000)
	}

	p99 := h.Percentile(99)
	if p99 != 2000 { // bounds[len-1] * 2 = 1000 * 2
		t.Errorf("p99 = %f, want 2000", p99)
	}
}

func TestHistogramPercentileEmpty(t *testing.T) {
	h := NewHistogram([]float64{100, 500, 1000})
	if h.Percentile(50) != 0 {
		t.Error("empty histogram should return 0")
	}
}

func TestHistogramSnapshotFormatting(t *testing.T) {
	h := NewHistogram([]float64{100, 1000, 10000})
	h.Observe(50)
	h.Observe(500)
	h.Observe(5000)

	snap := h.Snapshot()
	if snap.Count != 3 {
		t.Errorf("count = %d", snap.Count)
	}
	if len(snap.Buckets) == 0 {
		t.Error("buckets should be populated")
	}
}

func TestItoa64Negative(t *testing.T) {
	if itoa64(-42) != "-42" {
		t.Errorf("itoa64(-42) = %q", itoa64(-42))
	}
}

func TestItoa64LargeNumber(t *testing.T) {
	if itoa64(123456789) != "123456789" {
		t.Errorf("itoa64(123456789) = %q", itoa64(123456789))
	}
}

func TestFormatBoundSeconds(t *testing.T) {
	s := formatBound(1500000) // 1.5 seconds
	if s != "1.5s" {
		t.Errorf("formatBound(1500000) = %q", s)
	}
}

func TestFormatBoundMilliseconds(t *testing.T) {
	s := formatBound(1500) // 1.5ms
	if s != "1.5ms" {
		t.Errorf("formatBound(1500) = %q", s)
	}
}

func TestFormatBoundMicroseconds(t *testing.T) {
	s := formatBound(500) // 500us
	if s != "500us" {
		t.Errorf("formatBound(500) = %q", s)
	}
}

// --- Circuit breaker Allow paths ---

func TestCircuitBreakerAllowHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	// Trip the breaker
	for range 3 {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Error("should be open")
	}

	// Wait for cooldown
	time.Sleep(200 * time.Millisecond)

	// Allow() transitions from Open to HalfOpen and returns true
	if !cb.Allow() {
		t.Error("should allow after cooldown (transition to half-open)")
	}

	if cb.State() != CircuitHalfOpen {
		t.Error("should be half-open after Allow()")
	}

	// Record success to close the circuit
	cb.RecordSuccess()
}
