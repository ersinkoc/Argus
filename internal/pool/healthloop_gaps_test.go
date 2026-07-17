package pool

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/testutil"
)

// closedTarget returns a 127.0.0.1 address that is guaranteed not to be
// listening: it binds an ephemeral port and immediately closes the listener,
// so dials fail fast with connection refused.
func closedTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// --- NewCircuitBreaker: default clamping of invalid parameters ---

func TestNewCircuitBreakerDefaults(t *testing.T) {
	cb := NewCircuitBreaker(0, 0)
	if cb.threshold != 5 {
		t.Errorf("threshold = %d, want default 5", cb.threshold)
	}
	if cb.resetTimeout != 30*time.Second {
		t.Errorf("resetTimeout = %v, want default 30s", cb.resetTimeout)
	}
	if cb.HalfOpenMax() != 1 {
		t.Errorf("HalfOpenMax = %d, want default 1", cb.HalfOpenMax())
	}

	cb = NewCircuitBreaker(-3, -time.Second)
	if cb.threshold != 5 || cb.resetTimeout != 30*time.Second {
		t.Errorf("negative args not clamped: threshold=%d resetTimeout=%v", cb.threshold, cb.resetTimeout)
	}
}

// --- CircuitBreaker.SetHalfOpenMax / HalfOpenMax ---

func TestCircuitBreakerSetHalfOpenMax(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Second)

	cb.SetHalfOpenMax(4)
	if got := cb.HalfOpenMax(); got != 4 {
		t.Errorf("HalfOpenMax = %d, want 4", got)
	}

	// Non-positive values are ignored
	cb.SetHalfOpenMax(0)
	if got := cb.HalfOpenMax(); got != 4 {
		t.Errorf("HalfOpenMax after SetHalfOpenMax(0) = %d, want 4 (unchanged)", got)
	}
	cb.SetHalfOpenMax(-2)
	if got := cb.HalfOpenMax(); got != 4 {
		t.Errorf("HalfOpenMax after SetHalfOpenMax(-2) = %d, want 4 (unchanged)", got)
	}
}

func TestCircuitBreakerHalfOpenMaxBehavior(t *testing.T) {
	cb := NewCircuitBreaker(2, time.Minute)
	cb.SetHalfOpenMax(2)

	// Trip the breaker to open
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatal("breaker should be open")
	}

	// Backdate lastFailure so Allow() transitions to half-open without sleeping
	cb.mu.Lock()
	cb.lastFailure = time.Now().Add(-time.Hour)
	cb.mu.Unlock()

	if !cb.Allow() {
		t.Fatal("should allow test request after reset timeout")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatal("breaker should be half-open")
	}

	// With halfOpenMax=2, one success is not enough to close
	cb.RecordSuccess()
	if cb.State() != CircuitHalfOpen {
		t.Errorf("state after 1 success = %v, want half-open (need 2)", cb.State())
	}
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("state after 2 successes = %v, want closed", cb.State())
	}
}

// --- Conn.NetConn ---

func TestConnNetConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	c := &Conn{conn: client, createdAt: time.Now()}
	if c.NetConn() != client {
		t.Error("NetConn should return the wrapped net.Conn")
	}

	var empty Conn
	if empty.NetConn() != nil {
		t.Error("NetConn on zero Conn should return nil")
	}
}

// --- CheckAllTargets: concurrent multi-target health check ---

func TestCheckAllTargets(t *testing.T) {
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

	good := ln.Addr().String()
	bad := closedTarget(t)

	results := CheckAllTargets([]string{good, bad}, 2*time.Second)
	if len(results) != 2 {
		t.Fatalf("results = %d entries, want 2", len(results))
	}

	if !results[good].Healthy {
		t.Errorf("target %s should be healthy: %+v", good, results[good])
	}
	if results[bad].Healthy {
		t.Errorf("target %s should be unhealthy", bad)
	}
	if results[bad].LastError == "" {
		t.Error("unhealthy target should report LastError")
	}
}

func TestCheckAllTargetsEmpty(t *testing.T) {
	results := CheckAllTargets(nil, time.Second)
	if len(results) != 0 {
		t.Errorf("results = %d entries, want 0", len(results))
	}
}

// --- itoa64: zero input ---

func TestItoa64Zero(t *testing.T) {
	if got := itoa64(0); got != "0" {
		t.Errorf("itoa64(0) = %q, want \"0\"", got)
	}
	if got := itoa64(-42); got != "-42" {
		t.Errorf("itoa64(-42) = %q, want \"-42\"", got)
	}
}

// --- Pool.SetConnectFunc: custom connect function is used ---

func TestPoolSetConnectFunc(t *testing.T) {
	var called atomic.Bool
	var mu sync.Mutex
	var serverEnds []net.Conn

	p := NewPool("unused-target:0", 2, 0, time.Hour, time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		called.Store(true)
		client, server := net.Pipe()
		mu.Lock()
		serverEnds = append(serverEnds, server)
		mu.Unlock()
		return client, nil
	})
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range serverEnds {
			s.Close()
		}
	}()

	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if !called.Load() {
		t.Error("custom connect function was not called")
	}
	if conn.NetConn() == nil {
		t.Error("acquired conn should wrap the pipe connection")
	}
	p.Remove(conn)
	p.Close()
}

// --- Pool.SetBreakerHalfOpenMax ---

func TestPoolSetBreakerHalfOpenMax(t *testing.T) {
	p := NewPool("127.0.0.1:1", 1, 0, time.Hour, time.Second, 0)
	p.SetBreakerHalfOpenMax(3)
	if got := p.breaker.HalfOpenMax(); got != 3 {
		t.Errorf("breaker HalfOpenMax = %d, want 3", got)
	}
	p.Close()
}

// --- Pool.healthCheckLoop: ticker fires, checkHealth failure path, stop ---

func TestPoolHealthCheckLoopDetectsUnhealthy(t *testing.T) {
	// Target refuses connections, so the periodic health check must flip
	// the pool to unhealthy (covers the healthy -> unhealthy transition).
	p := NewPool(closedTarget(t), 5, 0, time.Hour, time.Second, 10*time.Millisecond)
	p.Start()

	testutil.WaitFor(t, 2*time.Second, func() bool {
		return !p.IsHealthy()
	}, "pool should become unhealthy via health check loop")

	// A second failing check exercises the already-unhealthy branch
	// (no repeated "now unhealthy" log).
	p.checkHealth()
	if p.IsHealthy() {
		t.Error("pool should remain unhealthy")
	}

	// Close stops the loop via stopCh.
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// --- SharedPool.SetConnectFunc ---

func TestSharedPoolSetConnectFunc(t *testing.T) {
	var called atomic.Bool
	var mu sync.Mutex
	var serverEnds []net.Conn

	sp := NewSharedPool("unused-target:0", 2, time.Hour, time.Second, 0)
	sp.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		called.Store(true)
		client, server := net.Pipe()
		mu.Lock()
		serverEnds = append(serverEnds, server)
		mu.Unlock()
		return client, nil
	})
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, s := range serverEnds {
			s.Close()
		}
	}()

	conn, err := sp.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if !called.Load() {
		t.Error("custom connect function was not called")
	}
	sp.Release(conn)
	sp.Close()
}

// --- SharedPool.Start / healthLoop: ticker fires and stop path ---

func TestSharedPoolStartHealthLoop(t *testing.T) {
	sp := NewSharedPool(closedTarget(t), 5, time.Hour, time.Second, 10*time.Millisecond)
	sp.Start()

	testutil.WaitFor(t, 2*time.Second, func() bool {
		return !sp.Stats().Healthy
	}, "shared pool should become unhealthy via health loop")

	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSharedPoolStartNoHealthInterval(t *testing.T) {
	// healthInterval == 0: Start must not spawn a health loop.
	sp := NewSharedPool("127.0.0.1:1", 1, time.Hour, time.Second, 0)
	sp.Start()
	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
