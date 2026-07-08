package pool

import (
	"testing"
	"time"
)

// --- CircuitBreaker.Allow: all states ---

func TestCircuitBreakerAllowClosed(t *testing.T) {
	cb := NewCircuitBreaker(5, time.Second)
	if !cb.Allow() {
		t.Error("closed state should allow")
	}
	if cb.State() != CircuitClosed {
		t.Error("should be closed")
	}
}

func TestCircuitBreakerAllowOpenNotExpired(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Hour) // long timeout
	for range 3 {
		cb.RecordFailure()
	}
	if cb.Allow() {
		t.Error("open state before timeout should not allow")
	}
}

func TestCircuitBreakerClosedAfterHalfOpenSuccess(t *testing.T) {
	cb := NewCircuitBreaker(3, 50*time.Millisecond)
	for range 3 {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Fatal("should be open")
	}

	time.Sleep(100 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("should allow (transition to half-open)")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatal("should be half-open")
	}

	// Success in half-open → should close circuit
	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Errorf("should be closed after success, got %v", cb.State())
	}

	// Now closed — all requests allowed
	if !cb.Allow() {
		t.Error("closed should allow")
	}
}

// --- WaitHistogram ---

func TestWaitHistogramObserveAndPercentile(t *testing.T) {
	// Use the global WaitHistogram
	WaitHistogram.Observe(100)
	WaitHistogram.Observe(500)
	WaitHistogram.Observe(1000)

	snap := WaitHistogram.Snapshot()
	if snap.Count < 3 {
		t.Errorf("count = %d", snap.Count)
	}
}
