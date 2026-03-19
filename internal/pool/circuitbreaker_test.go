package pool

import (
	"testing"
	"time"
)

func TestCircuitBreakerClosed(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Second)

	// Closed state: all requests allowed
	for i := 0; i < 10; i++ {
		if !cb.Allow() {
			t.Errorf("request %d should be allowed in closed state", i)
		}
		cb.RecordSuccess()
	}

	if cb.State() != CircuitClosed {
		t.Errorf("state = %v, want closed", cb.State())
	}
}

func TestCircuitBreakerOpen(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Second)

	// 3 failures should open the circuit
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != CircuitOpen {
		t.Errorf("state = %v, want open after 3 failures", cb.State())
	}

	// Requests should be rejected
	if cb.Allow() {
		t.Error("should reject in open state")
	}
}

func TestCircuitBreakerHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	// Open the circuit
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != CircuitOpen {
		t.Fatalf("state = %v, want open", cb.State())
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Should transition to half-open and allow one test request
	if !cb.Allow() {
		t.Error("should allow test request in half-open state")
	}

	if cb.State() != CircuitHalfOpen {
		t.Errorf("state = %v, want half-open", cb.State())
	}

	// Success in half-open → close
	cb.RecordSuccess()

	if cb.State() != CircuitClosed {
		t.Errorf("state = %v, want closed after half-open success", cb.State())
	}
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(60 * time.Millisecond)
	cb.Allow() // triggers half-open

	// Failure in half-open → back to open
	cb.RecordFailure()

	if cb.State() != CircuitOpen {
		t.Errorf("state = %v, want open after half-open failure", cb.State())
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	cb := NewCircuitBreaker(1, time.Second)
	cb.RecordFailure()

	if cb.State() != CircuitOpen {
		t.Fatal("should be open")
	}

	cb.Reset()

	if cb.State() != CircuitClosed {
		t.Errorf("state = %v, want closed after reset", cb.State())
	}
	if !cb.Allow() {
		t.Error("should allow after reset")
	}
}

func TestPoolSetCircuitBreaker(t *testing.T) {
	// SetCircuitBreaker replaces the breaker — just verify it doesn't panic
	// and the pool continues to function.
	p := NewPool("127.0.0.1:1", 5, 0, 0, 0, 0)
	p.SetCircuitBreaker(10, 5*time.Second)
	// Pool not started — just verify the breaker was replaced
	if p.breaker == nil {
		t.Error("breaker should not be nil after SetCircuitBreaker")
	}
}

func TestCircuitBreakerSuccessResetsFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, time.Second)

	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess() // resets failure count

	// 2 more failures should NOT open (total is now 2, not 4)
	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != CircuitClosed {
		t.Error("success should reset failure count")
	}

	// One more opens it
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Error("3 consecutive failures should open")
	}
}
