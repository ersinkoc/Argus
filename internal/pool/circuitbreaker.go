package pool

import (
	"sync"
	"time"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // normal operation
	CircuitOpen                         // failing, reject requests
	CircuitHalfOpen                     // testing recovery
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	}
	return "unknown"
}

// CircuitBreaker prevents cascading failures by tracking error rates
// and temporarily rejecting requests when a target is consistently failing.
type CircuitBreaker struct {
	mu           sync.Mutex
	state        CircuitState
	failures     int
	successes    int
	threshold    int           // failures before opening
	resetTimeout time.Duration // how long to stay open before half-open
	lastFailure  time.Time
	halfOpenMax  int           // max test requests in half-open state
}

// NewCircuitBreaker creates a circuit breaker.
// threshold: consecutive failures before opening.
// resetTimeout: duration to wait before allowing test requests.
func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if resetTimeout <= 0 {
		resetTimeout = 30 * time.Second
	}
	return &CircuitBreaker{
		state:        CircuitClosed,
		threshold:    threshold,
		resetTimeout: resetTimeout,
		halfOpenMax:  1,
	}
}

// Allow checks if a request should be allowed through.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if reset timeout has passed
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = CircuitHalfOpen
			cb.successes = 0
			return true
		}
		return false

	case CircuitHalfOpen:
		// Allow limited test requests
		return cb.successes < cb.halfOpenMax
	}

	return false
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0

	if cb.state == CircuitHalfOpen {
		cb.successes++
		if cb.successes >= cb.halfOpenMax {
			cb.state = CircuitClosed
		}
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.state == CircuitHalfOpen {
		cb.state = CircuitOpen
		return
	}

	if cb.failures >= cb.threshold {
		cb.state = CircuitOpen
	}
}

// State returns the current state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = CircuitClosed
	cb.failures = 0
	cb.successes = 0
}
