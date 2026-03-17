package ratelimit

import (
	"sync"
	"time"
)

// Limiter implements a token bucket rate limiter per key (user/role).
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   int     // max tokens
	cleanup time.Duration
}

type bucket struct {
	tokens    float64
	lastFill  time.Time
}

// NewLimiter creates a rate limiter.
// rate: queries per second allowed. burst: max burst size.
func NewLimiter(rate float64, burst int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		cleanup: 5 * time.Minute,
	}
}

// Allow checks if a request is allowed for the given key.
// Returns true if allowed, false if rate limited.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			tokens:   float64(l.burst),
			lastFill: now,
		}
		l.buckets[key] = b
	}

	// Refill tokens
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastFill = now

	// Try to consume a token
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// Reset resets the limiter for a specific key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.buckets, key)
	l.mu.Unlock()
}

// Cleanup removes stale entries older than the cleanup duration.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-l.cleanup)
	for key, b := range l.buckets {
		if b.lastFill.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}

// Stats returns the number of tracked keys.
func (l *Limiter) Stats() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
