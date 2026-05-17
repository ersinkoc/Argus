package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestLimiterAllow(t *testing.T) {
	// 10 requests/sec, burst of 5
	limiter := NewLimiter(10, 5)

	// First 5 should be allowed (burst)
	for i := 0; i < 5; i++ {
		if !limiter.Allow("user1") {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}

	// 6th should be denied (burst exhausted, no time for refill)
	if limiter.Allow("user1") {
		t.Error("request 6 should be denied (burst exhausted)")
	}
}

func TestLimiterRefill(t *testing.T) {
	// 100 requests/sec, burst of 1
	limiter := NewLimiter(100, 1)

	// Use the burst
	if !limiter.Allow("user1") {
		t.Error("first request should be allowed")
	}
	if limiter.Allow("user1") {
		t.Error("second request should be denied")
	}

	// Wait for refill (at 100/sec, should refill in 10ms)
	time.Sleep(20 * time.Millisecond)

	if !limiter.Allow("user1") {
		t.Error("after refill, request should be allowed")
	}
}

func TestLimiterDifferentKeys(t *testing.T) {
	limiter := NewLimiter(1, 1)

	if !limiter.Allow("user1") {
		t.Error("user1 first request should be allowed")
	}
	if !limiter.Allow("user2") {
		t.Error("user2 first request should be allowed (independent)")
	}

	// user1 should be limited
	if limiter.Allow("user1") {
		t.Error("user1 second request should be denied")
	}
}

func TestLimiterReset(t *testing.T) {
	limiter := NewLimiter(1, 1)

	limiter.Allow("user1")
	if limiter.Allow("user1") {
		t.Error("should be limited")
	}

	limiter.Reset("user1")
	if !limiter.Allow("user1") {
		t.Error("after reset, should be allowed")
	}
}

func TestLimiterCleanup(t *testing.T) {
	limiter := NewLimiter(1, 1)
	limiter.cleanup = 1 * time.Millisecond

	limiter.Allow("user1")
	limiter.Allow("user2")

	if limiter.Stats() != 2 {
		t.Errorf("stats = %d, want 2", limiter.Stats())
	}

	time.Sleep(5 * time.Millisecond)
	limiter.Cleanup()

	if limiter.Stats() != 0 {
		t.Errorf("after cleanup, stats = %d, want 0", limiter.Stats())
	}
}

func BenchmarkLimiterAllow(b *testing.B) {
	limiter := NewLimiter(1000000, 1000)
	for b.Loop() {
		limiter.Allow("user1")
	}
}

func TestStartCleanupRunner(t *testing.T) {
	limiter := NewLimiter(1, 10)
	ctx, cancel := context.WithCancel(context.Background())

	limiter.Allow("user1")
	limiter.Allow("user2")
	if limiter.Stats() != 2 {
		t.Errorf("stats = %d, want 2", limiter.Stats())
	}

	limiter.StartCleanupRunner(ctx)
	time.Sleep(50 * time.Millisecond)

	if limiter.Stats() != 2 {
		t.Errorf("stats = %d, want 2 (no cleanup yet)", limiter.Stats())
	}

	cancel()
	time.Sleep(10 * time.Millisecond)
	// After cancel, goroutine should stop (no panic)
}

func TestStop(t *testing.T) {
	limiter := NewLimiter(1, 10)

	limiter.StartCleanupRunner(context.Background())
	limiter.Stop()
}
