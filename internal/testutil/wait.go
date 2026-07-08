// Package testutil provides shared helpers for writing deterministic tests
// without relying on time.Sleep for synchronization.
package testutil

import (
	"testing"
	"time"
)

// Eventually polls fn every interval until it returns true or timeout elapses.
// On timeout, it calls t.Fatal with the given msg and args.
func Eventually(t *testing.T, timeout, interval time.Duration, fn func() bool, msg string, args ...any) {
	t.Helper()
	deadline := time.After(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if fn() {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out after %v waiting for condition: "+msg, append([]any{timeout}, args...)...)
		case <-ticker.C:
		}
	}
}

// WaitFor polls fn every 10ms until it returns true or timeout elapses.
// On timeout, it calls t.Fatal.
func WaitFor(t *testing.T, timeout time.Duration, fn func() bool, msg string, args ...any) {
	t.Helper()
	Eventually(t, timeout, 10*time.Millisecond, fn, msg, args...)
}
