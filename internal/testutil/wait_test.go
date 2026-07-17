package testutil

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestEventuallyPasses(t *testing.T) {
	counter := 0
	Eventually(t, time.Second, 10*time.Millisecond, func() bool {
		counter++
		return counter >= 3
	}, "counter should reach 3")
}

func TestWaitForPasses(t *testing.T) {
	var ready atomic.Bool
	go func() {
		time.Sleep(20 * time.Millisecond)
		ready.Store(true)
	}()
	WaitFor(t, time.Second, func() bool { return ready.Load() }, "goroutine should set ready")
}
