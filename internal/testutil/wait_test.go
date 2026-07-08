package testutil

import (
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
	ready := false
	go func() {
		time.Sleep(20 * time.Millisecond)
		ready = true
	}()
	WaitFor(t, time.Second, func() bool { return ready }, "goroutine should set ready")
}
