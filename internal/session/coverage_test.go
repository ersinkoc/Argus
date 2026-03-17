package session

import (
	"net"
	"testing"
	"time"
)

func TestCheckTimeoutsMaxDuration(t *testing.T) {
	mgr := NewManager(0, 50*time.Millisecond) // no idle timeout, 50ms max duration

	timedOut := make(chan string, 1)
	mgr.OnTimeout(func(s *Session) {
		timedOut <- s.ID
	})

	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	mgr.Create(info, nil)

	time.Sleep(100 * time.Millisecond) // exceed max duration
	mgr.checkTimeouts()

	select {
	case <-timedOut:
		// OK
	case <-time.After(time.Second):
		t.Error("max duration timeout should have fired")
	}

	if mgr.Count() != 0 {
		t.Error("session should be removed after max duration timeout")
	}
}

func TestCheckTimeoutsIdleAndMax(t *testing.T) {
	mgr := NewManager(50*time.Millisecond, 50*time.Millisecond)

	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	mgr.Create(info, nil)

	time.Sleep(100 * time.Millisecond)
	mgr.checkTimeouts()

	if mgr.Count() != 0 {
		t.Error("session should be removed")
	}
}

func TestCheckTimeoutsNoTimeout(t *testing.T) {
	mgr := NewManager(time.Hour, time.Hour)

	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	mgr.Create(info, nil)

	mgr.checkTimeouts() // should NOT remove (not timed out)

	if mgr.Count() != 1 {
		t.Error("session should still exist (not timed out)")
	}
}
