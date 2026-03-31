package session

import (
	"net"
	"testing"
	"time"
)

func TestSessionDuration(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)
	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	time.Sleep(10 * time.Millisecond)
	d := sess.Duration()
	if d < 10*time.Millisecond {
		t.Errorf("duration = %v, expected >= 10ms", d)
	}
}

func TestSessionIdleDuration(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)
	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	time.Sleep(10 * time.Millisecond)
	idle := sess.IdleDuration()
	if idle < 10*time.Millisecond {
		t.Errorf("idle = %v, expected >= 10ms", idle)
	}

	sess.Touch()
	idle2 := sess.IdleDuration()
	if idle2 >= idle {
		t.Error("idle should decrease after Touch")
	}
}

func TestSessionAddBytes(t *testing.T) {
	mgr := NewManager(0, 0)
	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	sess.AddBytes(100, 200)
	sess.AddBytes(50, 100)

	if sess.BytesIn != 150 {
		t.Errorf("BytesIn = %d, want 150", sess.BytesIn)
	}
	if sess.BytesOut != 300 {
		t.Errorf("BytesOut = %d, want 300", sess.BytesOut)
	}
}

func TestSessionKill(t *testing.T) {
	mgr := NewManager(0, 0)
	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	err := mgr.Kill(sess.ID)
	if err != nil {
		t.Errorf("Kill: %v", err)
	}
	if mgr.Count() != 0 {
		t.Error("session should be removed after kill")
	}

	err = mgr.Kill("nonexistent")
	if err == nil {
		t.Error("Kill nonexistent should error")
	}
}

func TestSessionTimeoutCheck(t *testing.T) {
	mgr := NewManager(50*time.Millisecond, 0)

	timedOut := make(chan string, 1)
	mgr.OnTimeout(func(s *Session, _ string) {
		timedOut <- s.ID
	})

	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	mgr.Create(info, nil)

	mgr.Start()
	defer mgr.Stop()

	// Force a check
	time.Sleep(100 * time.Millisecond)
	mgr.checkTimeouts()

	select {
	case <-timedOut:
		// OK
	case <-time.After(time.Second):
		t.Error("timeout callback should have been called")
	}

	if mgr.Count() != 0 {
		t.Error("timed out session should be removed")
	}
}
