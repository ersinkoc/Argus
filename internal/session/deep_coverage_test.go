package session

import (
	"net"
	"testing"
	"time"
)

// --- Session timeout via checkTimeouts ---

func TestManagerCheckTimeoutsIdle(t *testing.T) {
	m := NewManager(100*time.Millisecond, 0) // 100ms idle timeout
	m.Start()
	defer m.Stop()

	timedOut := make(chan string, 1)
	m.OnTimeout(func(s *Session) {
		timedOut <- s.ID
	})

	conn, _ := net.Pipe()
	defer conn.Close()

	info := &Info{Username: "timeout_user", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	sess := m.Create(info, conn)
	_ = sess

	// Wait for idle timeout + ticker (30s is too long — trigger manually)
	time.Sleep(150 * time.Millisecond)
	m.checkTimeouts() // manually trigger

	select {
	case id := <-timedOut:
		if id == "" {
			t.Error("should have session ID")
		}
	case <-time.After(time.Second):
		t.Error("timeout callback not fired")
	}
}

func TestManagerCheckTimeoutsMaxDuration(t *testing.T) {
	m := NewManager(0, 100*time.Millisecond) // 100ms max duration
	m.Start()
	defer m.Stop()

	timedOut := make(chan bool, 1)
	m.OnTimeout(func(s *Session) {
		timedOut <- true
	})

	conn, _ := net.Pipe()
	defer conn.Close()

	info := &Info{Username: "duration_user", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	sess := m.Create(info, conn)

	// Keep session active
	sess.IncrementCommand()

	time.Sleep(150 * time.Millisecond)
	m.checkTimeouts()

	select {
	case <-timedOut:
		// OK
	case <-time.After(time.Second):
		t.Error("max duration timeout not fired")
	}
}

func TestManagerCheckTimeoutsNoTimeout(t *testing.T) {
	m := NewManager(time.Hour, time.Hour) // very long timeouts
	m.Start()
	defer m.Stop()

	conn, _ := net.Pipe()
	defer conn.Close()

	info := &Info{Username: "u", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	m.Create(info, conn)

	m.checkTimeouts() // should not timeout anything
	if m.Count() != 1 {
		t.Errorf("count = %d", m.Count())
	}
}

// --- Kill ---

func TestManagerKill(t *testing.T) {
	m := NewManager(time.Hour, time.Hour)
	m.Start()
	defer m.Stop()

	conn, _ := net.Pipe()

	info := &Info{Username: "kill_user", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	sess := m.Create(info, conn)

	m.Kill(sess.ID)

	if m.Count() != 0 {
		t.Errorf("count after kill = %d", m.Count())
	}

	conn.Close()
}
