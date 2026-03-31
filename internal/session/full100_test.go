package session

import (
	"net"
	"testing"
	"time"
)

// --- timeoutLoop: ticker fires and calls checkTimeouts ---

func TestTimeoutLoopTickerFires(t *testing.T) {
	m := NewManager(50*time.Millisecond, 0) // 50ms idle timeout
	m.checkInterval = 50 * time.Millisecond  // fast check interval for test

	timedOut := make(chan string, 1)
	m.OnTimeout(func(s *Session, reason string) {
		timedOut <- reason
	})

	conn, _ := net.Pipe()
	defer conn.Close()

	info := &Info{Username: "u", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	m.Create(info, conn)

	m.Start()
	defer m.Stop()

	select {
	case reason := <-timedOut:
		if reason != "idle_timeout" {
			t.Errorf("reason = %q, want idle_timeout", reason)
		}
	case <-time.After(2 * time.Second):
		t.Error("ticker should have fired and triggered timeout")
	}
}

// --- checkTimeouts: timeout with BackendConn set ---

func TestCheckTimeoutsWithBackendConn(t *testing.T) {
	m := NewManager(50*time.Millisecond, 0)

	clientConn, clientServer := net.Pipe()
	backendConn, backendServer := net.Pipe()
	defer clientServer.Close()
	defer backendServer.Close()

	info := &Info{Username: "u", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	sess := m.Create(info, clientConn)
	sess.BackendConn = backendConn

	called := false
	m.OnTimeout(func(s *Session, reason string) {
		called = true
	})

	time.Sleep(100 * time.Millisecond)
	m.checkTimeouts()

	if !called {
		t.Error("timeout callback should have been called")
	}
	if m.Count() != 0 {
		t.Errorf("session should be removed, count = %d", m.Count())
	}
}

// --- checkTimeouts: timeout with nil onTimeout callback ---

func TestCheckTimeoutsNoCallback(t *testing.T) {
	m := NewManager(50*time.Millisecond, 0)
	// No OnTimeout callback set

	conn, _ := net.Pipe()
	defer conn.Close()

	info := &Info{Username: "u", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	m.Create(info, conn)

	time.Sleep(100 * time.Millisecond)
	m.checkTimeouts() // should not panic with nil onTimeout

	if m.Count() != 0 {
		t.Errorf("session should be removed, count = %d", m.Count())
	}
}

// --- checkTimeouts: timeout with nil ClientConn ---

func TestCheckTimeoutsNilClientConn(t *testing.T) {
	m := NewManager(50*time.Millisecond, 0)

	info := &Info{Username: "u", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	m.Create(info, nil) // nil clientConn

	time.Sleep(100 * time.Millisecond)
	m.checkTimeouts() // should not panic

	if m.Count() != 0 {
		t.Errorf("session should be removed, count = %d", m.Count())
	}
}
