package session

import (
	"net"
	"testing"
	"time"
)

func TestKillWithConnections(t *testing.T) {
	// Create two connected pipes to simulate client/backend
	clientConn, clientServer := net.Pipe()
	backendConn, backendServer := net.Pipe()
	defer clientServer.Close()
	defer backendServer.Close()

	mgr := NewManager(0, 0)
	info := &Info{Username: "u", Database: "d", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, clientConn)
	sess.BackendConn = backendConn

	err := mgr.Kill(sess.ID)
	if err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if mgr.Count() != 0 {
		t.Error("should be removed")
	}
}

func TestTimeoutLoopStops(t *testing.T) {
	mgr := NewManager(time.Hour, time.Hour)
	mgr.Start()
	time.Sleep(50 * time.Millisecond)
	mgr.Stop() // should not hang
}
