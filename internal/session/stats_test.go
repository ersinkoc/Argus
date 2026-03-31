package session

import (
	"net"
	"testing"
)

func TestSessionStats(t *testing.T) {
	info := &Info{Username: "alice", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
	mgr := NewManager(0, 0)
	sess := mgr.Create(info, nil)

	sess.IncrementCommand()
	sess.IncrementCommand()
	sess.AddBytes(100, 200)

	cmds, bytesIn, bytesOut := sess.Stats()
	if cmds != 2 {
		t.Errorf("commands = %d, want 2", cmds)
	}
	if bytesIn != 100 {
		t.Errorf("bytesIn = %d, want 100", bytesIn)
	}
	if bytesOut != 200 {
		t.Errorf("bytesOut = %d, want 200", bytesOut)
	}
}
