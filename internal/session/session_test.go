package session

import (
	"net"
	"testing"
	"time"
)

func TestSessionCreate(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)

	info := &Info{
		Username:   "testuser",
		Database:   "testdb",
		ClientIP:   net.ParseIP("192.168.1.100"),
		AuthMethod: "md5",
	}

	sess := mgr.Create(info, nil)

	if sess.ID == "" {
		t.Error("session ID should not be empty")
	}
	if sess.Username != "testuser" {
		t.Errorf("username = %q, want %q", sess.Username, "testuser")
	}
	if sess.Database != "testdb" {
		t.Errorf("database = %q, want %q", sess.Database, "testdb")
	}
	if mgr.Count() != 1 {
		t.Errorf("count = %d, want 1", mgr.Count())
	}
}

func TestSessionGet(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)

	info := &Info{Username: "testuser", Database: "testdb", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	got := mgr.Get(sess.ID)
	if got == nil {
		t.Fatal("Get should return the session")
	}
	if got.Username != "testuser" {
		t.Errorf("username = %q, want %q", got.Username, "testuser")
	}

	if mgr.Get("nonexistent") != nil {
		t.Error("Get should return nil for unknown ID")
	}
}

func TestSessionRemove(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)

	info := &Info{Username: "testuser", Database: "testdb", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	mgr.Remove(sess.ID)
	if mgr.Count() != 0 {
		t.Errorf("count = %d, want 0 after remove", mgr.Count())
	}
}

func TestSessionTouch(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)

	info := &Info{Username: "testuser", Database: "testdb", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	before := sess.LastActivity
	time.Sleep(10 * time.Millisecond)
	sess.Touch()

	if !sess.LastActivity.After(before) {
		t.Error("Touch should update LastActivity")
	}
}

func TestSessionIncrementCommand(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)

	info := &Info{Username: "testuser", Database: "testdb", ClientIP: net.ParseIP("127.0.0.1")}
	sess := mgr.Create(info, nil)

	sess.IncrementCommand()
	sess.IncrementCommand()
	sess.IncrementCommand()

	if sess.CommandCount != 3 {
		t.Errorf("command count = %d, want 3", sess.CommandCount)
	}
}

func TestSessionActiveSessions(t *testing.T) {
	mgr := NewManager(30*time.Minute, 8*time.Hour)

	for i := 0; i < 5; i++ {
		info := &Info{Username: "user", Database: "db", ClientIP: net.ParseIP("127.0.0.1")}
		mgr.Create(info, nil)
	}

	sessions := mgr.ActiveSessions()
	if len(sessions) != 5 {
		t.Errorf("active sessions = %d, want 5", len(sessions))
	}
}
