package cluster

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/session"
	"github.com/ersinkoc/argus/internal/testutil"
)

func TestSessionMirrorCreateAndRemove(t *testing.T) {
	store := NewMemoryStore()
	mirror := NewSessionMirror("node-1", store, 0)

	mgr := session.NewManager(0, 0)
	mgr.SetObserver(mirror)

	sess := mgr.Create(&session.Info{
		Username: "alice", Database: "app", ClientIP: net.ParseIP("10.0.0.9"),
	}, nil)
	sess.SetRoles([]string{"analyst"})

	entry, err := store.Get(sess.ID)
	if err != nil {
		t.Fatalf("Get after create: %v", err)
	}
	if entry.Username != "alice" || entry.Database != "app" || entry.NodeID != "node-1" {
		t.Fatalf("entry = %+v, want alice/app/node-1", entry)
	}
	if entry.ClientIP != "10.0.0.9" {
		t.Fatalf("ClientIP = %q, want 10.0.0.9", entry.ClientIP)
	}

	mgr.Remove(sess.ID)
	if _, err := store.Get(sess.ID); err == nil {
		t.Fatal("entry should be deleted after Remove")
	}
	if store.Count() != 0 {
		t.Fatalf("store count = %d, want 0", store.Count())
	}
}

func TestSessionMirrorKillRemovesEntry(t *testing.T) {
	store := NewMemoryStore()
	mgr := session.NewManager(0, 0)
	mgr.SetObserver(NewSessionMirror("node-1", store, 0))

	client, other := net.Pipe()
	defer other.Close()
	sess := mgr.Create(&session.Info{Username: "bob"}, client)

	if err := mgr.Kill(sess.ID); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if _, err := store.Get(sess.ID); err == nil {
		t.Fatal("entry should be deleted after Kill")
	}
}

func TestSessionMirrorAliveRefreshesEntry(t *testing.T) {
	store := NewMemoryStore()
	mgr := session.NewManager(0, 0)
	mgr.SetObserver(NewSessionMirror("node-1", store, time.Minute))
	mgr.SetCheckInterval(5 * time.Millisecond)

	sess := mgr.Create(&session.Info{Username: "carol"}, nil)
	sess.SetRoles([]string{"dba"})
	sess.IncrementCommand()

	mgr.Start()
	defer mgr.Stop()

	testutil.WaitFor(t, time.Second, func() bool {
		entry, err := store.Get(sess.ID)
		return err == nil && entry.CommandCount == 1 && len(entry.Roles) == 1 && entry.Roles[0] == "dba"
	}, "SessionAlive should refresh entry with roles and command count")
}

func TestSessionMirrorTimeoutRemovesEntry(t *testing.T) {
	store := NewMemoryStore()
	mgr := session.NewManager(time.Nanosecond, 0)
	mgr.SetObserver(NewSessionMirror("node-1", store, 0))
	mgr.SetCheckInterval(5 * time.Millisecond)

	sess := mgr.Create(&session.Info{Username: "dave"}, nil)
	mgr.Start()
	defer mgr.Stop()

	testutil.WaitFor(t, time.Second, func() bool {
		_, err := store.Get(sess.ID)
		return err != nil
	}, "idle timeout should delete the mirrored entry")
}

// failingStore forces the error paths in SessionMirror.
type failingStore struct{}

func (f *failingStore) Put(string, *SessionEntry, time.Duration) error {
	return fmt.Errorf("put failed")
}
func (f *failingStore) Get(string) (*SessionEntry, error) { return nil, fmt.Errorf("not found") }
func (f *failingStore) Delete(string) error               { return fmt.Errorf("delete failed") }
func (f *failingStore) List(string) ([]*SessionEntry, error) {
	return nil, fmt.Errorf("list failed")
}
func (f *failingStore) Touch(string) error { return fmt.Errorf("touch failed") }
func (f *failingStore) Close() error       { return nil }

func TestSessionMirrorStoreErrorsAreNonFatal(t *testing.T) {
	mirror := NewSessionMirror("node-1", &failingStore{}, 0)
	mgr := session.NewManager(0, 0)
	mgr.SetObserver(mirror)

	sess := mgr.Create(&session.Info{Username: "erin"}, nil)
	mirror.SessionAlive(sess)
	mgr.Remove(sess.ID)
}
