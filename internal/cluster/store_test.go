package cluster

import (
	"testing"
	"time"
)

func TestMemoryStoreBasic(t *testing.T) {
	store := NewMemoryStore()

	entry := &SessionEntry{
		ID:       "s1",
		Username: "alice",
		Database: "prod",
		NodeID:   "node-1",
	}

	// Put
	err := store.Put("s1", entry, time.Hour)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Get
	got, err := store.Get("s1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("username = %q", got.Username)
	}

	// Count
	if store.Count() != 1 {
		t.Errorf("count = %d", store.Count())
	}

	// Touch
	err = store.Touch("s1")
	if err != nil {
		t.Fatalf("Touch: %v", err)
	}

	// Delete
	store.Delete("s1")
	_, err = store.Get("s1")
	if err == nil {
		t.Error("deleted session should not be found")
	}

	store.Close()
}

func TestMemoryStoreExpiry(t *testing.T) {
	store := NewMemoryStore()

	store.Put("s1", &SessionEntry{ID: "s1"}, 50*time.Millisecond)
	time.Sleep(100 * time.Millisecond)

	_, err := store.Get("s1")
	if err == nil {
		t.Error("expired session should fail")
	}
}

func TestMemoryStoreList(t *testing.T) {
	store := NewMemoryStore()

	store.Put("s1", &SessionEntry{ID: "s1", NodeID: "node-1"}, time.Hour)
	store.Put("s2", &SessionEntry{ID: "s2", NodeID: "node-2"}, time.Hour)
	store.Put("s3", &SessionEntry{ID: "s3", NodeID: "node-1"}, time.Hour)

	// All sessions
	all, _ := store.List("")
	if len(all) != 3 {
		t.Errorf("all = %d, want 3", len(all))
	}

	// Filter by node
	node1, _ := store.List("node-1")
	if len(node1) != 2 {
		t.Errorf("node-1 = %d, want 2", len(node1))
	}
}

func TestClusterManager(t *testing.T) {
	store := NewMemoryStore()
	cm := NewClusterManager("node-abc", store)

	if cm.NodeID() != "node-abc" {
		t.Errorf("nodeID = %q", cm.NodeID())
	}

	cm.RegisterNode("localhost:15432")

	nodes := cm.Nodes()
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	if nodes[0].Address != "localhost:15432" {
		t.Errorf("address = %q", nodes[0].Address)
	}

	// Store a session
	store.Put("s1", &SessionEntry{ID: "s1", NodeID: "node-abc"}, time.Hour)

	sessions, _ := cm.ClusterSessions()
	if len(sessions) != 1 {
		t.Errorf("cluster sessions = %d", len(sessions))
	}
}

func TestMemoryStoreTouchNotFound(t *testing.T) {
	store := NewMemoryStore()
	err := store.Touch("nonexistent")
	if err == nil {
		t.Error("touch nonexistent should fail")
	}
}

func TestMemoryStoreGetNotFound(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.Get("nonexistent")
	if err == nil {
		t.Error("get nonexistent should fail")
	}
}
