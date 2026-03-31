package cluster

import (
	"testing"
	"time"
)

// --- List: expired entries are skipped ---

func TestListSkipsExpiredEntries(t *testing.T) {
	store := NewMemoryStore()

	store.Put("s1", &SessionEntry{ID: "s1", NodeID: "node-1"}, 50*time.Millisecond)
	store.Put("s2", &SessionEntry{ID: "s2", NodeID: "node-1"}, time.Hour)

	// Wait for s1 to expire
	time.Sleep(100 * time.Millisecond)

	all, err := store.List("")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 non-expired entry, got %d", len(all))
	}
	if all[0].ID != "s2" {
		t.Errorf("expected s2, got %s", all[0].ID)
	}
}

// --- List: expired entries with node filter ---

func TestListSkipsExpiredWithFilter(t *testing.T) {
	store := NewMemoryStore()

	store.Put("s1", &SessionEntry{ID: "s1", NodeID: "node-1"}, 50*time.Millisecond)
	store.Put("s2", &SessionEntry{ID: "s2", NodeID: "node-1"}, time.Hour)
	store.Put("s3", &SessionEntry{ID: "s3", NodeID: "node-2"}, time.Hour)

	time.Sleep(100 * time.Millisecond)

	filtered, err := store.List("node-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// s1 is expired, s3 is wrong node → only s2
	if len(filtered) != 1 {
		t.Errorf("expected 1 entry, got %d", len(filtered))
	}
}
