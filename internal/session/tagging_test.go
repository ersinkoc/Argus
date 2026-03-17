package session

import "testing"

func TestTagStore(t *testing.T) {
	ts := NewTagStore()

	ts.Set("sess-1", "team", "engineering")
	ts.Set("sess-1", "env", "production")
	ts.Set("sess-2", "team", "support")

	// Get
	val, ok := ts.Get("sess-1", "team")
	if !ok || val != "engineering" {
		t.Errorf("Get = %q, %v", val, ok)
	}

	// Missing key
	_, ok = ts.Get("sess-1", "nonexistent")
	if ok {
		t.Error("should return false for missing key")
	}

	// Missing session
	_, ok = ts.Get("sess-999", "team")
	if ok {
		t.Error("should return false for missing session")
	}

	// All
	all := ts.All("sess-1")
	if len(all) != 2 {
		t.Errorf("All = %d tags, want 2", len(all))
	}
	if all["team"] != "engineering" {
		t.Error("team should be engineering")
	}

	// All nil session
	if ts.All("nonexistent") != nil {
		t.Error("All for missing session should be nil")
	}

	// Delete
	ts.Delete("sess-1", "env")
	_, ok = ts.Get("sess-1", "env")
	if ok {
		t.Error("env should be deleted")
	}

	// Count
	if ts.Count() != 2 {
		t.Errorf("count = %d, want 2", ts.Count())
	}

	// Cleanup
	ts.Cleanup("sess-1")
	if ts.All("sess-1") != nil {
		t.Error("sess-1 should be cleaned up")
	}
	if ts.Count() != 1 {
		t.Errorf("count after cleanup = %d, want 1", ts.Count())
	}
}
