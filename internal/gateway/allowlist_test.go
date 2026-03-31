package gateway

import (
	"testing"
	"time"
)

func TestAllowlistAddAndCheck(t *testing.T) {
	al := NewAllowlist()

	entry := &AllowlistEntry{
		Fingerprint: "fp123",
		Username:    "alice",
		Database:    "mydb",
		Type:        AllowlistTimeWindow,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		CreatedBy:   "admin",
	}
	id := al.Add(entry)
	if id == "" {
		t.Fatal("expected non-empty ID")
	}

	// Check should return the entry
	found := al.Check("fp123", "alice", "mydb")
	if found == nil {
		t.Fatal("expected allowlist hit")
	}
	if found.CreatedBy != "admin" {
		t.Errorf("created_by = %q, want admin", found.CreatedBy)
	}

	// Different fingerprint should miss
	if al.Check("fp999", "alice", "mydb") != nil {
		t.Error("expected nil for different fingerprint")
	}

	// Different user should miss
	if al.Check("fp123", "bob", "mydb") != nil {
		t.Error("expected nil for different user")
	}
}

func TestAllowlistOneTime(t *testing.T) {
	al := NewAllowlist()

	al.Add(&AllowlistEntry{
		Fingerprint: "fp1",
		Username:    "alice",
		Database:    "db",
		Type:        AllowlistOneTime,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		CreatedBy:   "admin",
	})

	// First check should return and consume
	if al.Check("fp1", "alice", "db") == nil {
		t.Fatal("first check should hit")
	}

	// Second check should miss (consumed)
	if al.Check("fp1", "alice", "db") != nil {
		t.Error("second check should miss (one-time consumed)")
	}
}

func TestAllowlistPeekDoesNotConsume(t *testing.T) {
	al := NewAllowlist()

	al.Add(&AllowlistEntry{
		Fingerprint: "fp1",
		Username:    "alice",
		Database:    "db",
		Type:        AllowlistOneTime,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
		CreatedBy:   "admin",
	})

	// Peek should return entry without consuming
	if al.Peek("fp1", "alice", "db") == nil {
		t.Fatal("peek should return entry")
	}

	// Peek again — still there (not consumed)
	if al.Peek("fp1", "alice", "db") == nil {
		t.Fatal("second peek should still return entry")
	}

	// Check should consume it
	if al.Check("fp1", "alice", "db") == nil {
		t.Fatal("check should return entry")
	}

	// Now it's consumed
	if al.Peek("fp1", "alice", "db") != nil {
		t.Error("peek after check should return nil (consumed)")
	}
}

func TestAllowlistExpiry(t *testing.T) {
	al := NewAllowlist()

	al.Add(&AllowlistEntry{
		Fingerprint: "fp1",
		Username:    "alice",
		Database:    "db",
		Type:        AllowlistTimeWindow,
		ExpiresAt:   time.Now().Add(-1 * time.Second), // already expired
		CreatedBy:   "admin",
	})

	if al.Check("fp1", "alice", "db") != nil {
		t.Error("expired entry should not be returned")
	}
}

func TestAllowlistRemove(t *testing.T) {
	al := NewAllowlist()

	entry := &AllowlistEntry{
		Fingerprint: "fp1",
		Username:    "alice",
		Database:    "db",
		Type:        AllowlistTimeWindow,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	id := al.Add(entry)

	if !al.Remove(id) {
		t.Fatal("remove should return true")
	}
	if al.Remove(id) {
		t.Error("second remove should return false")
	}
	if al.Check("fp1", "alice", "db") != nil {
		t.Error("removed entry should not be found")
	}
}

func TestAllowlistCleanup(t *testing.T) {
	al := NewAllowlist()

	al.Add(&AllowlistEntry{
		Fingerprint: "expired",
		Username:    "alice",
		Database:    "db",
		Type:        AllowlistTimeWindow,
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	})
	al.Add(&AllowlistEntry{
		Fingerprint: "active",
		Username:    "alice",
		Database:    "db",
		Type:        AllowlistTimeWindow,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	removed := al.Cleanup()
	if removed != 1 {
		t.Errorf("cleanup removed %d, want 1", removed)
	}
	if al.Count() != 1 {
		t.Errorf("count = %d, want 1", al.Count())
	}
}

func TestAllowlistList(t *testing.T) {
	al := NewAllowlist()

	al.Add(&AllowlistEntry{
		Fingerprint: "fp1", Username: "alice", Database: "db",
		Type: AllowlistTimeWindow, ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	al.Add(&AllowlistEntry{
		Fingerprint: "fp2", Username: "bob", Database: "db",
		Type: AllowlistOneTime, ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	list := al.List()
	if len(list) != 2 {
		t.Errorf("list len = %d, want 2", len(list))
	}
}

func TestAPIKeyStoreValidate(t *testing.T) {
	store := NewAPIKeyStore()

	store.Add(&APIKey{Key: "key1", Username: "alice", Enabled: true})
	store.Add(&APIKey{Key: "key2", Username: "bob", Enabled: false})

	if store.Validate("key1") == nil {
		t.Error("key1 should be valid")
	}
	if store.Validate("key2") != nil {
		t.Error("key2 should be invalid (disabled)")
	}
	if store.Validate("key3") != nil {
		t.Error("key3 should be invalid (not found)")
	}
	if store.Count() != 2 {
		t.Errorf("count = %d, want 2", store.Count())
	}
}
