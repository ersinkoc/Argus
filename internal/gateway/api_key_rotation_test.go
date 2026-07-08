package gateway

import "testing"

func TestAPIKeyStoreValidateAcceptsPreviousKeys(t *testing.T) {
	store := NewAPIKeyStore()
	store.Add(&APIKey{
		ID:           "gateway-primary",
		Key:          "current-key",
		PreviousKeys: []string{"old-key"},
		Username:     "alice",
		Enabled:      true,
	})

	current := store.Validate("current-key")
	if current == nil {
		t.Fatal("current key should validate")
	}
	if current.ID != "gateway-primary" {
		t.Fatalf("id = %q, want gateway-primary", current.ID)
	}

	previous := store.Validate("old-key")
	if previous == nil {
		t.Fatal("previous key should validate during rotation")
	}
	if previous.Fingerprint == "" {
		t.Fatal("fingerprint should be populated")
	}
}

func TestAPIKeyEnsureMetadataDefaults(t *testing.T) {
	key := &APIKey{Key: "secret", Enabled: true}
	key.ensureMetadata()

	if key.ID == "" {
		t.Fatal("id should default from key fingerprint")
	}
	if key.Fingerprint == "" {
		t.Fatal("fingerprint should default from key fingerprint")
	}
	if key.ID != key.Fingerprint {
		t.Fatalf("id = %q, fingerprint = %q, want equal defaults", key.ID, key.Fingerprint)
	}
}
