package admin

import "testing"

func TestComputeAcceptKey(t *testing.T) {
	// Known test vector from RFC 6455
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	got := computeAcceptKey(key)
	if got != want {
		t.Errorf("computeAcceptKey = %q, want %q", got, want)
	}
}

func TestEventStreamBroadcastNoClients(t *testing.T) {
	es := NewEventStream()
	// Should not panic with no clients
	es.Broadcast(map[string]string{"test": "value"})
}

func TestEventStreamAddRemove(t *testing.T) {
	es := NewEventStream()
	if es.Count() != 0 {
		t.Error("initial count should be 0")
	}
}
