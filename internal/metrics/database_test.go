package metrics

import "testing"

func TestDatabaseCounters(t *testing.T) {
	d := &DatabaseCounters{counters: make(map[string]*dbCounter)}

	d.RecordQuery("prod")
	d.RecordQuery("prod")
	d.RecordWrite("prod")
	d.RecordBlocked("prod")
	d.RecordRows("prod", 42)

	d.RecordQuery("staging")

	snap := d.Snapshot()
	if snap["prod"]["queries"] != 2 {
		t.Errorf("prod queries = %d, want 2", snap["prod"]["queries"])
	}
	if snap["prod"]["writes"] != 1 {
		t.Errorf("prod writes = %d, want 1", snap["prod"]["writes"])
	}
	if snap["prod"]["rows"] != 42 {
		t.Errorf("prod rows = %d, want 42", snap["prod"]["rows"])
	}
	if snap["staging"]["queries"] != 1 {
		t.Errorf("staging queries = %d, want 1", snap["staging"]["queries"])
	}

	if d.TrackedDatabases() != 2 {
		t.Errorf("tracked = %d, want 2", d.TrackedDatabases())
	}
}
