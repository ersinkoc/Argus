package inspection

import (
	"testing"
	"time"
)

func TestAnomalyDetectorBaseline(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)

	ts := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	// Build baseline: 200 SELECT queries on "users" table
	for i := 0; i < 200; i++ {
		d.Record("dev_john", CommandSELECT, []string{"users"}, ts)
	}

	// Normal query — should produce no alerts
	alerts := d.Check("dev_john", CommandSELECT, []string{"users"}, ts)
	if len(alerts) > 0 {
		t.Errorf("expected no alerts for normal query, got %d: %v", len(alerts), alerts)
	}
}

func TestAnomalyDetectorUnusualCommand(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)
	ts := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	// 200 SELECTs, 0 DDL
	for i := 0; i < 200; i++ {
		d.Record("dev_john", CommandSELECT, []string{"users"}, ts)
	}

	// DDL from a SELECT-only user → unusual
	alerts := d.Check("dev_john", CommandDDL, []string{"users"}, ts)
	found := false
	for _, a := range alerts {
		if a.Type == "unusual_command" {
			found = true
		}
	}
	if !found {
		t.Error("expected unusual_command alert for DDL from SELECT-only user")
	}
}

func TestAnomalyDetectorUnusualTable(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)
	ts := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	for i := 0; i < 200; i++ {
		d.Record("dev_john", CommandSELECT, []string{"users"}, ts)
	}

	// Access a never-seen table
	alerts := d.Check("dev_john", CommandSELECT, []string{"salaries"}, ts)
	found := false
	for _, a := range alerts {
		if a.Type == "unusual_table" {
			found = true
		}
	}
	if !found {
		t.Error("expected unusual_table alert for never-accessed table")
	}
}

func TestAnomalyDetectorNotEnoughData(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)
	ts := time.Now()

	// Only 10 queries — not enough for baseline
	for i := 0; i < 10; i++ {
		d.Record("newuser", CommandSELECT, []string{"users"}, ts)
	}

	alerts := d.Check("newuser", CommandDDL, []string{"secrets"}, ts)
	if len(alerts) != 0 {
		t.Error("should not alert with insufficient baseline data")
	}
}

func TestAnomalyDetectorUnknownUser(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)

	alerts := d.Check("unknown", CommandSELECT, []string{"users"}, time.Now())
	if len(alerts) != 0 {
		t.Error("should not alert for unknown user (no baseline)")
	}
}

func TestAnomalyDetectorUserStats(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)
	ts := time.Now()

	d.Record("alice", CommandSELECT, []string{"users"}, ts)
	d.Record("alice", CommandSELECT, []string{"orders"}, ts)
	d.Record("alice", CommandINSERT, []string{"logs"}, ts)

	stats := d.UserStats("alice")
	if stats == nil {
		t.Fatal("stats should not be nil")
	}
	if stats["total_queries"].(int64) != 3 {
		t.Errorf("total = %v, want 3", stats["total_queries"])
	}

	if d.TrackedUsers() != 1 {
		t.Errorf("tracked users = %d, want 1", d.TrackedUsers())
	}

	// Unknown user
	if d.UserStats("nobody") != nil {
		t.Error("unknown user should return nil")
	}
}
