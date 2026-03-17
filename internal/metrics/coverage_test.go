package metrics

import "testing"

func TestProtocolStatsSnapshot(t *testing.T) {
	p := &ProtocolCounters{}
	p.PGCommands.Add(10)
	p.MySQLQueries.Add(5)
	p.MSSQLBatches.Add(3)

	snap := p.Snapshot()
	if snap["pg_commands"] != 10 {
		t.Errorf("pg_commands = %d, want 10", snap["pg_commands"])
	}
	if snap["mysql_queries"] != 5 {
		t.Errorf("mysql_queries = %d, want 5", snap["mysql_queries"])
	}
	if snap["mssql_batches"] != 3 {
		t.Errorf("mssql_batches = %d, want 3", snap["mssql_batches"])
	}
}

func TestLatencyHistogramOverflow(t *testing.T) {
	h := &LatencyHistogram{}
	// Value larger than largest bucket (1s = 1000000us)
	h.Observe(2000000) // 2s
	h.Observe(5000000) // 5s

	if h.Count() != 2 {
		t.Errorf("count = %d, want 2", h.Count())
	}

	// P99 should be at max bucket
	p99 := h.Percentile(99)
	if p99 < 1000000 {
		t.Errorf("p99 = %.0f, should be >= 1000000 for overflow values", p99)
	}
}

func TestDatabaseCountersRecordBlocked(t *testing.T) {
	d := &DatabaseCounters{counters: make(map[string]*dbCounter)}
	d.RecordBlocked("prod")
	d.RecordBlocked("prod")

	snap := d.Snapshot()
	if snap["prod"]["blocked"] != 2 {
		t.Errorf("blocked = %d, want 2", snap["prod"]["blocked"])
	}
}

func TestDatabaseCountersConcurrentAccess(t *testing.T) {
	d := &DatabaseCounters{counters: make(map[string]*dbCounter)}

	// Concurrent access to same key
	done := make(chan struct{})
	for range 10 {
		go func() {
			d.RecordQuery("test")
			d.RecordWrite("test")
			done <- struct{}{}
		}()
	}
	for range 10 {
		<-done
	}

	snap := d.Snapshot()
	if snap["test"]["queries"] != 10 {
		t.Errorf("queries = %d, want 10", snap["test"]["queries"])
	}
}
