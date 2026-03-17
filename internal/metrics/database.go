package metrics

import (
	"sync"
	"sync/atomic"
)

// DatabaseCounters tracks per-database command statistics.
type DatabaseCounters struct {
	mu       sync.RWMutex
	counters map[string]*dbCounter
}

type dbCounter struct {
	Queries  atomic.Int64
	Writes   atomic.Int64
	Blocked  atomic.Int64
	Rows     atomic.Int64
}

// DatabaseStats is the global per-database metrics instance.
var DatabaseStats = &DatabaseCounters{
	counters: make(map[string]*dbCounter),
}

// RecordQuery records a query for a database.
func (d *DatabaseCounters) RecordQuery(database string) {
	d.getOrCreate(database).Queries.Add(1)
}

// RecordWrite records a write for a database.
func (d *DatabaseCounters) RecordWrite(database string) {
	d.getOrCreate(database).Writes.Add(1)
}

// RecordBlocked records a blocked command for a database.
func (d *DatabaseCounters) RecordBlocked(database string) {
	d.getOrCreate(database).Blocked.Add(1)
}

// RecordRows records returned rows for a database.
func (d *DatabaseCounters) RecordRows(database string, rows int64) {
	d.getOrCreate(database).Rows.Add(rows)
}

// Snapshot returns current per-database stats.
func (d *DatabaseCounters) Snapshot() map[string]map[string]int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make(map[string]map[string]int64, len(d.counters))
	for db, c := range d.counters {
		result[db] = map[string]int64{
			"queries": c.Queries.Load(),
			"writes":  c.Writes.Load(),
			"blocked": c.Blocked.Load(),
			"rows":    c.Rows.Load(),
		}
	}
	return result
}

func (d *DatabaseCounters) getOrCreate(database string) *dbCounter {
	d.mu.RLock()
	if c, ok := d.counters[database]; ok {
		d.mu.RUnlock()
		return c
	}
	d.mu.RUnlock()

	d.mu.Lock()
	defer d.mu.Unlock()

	if c, ok := d.counters[database]; ok {
		return c
	}
	c := &dbCounter{}
	d.counters[database] = c
	return c
}

// TrackedDatabases returns the number of tracked databases.
func (d *DatabaseCounters) TrackedDatabases() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.counters)
}
