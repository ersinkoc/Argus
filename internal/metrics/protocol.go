package metrics

import "sync/atomic"

// ProtocolCounters tracks per-protocol command statistics.
type ProtocolCounters struct {
	PGCommands      atomic.Int64
	PGQueries       atomic.Int64
	PGExtended      atomic.Int64
	PGCopy          atomic.Int64
	MySQLCommands   atomic.Int64
	MySQLQueries    atomic.Int64
	MySQLPrepared   atomic.Int64
	MSSQLCommands   atomic.Int64
	MSSQLBatches    atomic.Int64
}

// ProtocolStats is the global per-protocol metrics instance.
var ProtocolStats = &ProtocolCounters{}

// Snapshot returns a copy of current protocol stats.
func (p *ProtocolCounters) Snapshot() map[string]int64 {
	return map[string]int64{
		"pg_commands":     p.PGCommands.Load(),
		"pg_queries":      p.PGQueries.Load(),
		"pg_extended":     p.PGExtended.Load(),
		"pg_copy":         p.PGCopy.Load(),
		"mysql_commands":  p.MySQLCommands.Load(),
		"mysql_queries":   p.MySQLQueries.Load(),
		"mysql_prepared":  p.MySQLPrepared.Load(),
		"mssql_commands":  p.MSSQLCommands.Load(),
		"mssql_batches":   p.MSSQLBatches.Load(),
	}
}
