package metrics

import "sync/atomic"

// Counters holds all Prometheus-style counters and gauges.
type Counters struct {
	ConnectionsTotal  atomic.Int64
	ConnectionsFailed atomic.Int64
	CommandsTotal     atomic.Int64
	CommandsBlocked   atomic.Int64
	CommandsMasked    atomic.Int64
	ResultRowsTotal   atomic.Int64
	PolicyEvals       atomic.Int64
	PolicyCacheHits   atomic.Int64
	PolicyCacheMisses atomic.Int64
}

// Global is the singleton metrics instance.
var Global = &Counters{}
