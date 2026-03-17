package metrics

import (
	"sync/atomic"
)

// LatencyHistogram tracks query execution latency distribution.
// Uses fixed buckets in microseconds for O(1) recording.
type LatencyHistogram struct {
	buckets [12]atomic.Int64 // 12 fixed buckets
	count   atomic.Int64
	sum     atomic.Int64 // sum in microseconds
}

// Bucket boundaries in microseconds
var latencyBounds = [12]float64{
	100,       // 0.1ms
	500,       // 0.5ms
	1000,      // 1ms
	2500,      // 2.5ms
	5000,      // 5ms
	10000,     // 10ms
	25000,     // 25ms
	50000,     // 50ms
	100000,    // 100ms
	250000,    // 250ms
	500000,    // 500ms
	1000000,   // 1s
}

// QueryLatency is the global query latency histogram.
var QueryLatency = &LatencyHistogram{}

// Observe records a latency value in microseconds.
func (h *LatencyHistogram) Observe(us float64) {
	h.count.Add(1)
	h.sum.Add(int64(us))

	for i, bound := range latencyBounds {
		if us <= bound {
			h.buckets[i].Add(1)
			return
		}
	}
	// Overflow: > 1s
	h.buckets[len(latencyBounds)-1].Add(1)
}

// Count returns total observations.
func (h *LatencyHistogram) Count() int64 {
	return h.count.Load()
}

// AvgMicroseconds returns the average latency in microseconds.
func (h *LatencyHistogram) AvgMicroseconds() float64 {
	c := h.count.Load()
	if c == 0 {
		return 0
	}
	return float64(h.sum.Load()) / float64(c)
}

// Percentile returns an approximate percentile in microseconds.
func (h *LatencyHistogram) Percentile(p float64) float64 {
	total := h.count.Load()
	if total == 0 {
		return 0
	}

	threshold := int64(float64(total) * p / 100.0)
	cumulative := int64(0)

	for i, bound := range latencyBounds {
		cumulative += h.buckets[i].Load()
		if cumulative >= threshold {
			return bound
		}
	}

	return latencyBounds[len(latencyBounds)-1]
}

// Snapshot returns current histogram state.
type LatencySnapshot struct {
	Count  int64   `json:"count"`
	AvgUS  float64 `json:"avg_us"`
	P50US  float64 `json:"p50_us"`
	P95US  float64 `json:"p95_us"`
	P99US  float64 `json:"p99_us"`
	SumUS  int64   `json:"sum_us"`
}

func (h *LatencyHistogram) Snapshot() LatencySnapshot {
	return LatencySnapshot{
		Count: h.count.Load(),
		AvgUS: h.AvgMicroseconds(),
		P50US: h.Percentile(50),
		P95US: h.Percentile(95),
		P99US: h.Percentile(99),
		SumUS: h.sum.Load(),
	}
}
