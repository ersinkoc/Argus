package pool

import (
	"math"
	"sync"
	"sync/atomic"
)

// Histogram tracks the distribution of values (e.g., wait times).
// Uses fixed exponential buckets for O(1) recording.
type Histogram struct {
	buckets []atomic.Int64
	bounds  []float64
	count   atomic.Int64
	sum     atomic.Int64 // sum in microseconds
}

// DefaultBuckets are the default histogram bucket boundaries in microseconds.
var DefaultBuckets = []float64{
	100,      // 0.1ms
	500,      // 0.5ms
	1000,     // 1ms
	5000,     // 5ms
	10000,    // 10ms
	50000,    // 50ms
	100000,   // 100ms
	500000,   // 500ms
	1000000,  // 1s
	5000000,  // 5s
	10000000, // 10s
}

// NewHistogram creates a histogram with the given bucket boundaries.
func NewHistogram(bounds []float64) *Histogram {
	if len(bounds) == 0 {
		bounds = DefaultBuckets
	}
	return &Histogram{
		buckets: make([]atomic.Int64, len(bounds)+1), // +1 for overflow
		bounds:  bounds,
	}
}

// Observe records a value in the histogram.
func (h *Histogram) Observe(value float64) {
	h.count.Add(1)
	h.sum.Add(int64(value))

	idx := len(h.bounds) // overflow bucket
	for i, bound := range h.bounds {
		if value <= bound {
			idx = i
			break
		}
	}
	h.buckets[idx].Add(1)
}

// Count returns the total number of observations.
func (h *Histogram) Count() int64 {
	return h.count.Load()
}

// Sum returns the total sum of all observed values.
func (h *Histogram) Sum() int64 {
	return h.sum.Load()
}

// Percentile returns an approximate percentile value.
func (h *Histogram) Percentile(p float64) float64 {
	total := h.count.Load()
	if total == 0 {
		return 0
	}

	threshold := int64(math.Ceil(float64(total) * p / 100.0))
	cumulative := int64(0)

	for i, b := range h.bounds {
		cumulative += h.buckets[i].Load()
		if cumulative >= threshold {
			return b
		}
	}

	// In overflow bucket
	if len(h.bounds) > 0 {
		return h.bounds[len(h.bounds)-1] * 2
	}
	return 0
}

// Snapshot returns a copy of the histogram data.
type HistogramSnapshot struct {
	Count   int64              `json:"count"`
	Sum     int64              `json:"sum_us"`
	P50     float64            `json:"p50_us"`
	P95     float64            `json:"p95_us"`
	P99     float64            `json:"p99_us"`
	Buckets map[string]int64   `json:"buckets"`
}

func (h *Histogram) Snapshot() HistogramSnapshot {
	snap := HistogramSnapshot{
		Count:   h.count.Load(),
		Sum:     h.sum.Load(),
		P50:     h.Percentile(50),
		P95:     h.Percentile(95),
		P99:     h.Percentile(99),
		Buckets: make(map[string]int64),
	}

	for i, bound := range h.bounds {
		label := formatBound(bound)
		snap.Buckets[label] = h.buckets[i].Load()
	}
	snap.Buckets["+Inf"] = h.buckets[len(h.bounds)].Load()

	return snap
}

func formatBound(us float64) string {
	if us >= 1000000 {
		return fmtFloat(us/1000000) + "s"
	}
	if us >= 1000 {
		return fmtFloat(us/1000) + "ms"
	}
	return fmtFloat(us) + "us"
}

func fmtFloat(f float64) string {
	if f == math.Trunc(f) {
		return itoa64(int64(f))
	}
	// Simple 1 decimal place
	whole := int64(f)
	frac := int64((f - float64(whole)) * 10)
	return itoa64(whole) + "." + itoa64(frac)
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

// Bounds returns the bucket upper boundaries in microseconds.
func (h *Histogram) Bounds() []float64 {
	return h.bounds
}

// CumulativeBuckets returns cumulative counts per bucket (Prometheus convention).
func (h *Histogram) CumulativeBuckets() []int64 {
	cum := make([]int64, len(h.bounds))
	var running int64
	for i := range h.bounds {
		running += h.buckets[i].Load()
		cum[i] = running
	}
	return cum
}

// WaitHistogram is the global pool wait time histogram.
var WaitHistogram = NewHistogram(nil)

// mu is unexported, just used to verify Histogram is safe
var _ sync.Locker = (*sync.Mutex)(nil)
