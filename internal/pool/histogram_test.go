package pool

import "testing"

func TestHistogramObserve(t *testing.T) {
	h := NewHistogram(nil)

	h.Observe(500)    // 0.5ms
	h.Observe(1500)   // 1.5ms
	h.Observe(50000)  // 50ms
	h.Observe(500000) // 500ms

	if h.Count() != 4 {
		t.Errorf("count = %d, want 4", h.Count())
	}

	sum := h.Sum()
	if sum != 552000 {
		t.Errorf("sum = %d, want 552000", sum)
	}
}

func TestHistogramPercentile(t *testing.T) {
	h := NewHistogram(nil)

	// Add 100 observations: 100us each
	for i := 0; i < 100; i++ {
		h.Observe(100)
	}

	p50 := h.Percentile(50)
	if p50 != 100 {
		t.Errorf("p50 = %v, want 100", p50)
	}

	// Add 1 slow observation
	h.Observe(5000000) // 5s

	p99 := h.Percentile(99)
	// Should be in a high bucket
	if p99 < 100 {
		t.Errorf("p99 = %v, should be higher after slow observation", p99)
	}
}

func TestHistogramEmpty(t *testing.T) {
	h := NewHistogram(nil)
	if h.Percentile(50) != 0 {
		t.Error("empty histogram p50 should be 0")
	}
	if h.Count() != 0 {
		t.Error("empty histogram count should be 0")
	}
}

func TestHistogramSnapshot(t *testing.T) {
	h := NewHistogram(nil)
	h.Observe(500)
	h.Observe(5000)
	h.Observe(50000)

	snap := h.Snapshot()
	if snap.Count != 3 {
		t.Errorf("count = %d, want 3", snap.Count)
	}
	if len(snap.Buckets) == 0 {
		t.Error("buckets should not be empty")
	}
}

func TestHistogramBounds(t *testing.T) {
	h := NewHistogram(nil)
	bounds := h.Bounds()
	if len(bounds) != len(DefaultBuckets) {
		t.Errorf("len(Bounds) = %d, want %d", len(bounds), len(DefaultBuckets))
	}
	if bounds[0] != DefaultBuckets[0] {
		t.Errorf("Bounds[0] = %v, want %v", bounds[0], DefaultBuckets[0])
	}
}

func TestHistogramCumulativeBuckets(t *testing.T) {
	h := NewHistogram(nil)
	h.Observe(100)  // fits in bucket 0 (≤100)
	h.Observe(500)  // fits in bucket 1 (≤500)
	h.Observe(1000) // fits in bucket 2 (≤1000)

	cum := h.CumulativeBuckets()
	if len(cum) != len(DefaultBuckets) {
		t.Errorf("len(CumulativeBuckets) = %d", len(cum))
	}
	// bucket 0: 1, bucket 1: cumulative=2, bucket 2: cumulative=3
	if cum[0] != 1 {
		t.Errorf("cum[0] = %d, want 1", cum[0])
	}
	if cum[1] != 2 {
		t.Errorf("cum[1] = %d, want 2", cum[1])
	}
	if cum[2] != 3 {
		t.Errorf("cum[2] = %d, want 3", cum[2])
	}
}

func TestHistogramPercentile_Overflow(t *testing.T) {
	h := NewHistogram(nil)
	// Observe beyond the last bucket
	h.Observe(20000000) // 20s — beyond 10s last bound
	// With count=1, p99 falls in overflow, returns last bound * 2
	p99 := h.Percentile(99)
	want := DefaultBuckets[len(DefaultBuckets)-1] * 2
	if p99 != want {
		t.Errorf("overflow p99 = %v, want %v", p99, want)
	}
}

func TestWaitHistogram_NotNil(t *testing.T) {
	if WaitHistogram == nil {
		t.Error("WaitHistogram should not be nil")
	}
	WaitHistogram.Observe(1000)
	if WaitHistogram.Count() == 0 {
		t.Error("WaitHistogram count should be > 0 after observe")
	}
}

func BenchmarkHistogramObserve(b *testing.B) {
	h := NewHistogram(nil)
	for b.Loop() {
		h.Observe(1234)
	}
}
