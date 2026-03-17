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

func BenchmarkHistogramObserve(b *testing.B) {
	h := NewHistogram(nil)
	for b.Loop() {
		h.Observe(1234)
	}
}
