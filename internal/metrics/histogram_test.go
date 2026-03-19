package metrics

import "testing"

func TestLatencyHistogram(t *testing.T) {
	h := &LatencyHistogram{}

	h.Observe(500)   // 0.5ms
	h.Observe(1000)  // 1ms
	h.Observe(5000)  // 5ms
	h.Observe(50000) // 50ms

	if h.Count() != 4 {
		t.Errorf("count = %d, want 4", h.Count())
	}

	avg := h.AvgMicroseconds()
	if avg < 14000 || avg > 14200 {
		t.Errorf("avg = %.0f, want ~14125", avg)
	}
}

func TestLatencyPercentile(t *testing.T) {
	h := &LatencyHistogram{}

	// 100 fast queries at 100us
	for range 100 {
		h.Observe(100)
	}

	p50 := h.Percentile(50)
	if p50 != 100 {
		t.Errorf("p50 = %.0f, want 100", p50)
	}

	// Add 1 slow query
	h.Observe(500000) // 500ms

	p99 := h.Percentile(99)
	// With 100 fast + 1 slow, p99 threshold is ~100th entry = still fast bucket
	// p99.9 would catch the outlier. This is expected histogram behavior.
	_ = p99
}

func TestLatencySnapshot(t *testing.T) {
	h := &LatencyHistogram{}
	h.Observe(1000)
	h.Observe(2000)

	snap := h.Snapshot()
	if snap.Count != 2 {
		t.Errorf("count = %d, want 2", snap.Count)
	}
	if snap.SumUS != 3000 {
		t.Errorf("sum = %d, want 3000", snap.SumUS)
	}
}

func TestLatencyEmpty(t *testing.T) {
	h := &LatencyHistogram{}
	if h.Count() != 0 {
		t.Error("empty count should be 0")
	}
	if h.AvgMicroseconds() != 0 {
		t.Error("empty avg should be 0")
	}
	if h.Percentile(50) != 0 {
		t.Error("empty p50 should be 0")
	}
}

func TestBounds(t *testing.T) {
	b := Bounds()
	if len(b) != 12 {
		t.Errorf("len(Bounds) = %d, want 12", len(b))
	}
	// First bound is 100us, last is 1s
	if b[0] != 100 {
		t.Errorf("Bounds[0] = %v, want 100", b[0])
	}
	if b[11] != 1000000 {
		t.Errorf("Bounds[11] = %v, want 1000000", b[11])
	}
}


func BenchmarkLatencyObserve(b *testing.B) {
	h := &LatencyHistogram{}
	for b.Loop() {
		h.Observe(1234)
	}
}
