package pool

import (
	"testing"
	"time"
)

func TestCircuitBreakerStateString(t *testing.T) {
	tests := []struct {
		s    CircuitState
		want string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("CircuitState(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestHistogramFormatBound(t *testing.T) {
	tests := []struct {
		us   float64
		want string
	}{
		{100, "100us"},
		{1000, "1ms"},
		{5000, "5ms"},
		{100000, "100ms"},
		{1000000, "1s"},
		{5000000, "5s"},
	}
	for _, tt := range tests {
		got := formatBound(tt.us)
		if got != tt.want {
			t.Errorf("formatBound(%.0f) = %q, want %q", tt.us, got, tt.want)
		}
	}
}

func TestSharedPoolClose(t *testing.T) {
	p := NewSharedPool("127.0.0.1:1", 5, time.Hour, time.Second, 0)
	if err := p.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestSharedPoolStats(t *testing.T) {
	p := NewSharedPool("127.0.0.1:5432", 10, time.Hour, time.Second, 0)
	stats := p.Stats()
	if stats.Max != 10 {
		t.Errorf("max = %d, want 10", stats.Max)
	}
	if stats.Target != "127.0.0.1:5432" {
		t.Errorf("target = %q", stats.Target)
	}
	p.Close()
}

func TestPoolIsHealthy(t *testing.T) {
	p := NewPool("127.0.0.1:5432", 5, 0, time.Hour, time.Second, 0)
	if !p.IsHealthy() {
		t.Error("should be healthy initially")
	}
	p.Close()
}

func TestWaitHistogramGlobal(t *testing.T) {
	// Just verify it's initialized
	WaitHistogram.Observe(100)
	if WaitHistogram.Count() < 1 {
		t.Error("global histogram should accept observations")
	}
}

func TestHistogramSnapshotDetailed(t *testing.T) {
	h := NewHistogram(nil)
	h.Observe(100)
	h.Observe(1000)
	h.Observe(10000)

	snap := h.Snapshot()
	if snap.Count != 3 {
		t.Errorf("count = %d, want 3", snap.Count)
	}
	if len(snap.Buckets) == 0 {
		t.Error("buckets should not be empty")
	}
	if _, ok := snap.Buckets["+Inf"]; !ok {
		t.Error("should have +Inf bucket")
	}
}
