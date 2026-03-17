package core

import (
	"testing"

	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/pool"
)

func TestProxyPoolStats(t *testing.T) {
	cfg := config.DefaultConfig()
	proxy := NewProxy(cfg, nil, nil)

	stats := proxy.PoolStats()
	if stats == nil {
		t.Error("PoolStats should return non-nil map")
	}
	if len(stats) != 0 {
		t.Errorf("should have 0 pools initially, got %d", len(stats))
	}
}

func TestProxySummarize(t *testing.T) {
	stats := map[string]pool.PoolStats{
		"pg":    {Healthy: true, Active: 5, Idle: 3},
		"mysql": {Healthy: true, Active: 2, Idle: 1},
	}

	summary := pool.Summarize(stats)
	if summary.OverallStatus != "healthy" {
		t.Errorf("status = %q, want healthy", summary.OverallStatus)
	}
	if summary.TotalTargets != 2 {
		t.Errorf("total = %d", summary.TotalTargets)
	}
}
