package pool

import (
	"net"
	"testing"
	"time"
)

func TestDeepHealthCheckHealthy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	status := DeepHealthCheck(ln.Addr().String(), 2*time.Second)
	if !status.Healthy {
		t.Errorf("should be healthy: %s", status.LastError)
	}
	if status.Latency < 0 {
		t.Error("latency should be >= 0")
	}
}

func TestDeepHealthCheckUnhealthy(t *testing.T) {
	status := DeepHealthCheck("127.0.0.1:1", 500*time.Millisecond)
	if status.Healthy {
		t.Error("should be unhealthy (port 1 should not be listening)")
	}
	if status.LastError == "" {
		t.Error("should have error message")
	}
}

func TestSummarize(t *testing.T) {
	stats := map[string]PoolStats{
		"pg1":    {Healthy: true},
		"pg2":    {Healthy: true},
		"mysql1": {Healthy: false},
	}

	summary := Summarize(stats)
	if summary.TotalTargets != 3 {
		t.Errorf("total = %d, want 3", summary.TotalTargets)
	}
	if summary.HealthyTargets != 2 {
		t.Errorf("healthy = %d, want 2", summary.HealthyTargets)
	}
	if summary.OverallStatus != "degraded (2/3 healthy)" {
		t.Errorf("status = %q", summary.OverallStatus)
	}

	// All healthy
	allHealthy := map[string]PoolStats{"pg1": {Healthy: true}}
	s2 := Summarize(allHealthy)
	if s2.OverallStatus != "healthy" {
		t.Errorf("should be healthy, got %q", s2.OverallStatus)
	}

	// All unhealthy
	allUnhealthy := map[string]PoolStats{"pg1": {Healthy: false}}
	s3 := Summarize(allUnhealthy)
	if s3.OverallStatus != "unhealthy" {
		t.Errorf("should be unhealthy, got %q", s3.OverallStatus)
	}
}
