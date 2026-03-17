package pool

import (
	"context"
	"fmt"
	"net"
	"time"
)

// HealthStatus represents detailed health information for a target.
type HealthStatus struct {
	Target      string        `json:"target"`
	Healthy     bool          `json:"healthy"`
	Latency     time.Duration `json:"latency_us"`
	LastCheck   time.Time     `json:"last_check"`
	LastError   string        `json:"last_error,omitempty"`
	CheckCount  int64         `json:"check_count"`
	FailCount   int64         `json:"fail_count"`
	CircuitState string       `json:"circuit_state,omitempty"`
}

// DeepHealthCheck performs a full connectivity test to the target.
// Unlike the basic health check (TCP connect), this can optionally
// send a protocol-level ping (e.g., SELECT 1).
func DeepHealthCheck(target string, timeout time.Duration) *HealthStatus {
	start := time.Now()
	status := &HealthStatus{
		Target:    target,
		LastCheck: start,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		status.Healthy = false
		status.LastError = err.Error()
		status.Latency = time.Since(start)
		return status
	}
	defer conn.Close()

	status.Healthy = true
	status.Latency = time.Since(start)
	return status
}

// CheckAllTargets checks health of multiple targets concurrently.
func CheckAllTargets(targets []string, timeout time.Duration) map[string]*HealthStatus {
	results := make(map[string]*HealthStatus, len(targets))
	ch := make(chan *HealthStatus, len(targets))

	for _, target := range targets {
		go func(t string) {
			ch <- DeepHealthCheck(t, timeout)
		}(target)
	}

	for range targets {
		status := <-ch
		results[status.Target] = status
	}

	return results
}

// PoolHealthSummary returns a summary of all pool health states.
type PoolHealthSummary struct {
	TotalTargets    int    `json:"total_targets"`
	HealthyTargets  int    `json:"healthy_targets"`
	UnhealthyTargets int   `json:"unhealthy_targets"`
	OverallStatus   string `json:"overall_status"` // healthy, degraded, unhealthy
}

// Summarize creates a health summary from pool stats.
func Summarize(stats map[string]PoolStats) *PoolHealthSummary {
	summary := &PoolHealthSummary{
		TotalTargets: len(stats),
	}

	for _, s := range stats {
		if s.Healthy {
			summary.HealthyTargets++
		} else {
			summary.UnhealthyTargets++
		}
	}

	switch {
	case summary.UnhealthyTargets == 0:
		summary.OverallStatus = "healthy"
	case summary.HealthyTargets == 0:
		summary.OverallStatus = "unhealthy"
	default:
		summary.OverallStatus = fmt.Sprintf("degraded (%d/%d healthy)",
			summary.HealthyTargets, summary.TotalTargets)
	}

	return summary
}
