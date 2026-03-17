package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/ersinkoc/argus/internal/core"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// Metrics holds Prometheus-style counters and gauges.
type Metrics struct {
	ConnectionsTotal   atomic.Int64
	ConnectionsFailed  atomic.Int64
	CommandsTotal      atomic.Int64
	CommandsBlocked    atomic.Int64
	CommandsMasked     atomic.Int64
	ResultRowsTotal    atomic.Int64
	PolicyEvals        atomic.Int64
	PolicyCacheHits    atomic.Int64
	PolicyCacheMisses  atomic.Int64
}

// GlobalMetrics is the singleton metrics instance.
var GlobalMetrics = &Metrics{}

// Server is the admin/metrics HTTP server.
type Server struct {
	proxy     *core.Proxy
	metrics   *Metrics
	addr      string
	server    *http.Server
}

// NewServer creates a new admin server.
func NewServer(proxy *core.Proxy, metrics *Metrics, addr string) *Server {
	return &Server{
		proxy:   proxy,
		metrics: metrics,
		addr:    addr,
	}
}

// Start begins serving the admin/metrics endpoints.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/sessions", s.handleSessions)

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	log.Printf("[argus] admin/metrics server on %s", s.addr)

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[argus] admin server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the admin server.
func (s *Server) Stop() {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	sm := s.proxy.SessionManager()
	poolStats := s.proxy.PoolStats()

	status := "healthy"
	for _, ps := range poolStats {
		if !ps.Healthy {
			status = "degraded"
			break
		}
	}

	resp := map[string]any{
		"status":          status,
		"active_sessions": sm.Count(),
		"pools":           poolStats,
		"uptime":          time.Since(startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if status != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	sm := s.proxy.SessionManager()
	poolStats := s.proxy.PoolStats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Active sessions
	fmt.Fprintf(w, "# HELP argus_active_sessions Current active sessions\n")
	fmt.Fprintf(w, "# TYPE argus_active_sessions gauge\n")
	fmt.Fprintf(w, "argus_active_sessions %d\n\n", sm.Count())

	// Connections
	fmt.Fprintf(w, "# HELP argus_connections_total Total connections\n")
	fmt.Fprintf(w, "# TYPE argus_connections_total counter\n")
	fmt.Fprintf(w, "argus_connections_total{status=\"success\"} %d\n", s.metrics.ConnectionsTotal.Load())
	fmt.Fprintf(w, "argus_connections_total{status=\"failed\"} %d\n\n", s.metrics.ConnectionsFailed.Load())

	// Commands
	fmt.Fprintf(w, "# HELP argus_commands_total Total commands processed\n")
	fmt.Fprintf(w, "# TYPE argus_commands_total counter\n")
	fmt.Fprintf(w, "argus_commands_total %d\n\n", s.metrics.CommandsTotal.Load())

	fmt.Fprintf(w, "# HELP argus_commands_blocked_total Total commands blocked\n")
	fmt.Fprintf(w, "# TYPE argus_commands_blocked_total counter\n")
	fmt.Fprintf(w, "argus_commands_blocked_total %d\n\n", s.metrics.CommandsBlocked.Load())

	// Results
	fmt.Fprintf(w, "# HELP argus_result_rows_total Total result rows\n")
	fmt.Fprintf(w, "# TYPE argus_result_rows_total counter\n")
	fmt.Fprintf(w, "argus_result_rows_total %d\n\n", s.metrics.ResultRowsTotal.Load())

	fmt.Fprintf(w, "# HELP argus_result_masked_total Total masked result sets\n")
	fmt.Fprintf(w, "# TYPE argus_result_masked_total counter\n")
	fmt.Fprintf(w, "argus_result_masked_total %d\n\n", s.metrics.CommandsMasked.Load())

	// Policy
	fmt.Fprintf(w, "# HELP argus_policy_evaluations_total Total policy evaluations\n")
	fmt.Fprintf(w, "# TYPE argus_policy_evaluations_total counter\n")
	fmt.Fprintf(w, "argus_policy_evaluations_total %d\n\n", s.metrics.PolicyEvals.Load())

	fmt.Fprintf(w, "# HELP argus_policy_cache_hits_total Policy cache hits\n")
	fmt.Fprintf(w, "# TYPE argus_policy_cache_hits_total counter\n")
	fmt.Fprintf(w, "argus_policy_cache_hits_total %d\n\n", s.metrics.PolicyCacheHits.Load())

	// Pool metrics
	for name, ps := range poolStats {
		fmt.Fprintf(w, "argus_pool_active_connections{target=%q} %d\n", name, ps.Active)
		fmt.Fprintf(w, "argus_pool_idle_connections{target=%q} %d\n", name, ps.Idle)
	}

	// Go runtime
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fmt.Fprintf(w, "\n# HELP argus_go_goroutines Number of goroutines\n")
	fmt.Fprintf(w, "# TYPE argus_go_goroutines gauge\n")
	fmt.Fprintf(w, "argus_go_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "argus_go_alloc_bytes %d\n", memStats.Alloc)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sm := s.proxy.SessionManager()
	sessions := sm.ActiveSessions()

	type sessionInfo struct {
		ID           string `json:"id"`
		Username     string `json:"username"`
		Database     string `json:"database"`
		ClientIP     string `json:"client_ip"`
		Duration     string `json:"duration"`
		CommandCount int64  `json:"command_count"`
	}

	var result []sessionInfo
	for _, sess := range sessions {
		result = append(result, sessionInfo{
			ID:           sess.ID,
			Username:     sess.Username,
			Database:     sess.Database,
			ClientIP:     sess.ClientIP.String(),
			Duration:     sess.Duration().String(),
			CommandCount: sess.CommandCount,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

var startTime = time.Now()

// Ensure pool.PoolStats is used
var _ = pool.PoolStats{}
var _ = session.Session{}
