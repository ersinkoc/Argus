package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/ersinkoc/argus/internal/metrics"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// SessionProvider gives access to session data without importing core.
type SessionProvider interface {
	SessionManager() *session.Manager
	PoolStats() map[string]pool.PoolStats
}

// Server is the admin/metrics HTTP server.
type Server struct {
	provider       SessionProvider
	addr           string
	server         *http.Server
	policyReloadFn func() error
}

// NewServer creates a new admin server.
func NewServer(provider SessionProvider, addr string) *Server {
	return &Server{
		provider: provider,
		addr:     addr,
	}
}

// OnPolicyReload sets the callback for policy reload requests.
func (s *Server) OnPolicyReload(fn func() error) {
	s.policyReloadFn = fn
}

// Start begins serving the admin/metrics endpoints.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/sessions/kill", s.handleSessionKill)
	mux.HandleFunc("/api/policies/reload", s.handlePolicyReload)
	mux.HandleFunc("/api/stats", s.handleStats)

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
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
	poolStats := s.provider.PoolStats()

	status := "healthy"
	for _, ps := range poolStats {
		if !ps.Healthy {
			status = "degraded"
			break
		}
	}

	resp := map[string]any{
		"status":          status,
		"active_sessions": s.provider.SessionManager().Count(),
		"pools":           poolStats,
		"uptime":          time.Since(startTime).String(),
		"version":         Version,
	}

	w.Header().Set("Content-Type", "application/json")
	if status != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	m := metrics.Global
	sm := s.provider.SessionManager()
	poolStats := s.provider.PoolStats()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Active sessions
	fmt.Fprintf(w, "# HELP argus_active_sessions Current active sessions\n")
	fmt.Fprintf(w, "# TYPE argus_active_sessions gauge\n")
	fmt.Fprintf(w, "argus_active_sessions %d\n\n", sm.Count())

	// Connections
	fmt.Fprintf(w, "# HELP argus_connections_total Total connections\n")
	fmt.Fprintf(w, "# TYPE argus_connections_total counter\n")
	fmt.Fprintf(w, "argus_connections_total{status=\"success\"} %d\n", m.ConnectionsTotal.Load())
	fmt.Fprintf(w, "argus_connections_total{status=\"failed\"} %d\n\n", m.ConnectionsFailed.Load())

	// Commands
	fmt.Fprintf(w, "# HELP argus_commands_total Total commands processed\n")
	fmt.Fprintf(w, "# TYPE argus_commands_total counter\n")
	fmt.Fprintf(w, "argus_commands_total %d\n\n", m.CommandsTotal.Load())

	fmt.Fprintf(w, "# HELP argus_commands_blocked_total Total commands blocked\n")
	fmt.Fprintf(w, "# TYPE argus_commands_blocked_total counter\n")
	fmt.Fprintf(w, "argus_commands_blocked_total %d\n\n", m.CommandsBlocked.Load())

	// Results
	fmt.Fprintf(w, "# HELP argus_result_rows_total Total result rows\n")
	fmt.Fprintf(w, "# TYPE argus_result_rows_total counter\n")
	fmt.Fprintf(w, "argus_result_rows_total %d\n\n", m.ResultRowsTotal.Load())

	fmt.Fprintf(w, "# HELP argus_result_masked_total Total masked result sets\n")
	fmt.Fprintf(w, "# TYPE argus_result_masked_total counter\n")
	fmt.Fprintf(w, "argus_result_masked_total %d\n\n", m.CommandsMasked.Load())

	// Policy
	fmt.Fprintf(w, "# HELP argus_policy_evaluations_total Total policy evaluations\n")
	fmt.Fprintf(w, "# TYPE argus_policy_evaluations_total counter\n")
	fmt.Fprintf(w, "argus_policy_evaluations_total %d\n\n", m.PolicyEvals.Load())

	fmt.Fprintf(w, "# HELP argus_policy_cache_hits_total Policy cache hits\n")
	fmt.Fprintf(w, "# TYPE argus_policy_cache_hits_total counter\n")
	fmt.Fprintf(w, "argus_policy_cache_hits_total %d\n\n", m.PolicyCacheHits.Load())

	// Pool metrics
	fmt.Fprintf(w, "# HELP argus_pool_active_connections Active pool connections per target\n")
	fmt.Fprintf(w, "# TYPE argus_pool_active_connections gauge\n")
	for name, ps := range poolStats {
		fmt.Fprintf(w, "argus_pool_active_connections{target=%q} %d\n", name, ps.Active)
	}
	fmt.Fprintf(w, "\n# HELP argus_pool_idle_connections Idle pool connections per target\n")
	fmt.Fprintf(w, "# TYPE argus_pool_idle_connections gauge\n")
	for name, ps := range poolStats {
		fmt.Fprintf(w, "argus_pool_idle_connections{target=%q} %d\n", name, ps.Idle)
	}

	// Go runtime
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fmt.Fprintf(w, "\n# HELP argus_go_goroutines Number of goroutines\n")
	fmt.Fprintf(w, "# TYPE argus_go_goroutines gauge\n")
	fmt.Fprintf(w, "argus_go_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "\n# HELP argus_go_alloc_bytes Current memory allocation in bytes\n")
	fmt.Fprintf(w, "# TYPE argus_go_alloc_bytes gauge\n")
	fmt.Fprintf(w, "argus_go_alloc_bytes %d\n", memStats.Alloc)
	fmt.Fprintf(w, "\n# HELP argus_go_sys_bytes Total memory obtained from the OS\n")
	fmt.Fprintf(w, "# TYPE argus_go_sys_bytes gauge\n")
	fmt.Fprintf(w, "argus_go_sys_bytes %d\n", memStats.Sys)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.provider.SessionManager().ActiveSessions()

	type sessionInfo struct {
		ID           string   `json:"id"`
		Username     string   `json:"username"`
		Database     string   `json:"database"`
		ClientIP     string   `json:"client_ip"`
		Roles        []string `json:"roles"`
		Duration     string   `json:"duration"`
		IdleDuration string   `json:"idle_duration"`
		CommandCount int64    `json:"command_count"`
		BytesIn      int64    `json:"bytes_in"`
		BytesOut     int64    `json:"bytes_out"`
	}

	result := make([]sessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, sessionInfo{
			ID:           sess.ID,
			Username:     sess.Username,
			Database:     sess.Database,
			ClientIP:     sess.ClientIP.String(),
			Roles:        sess.Roles,
			Duration:     sess.Duration().String(),
			IdleDuration: sess.IdleDuration().String(),
			CommandCount: sess.CommandCount,
			BytesIn:      sess.BytesIn,
			BytesOut:     sess.BytesOut,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleSessionKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		http.Error(w, `{"error": "missing id parameter"}`, http.StatusBadRequest)
		return
	}

	if err := s.provider.SessionManager().Kill(sessionID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, err.Error()), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "killed",
		"session": sessionID,
	})
}

func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.policyReloadFn == nil {
		http.Error(w, `{"error": "policy reload not configured"}`, http.StatusInternalServerError)
		return
	}

	if err := s.policyReloadFn(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": %q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	m := metrics.Global
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	resp := map[string]any{
		"uptime":      time.Since(startTime).String(),
		"sessions":    s.provider.SessionManager().Count(),
		"goroutines":  runtime.NumGoroutine(),
		"memory_mb":   memStats.Alloc / 1024 / 1024,
		"connections": m.ConnectionsTotal.Load(),
		"commands":    m.CommandsTotal.Load(),
		"blocked":     m.CommandsBlocked.Load(),
		"masked":      m.CommandsMasked.Load(),
		"pools":       s.provider.PoolStats(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

var (
	startTime = time.Now()
	Version   = "dev"
)
