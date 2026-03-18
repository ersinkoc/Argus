package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/metrics"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

// SessionProvider gives access to session data without importing core.
type SessionProvider interface {
	SessionManager() *session.Manager
	PoolStats() map[string]pool.PoolStats
}

// ApprovalProvider gives access to approval workflow.
type ApprovalProvider interface {
	Approve(id, approver string) error
	Deny(id, approver, reason string) error
	PendingRequests() []any
}

// DryRunFunc evaluates a policy dry-run request.
type DryRunFunc func(username, database, sql, clientIP string) (any, error)

// Server is the admin/metrics HTTP server.
type Server struct {
	provider       SessionProvider
	addr           string
	server         *http.Server
	policyReloadFn func() error
	EventStream    *EventStream
	approvalFn     ApprovalProvider
	auditLogPath   string
	recordFile     string
	dryRunFn       DryRunFunc
	configData     func() ([]byte, error)
	authToken      string
	validateFn     func() (any, error)
	classifyFn     func([]string) any
	pluginListFn   func() any
}

// NewServer creates a new admin server.
func NewServer(provider SessionProvider, addr string) *Server {
	return &Server{
		provider:    provider,
		addr:        addr,
		EventStream: NewEventStream(),
	}
}

// SetAuthToken sets the bearer token for admin API authentication.
func (s *Server) SetAuthToken(token string) {
	s.authToken = token
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
	mux.HandleFunc("/api/events/ws", s.EventStream.HandleWebSocket)
	mux.HandleFunc("/api/approvals", s.handleApprovals)
	mux.HandleFunc("/api/approvals/approve", s.handleApprovalAction)
	mux.HandleFunc("/api/approvals/deny", s.handleApprovalDeny)
	mux.HandleFunc("/api/audit/search", s.handleAuditSearch)
	mux.HandleFunc("/api/audit/replay", s.handleReplay)
	mux.HandleFunc("/api/audit/fingerprints", s.handleFingerprints)
	mux.HandleFunc("/api/policies/dryrun", s.handleDryRun)
	mux.HandleFunc("/api/config/export", s.handleConfigExport)
	mux.HandleFunc("/api/audit/compact", s.handleCompact)
	mux.HandleFunc("/api/policies/validate", s.handlePolicyValidate)
	mux.HandleFunc("/api/audit/export", s.handleAuditExport)
	mux.HandleFunc("/api/pool/health", s.handlePoolHealth)
	mux.HandleFunc("/api/health/deep", s.handleDeepHealth)
	mux.HandleFunc("/api/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/classify", s.handleClassify)
	mux.HandleFunc("/api/plugins", s.handlePlugins)
	mux.HandleFunc("/ui", HandleDashboardUI)
	mux.HandleFunc("/ui/test", HandleTestRunnerUI)
	mux.HandleFunc("/api/test/run", handleTestRun)
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/livez", s.handleLive)

	var handler http.Handler = mux
	if s.authToken != "" {
		handler = NewAuthMiddleware(s.authToken).Wrap(mux)
	}

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      handler,
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

	// Query latency histogram
	latency := metrics.QueryLatency.Snapshot()
	fmt.Fprintf(w, "\n# HELP argus_query_duration_us Query execution duration in microseconds\n")
	fmt.Fprintf(w, "# TYPE argus_query_duration_us summary\n")
	fmt.Fprintf(w, "argus_query_duration_count %d\n", latency.Count)
	fmt.Fprintf(w, "argus_query_duration_avg_us %.0f\n", latency.AvgUS)
	fmt.Fprintf(w, "argus_query_duration_p50_us %.0f\n", latency.P50US)
	fmt.Fprintf(w, "argus_query_duration_p95_us %.0f\n", latency.P95US)
	fmt.Fprintf(w, "argus_query_duration_p99_us %.0f\n", latency.P99US)

	// Per-protocol stats
	protoStats := metrics.ProtocolStats.Snapshot()
	fmt.Fprintf(w, "\n# HELP argus_protocol_commands_total Commands per protocol\n")
	fmt.Fprintf(w, "# TYPE argus_protocol_commands_total counter\n")
	for proto, count := range protoStats {
		fmt.Fprintf(w, "argus_protocol_commands_total{protocol=%q} %d\n", proto, count)
	}

	// Per-database stats
	dbStats := metrics.DatabaseStats.Snapshot()
	fmt.Fprintf(w, "\n# HELP argus_database_queries_total Queries per database\n")
	fmt.Fprintf(w, "# TYPE argus_database_queries_total counter\n")
	for db, stats := range dbStats {
		fmt.Fprintf(w, "argus_database_queries_total{database=%q} %d\n", db, stats["queries"])
		fmt.Fprintf(w, "argus_database_writes_total{database=%q} %d\n", db, stats["writes"])
		fmt.Fprintf(w, "argus_database_rows_total{database=%q} %d\n", db, stats["rows"])
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

	// Pool wait time histogram
	hist := pool.WaitHistogram.Snapshot()
	fmt.Fprintf(w, "\n# HELP argus_pool_wait_seconds Pool connection acquire wait time\n")
	fmt.Fprintf(w, "# TYPE argus_pool_wait_seconds histogram\n")
	fmt.Fprintf(w, "argus_pool_wait_count %d\n", hist.Count)
	fmt.Fprintf(w, "argus_pool_wait_sum_us %d\n", hist.Sum)
	fmt.Fprintf(w, "argus_pool_wait_p50_us %.0f\n", hist.P50)
	fmt.Fprintf(w, "argus_pool_wait_p95_us %.0f\n", hist.P95)
	fmt.Fprintf(w, "argus_pool_wait_p99_us %.0f\n", hist.P99)
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

// SetApprovalProvider sets the approval workflow provider.
func (s *Server) SetApprovalProvider(ap ApprovalProvider) {
	s.approvalFn = ap
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if s.approvalFn == nil {
		json.NewEncoder(w).Encode([]any{})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.approvalFn.PendingRequests())
}

func (s *Server) handleApprovalAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.approvalFn == nil {
		http.Error(w, `{"error":"approval not configured"}`, http.StatusInternalServerError)
		return
	}
	id := r.URL.Query().Get("id")
	approver := r.URL.Query().Get("approver")
	if id == "" {
		http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
		return
	}
	if approver == "" {
		approver = "admin"
	}
	if err := s.approvalFn.Approve(id, approver); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
}

func (s *Server) handleApprovalDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.approvalFn == nil {
		http.Error(w, `{"error":"approval not configured"}`, http.StatusInternalServerError)
		return
	}
	id := r.URL.Query().Get("id")
	approver := r.URL.Query().Get("approver")
	reason := r.URL.Query().Get("reason")
	if id == "" {
		http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
		return
	}
	if approver == "" {
		approver = "admin"
	}
	if err := s.approvalFn.Deny(id, approver, reason); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
}

// SetAuditLogPath sets the audit log file path for search.
func (s *Server) SetAuditLogPath(path string) {
	s.auditLogPath = path
}

func (s *Server) handleAuditSearch(w http.ResponseWriter, r *http.Request) {
	if s.auditLogPath == "" {
		http.Error(w, `{"error":"audit log path not configured"}`, http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	filter := audit.SearchFilter{
		SessionID:   q.Get("session_id"),
		Username:    q.Get("username"),
		Database:    q.Get("database"),
		EventType:   q.Get("event_type"),
		Action:      q.Get("action"),
		CommandType: q.Get("command_type"),
	}
	if v := q.Get("limit"); v != "" {
		n := 0
		for _, c := range v {
			n = n*10 + int(c-'0')
		}
		filter.Limit = n
	}
	if v := q.Get("start"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.StartTime = t
		}
	}
	if v := q.Get("end"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.EndTime = t
		}
	}

	result, err := audit.SearchFile(s.auditLogPath, filter)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Server.recordFile is the path to query recordings for replay.
func (s *Server) SetRecordFile(path string) {
	s.recordFile = path
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, `{"error":"missing session_id parameter"}`, http.StatusBadRequest)
		return
	}
	path := s.recordFile
	if path == "" {
		path = s.auditLogPath
	}
	if path == "" {
		http.Error(w, `{"error":"recording not configured"}`, http.StatusInternalServerError)
		return
	}

	replay, err := audit.ReplayFromFile(path, sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(replay)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	m := metrics.Global
	sm := s.provider.SessionManager()
	poolStats := s.provider.PoolStats()
	histSnap := pool.WaitHistogram.Snapshot()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Aggregate pool stats
	totalActive, totalIdle := 0, 0
	healthyTargets, unhealthyTargets := 0, 0
	for _, ps := range poolStats {
		totalActive += ps.Active
		totalIdle += ps.Idle
		if ps.Healthy {
			healthyTargets++
		} else {
			unhealthyTargets++
		}
	}

	dashboard := map[string]any{
		"overview": map[string]any{
			"uptime":           time.Since(startTime).String(),
			"version":          Version,
			"active_sessions":  sm.Count(),
			"goroutines":       runtime.NumGoroutine(),
			"memory_mb":        memStats.Alloc / 1024 / 1024,
			"healthy_targets":  healthyTargets,
			"unhealthy_targets": unhealthyTargets,
		},
		"traffic": map[string]any{
			"total_connections": m.ConnectionsTotal.Load(),
			"failed_connections": m.ConnectionsFailed.Load(),
			"total_commands":    m.CommandsTotal.Load(),
			"blocked_commands":  m.CommandsBlocked.Load(),
			"masked_results":   m.CommandsMasked.Load(),
			"total_rows":       m.ResultRowsTotal.Load(),
		},
		"pool": map[string]any{
			"active_connections": totalActive,
			"idle_connections":   totalIdle,
			"wait_p50_us":       histSnap.P50,
			"wait_p95_us":       histSnap.P95,
			"wait_p99_us":       histSnap.P99,
			"targets":           poolStats,
		},
		"policy": map[string]any{
			"evaluations":  m.PolicyEvals.Load(),
			"cache_hits":   m.PolicyCacheHits.Load(),
			"cache_misses": m.PolicyCacheMisses.Load(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard)
}

// SetDryRunFunc sets the policy dry-run function.
func (s *Server) SetDryRunFunc(fn DryRunFunc) {
	s.dryRunFn = fn
}

// SetConfigExporter sets the config export function.
func (s *Server) SetConfigExporter(fn func() ([]byte, error)) {
	s.configData = fn
}

func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	path := s.recordFile
	if path == "" {
		http.Error(w, `{"error":"recording not configured"}`, http.StatusInternalServerError)
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		n := 0
		for _, c := range v {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 {
			limit = n
		}
	}

	top, err := audit.TopFingerprints(path, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(top)
}

func (s *Server) handleDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.dryRunFn == nil {
		http.Error(w, `{"error":"dry-run not configured"}`, http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	result, err := s.dryRunFn(
		q.Get("username"),
		q.Get("database"),
		q.Get("sql"),
		q.Get("client_ip"),
	)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if s.configData == nil {
		http.Error(w, `{"error":"config export not configured"}`, http.StatusInternalServerError)
		return
	}

	data, err := s.configData()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=argus-config.json")
	w.Write(data)
}

// handleReady is the Kubernetes readiness probe.
// Returns 200 if at least one backend target is healthy.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	poolStats := s.provider.PoolStats()
	ready := false
	for _, ps := range poolStats {
		if ps.Healthy {
			ready = true
			break
		}
	}

	if !ready && len(poolStats) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "not ready: no healthy targets")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ready")
}

// handleLive is the Kubernetes liveness probe.
// Always returns 200 if the process is running.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "alive")
}

func (s *Server) handleCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logDir := ""
	if s.auditLogPath != "" {
		logDir = filepath.Dir(s.auditLogPath)
	}
	if logDir == "" || logDir == "." {
		http.Error(w, `{"error":"audit log path not configured"}`, http.StatusInternalServerError)
		return
	}

	dryRun := r.URL.Query().Get("dry_run") == "true"
	maxAge := 7 * 24 * time.Hour // default 7 days
	if v := r.URL.Query().Get("max_age_hours"); v != "" {
		hours := 0
		for _, c := range v {
			if c >= '0' && c <= '9' {
				hours = hours*10 + int(c-'0')
			}
		}
		if hours > 0 {
			maxAge = time.Duration(hours) * time.Hour
		}
	}

	result, err := audit.CompactLogs(logDir, audit.CompactionConfig{
		MaxAge: maxAge,
		DryRun: dryRun,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// SetPolicyValidator sets the policy validation function.
func (s *Server) SetPolicyValidator(fn func() (any, error)) {
	s.validateFn = fn
}

func (s *Server) handlePolicyValidate(w http.ResponseWriter, r *http.Request) {
	if s.validateFn == nil {
		http.Error(w, `{"error":"policy validation not configured"}`, http.StatusInternalServerError)
		return
	}
	result, err := s.validateFn()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if s.auditLogPath == "" {
		http.Error(w, `{"error":"audit log path not configured"}`, http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	filter := audit.SearchFilter{
		Username: q.Get("username"),
		Action:   q.Get("action"),
		Limit:    1000,
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=argus-audit.csv")

	count, err := audit.ExportCSV(s.auditLogPath, w, filter)
	if err != nil {
		log.Printf("[argus] CSV export error: %v", err)
	}
	log.Printf("[argus] CSV export: %d events exported", count)
}

func (s *Server) handlePoolHealth(w http.ResponseWriter, r *http.Request) {
	poolStats := s.provider.PoolStats()
	summary := pool.Summarize(poolStats)

	resp := map[string]any{
		"summary": summary,
		"targets": poolStats,
	}

	w.Header().Set("Content-Type", "application/json")
	if summary.UnhealthyTargets > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDeepHealth(w http.ResponseWriter, r *http.Request) {
	poolStats := s.provider.PoolStats()

	var targets []string
	for _, ps := range poolStats {
		targets = append(targets, ps.Target)
	}

	results := pool.CheckAllTargets(targets, 5*time.Second)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// SetClassifyFunc sets the data classification function.
func (s *Server) SetClassifyFunc(fn func([]string) any) {
	s.classifyFn = fn
}

// SetPluginListFunc sets the plugin list function.
func (s *Server) SetPluginListFunc(fn func() any) {
	s.pluginListFn = fn
}

func (s *Server) handleClassify(w http.ResponseWriter, r *http.Request) {
	if s.classifyFn == nil {
		http.Error(w, `{"error":"classification not configured"}`, http.StatusInternalServerError)
		return
	}
	columns := r.URL.Query()["column"]
	if len(columns) == 0 {
		cols := r.URL.Query().Get("columns")
		if cols != "" {
			for _, c := range splitComma(cols) {
				columns = append(columns, c)
			}
		}
	}
	if len(columns) == 0 {
		http.Error(w, `{"error":"provide column names via ?column=x&column=y or ?columns=x,y"}`, http.StatusBadRequest)
		return
	}
	result := s.classifyFn(columns)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	if s.pluginListFn == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"plugins": []any{}, "count": 0})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.pluginListFn())
}

func splitComma(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

var (
	startTime = time.Now()
	Version   = "dev"
)
