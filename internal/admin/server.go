package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
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
	provider           SessionProvider
	addr               string
	server             *http.Server
	policyReloadFn     func() error
	policyListFn       func() []map[string]any
	EventStream        *EventStream
	approvalFn         ApprovalProvider
	auditLogPath       string
	recordFile         string
	dryRunFn           DryRunFunc
	configData         func() ([]byte, error)
	authToken          string
	allowedSources     []string
	trustedProxies     []string
	validateFn         func() (any, error)
	classifyFn         func([]string) any
	pluginListFn       func() any
	onSessionKill      func(sessionID string)
	gatewayHandler     GatewayHandler
	gatewayMiddleware  func(http.Handler) http.Handler
	enableAdminRoutes  bool
	enableMetricRoutes bool
}

// GatewayHandler is the interface for gateway HTTP handlers.
type GatewayHandler interface {
	HandleQuery(w http.ResponseWriter, r *http.Request)
	HandleApprove(w http.ResponseWriter, r *http.Request)
	HandleAllowlist(w http.ResponseWriter, r *http.Request)
	HandleQueryStatus(w http.ResponseWriter, r *http.Request)
	HandleDryRun(w http.ResponseWriter, r *http.Request)
}

// SetGateway sets the gateway handler and optional API key middleware.
func (s *Server) SetGateway(gw GatewayHandler, middleware func(http.Handler) http.Handler) {
	s.gatewayHandler = gw
	s.gatewayMiddleware = middleware
}

// NewServer creates a new admin server.
func NewServer(provider SessionProvider, addr string) *Server {
	return &Server{
		provider:           provider,
		addr:               addr,
		EventStream:        NewEventStream(),
		enableAdminRoutes:  true,
		enableMetricRoutes: true,
	}
}

// SetRouteModes controls which route groups are exposed by this server.
func (s *Server) SetRouteModes(enableAdminRoutes, enableMetricRoutes bool) {
	s.enableAdminRoutes = enableAdminRoutes
	s.enableMetricRoutes = enableMetricRoutes
}

// Addr returns the configured listen address.
func (s *Server) Addr() string {
	return s.addr
}

// RouteModes returns whether admin and metric routes are enabled on this server.
func (s *Server) RouteModes() (bool, bool) {
	return s.enableAdminRoutes, s.enableMetricRoutes
}

// SetAuthToken sets the bearer token and allowed source IPs for admin API authentication.
func (s *Server) SetAuthToken(token string, allowedSources ...string) {
	s.authToken = token
	s.allowedSources = allowedSources
}

// SetAllowedOrigins configures the WebSocket/browser origin allowlist.
func (s *Server) SetAllowedOrigins(origins ...string) {
	s.EventStream.SetAllowedOrigins(origins)
}

// SetTrustedProxies configures proxy IP ranges whose X-Forwarded-For header is trusted.
func (s *Server) SetTrustedProxies(proxies []string) {
	s.trustedProxies = proxies
}

// OnPolicyReload sets the callback for policy reload requests.
func (s *Server) OnPolicyReload(fn func() error) {
	s.policyReloadFn = fn
}

// SetPolicyListFn sets the callback for listing current policies.
func (s *Server) SetPolicyListFn(fn func() []map[string]any) {
	s.policyListFn = fn
}

// Start begins serving the admin/metrics endpoints.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	if s.enableMetricRoutes {
		mux.HandleFunc("/healthz", s.handleHealth)
		mux.HandleFunc("/metrics", s.handleMetrics)
		mux.HandleFunc("/ready", s.handleReady)
		mux.HandleFunc("/readyz", s.handleReady) // Kubernetes readiness probe alias
		mux.HandleFunc("/livez", s.handleLive)
	}
	if s.enableAdminRoutes {
		mux.HandleFunc("/api/sessions", s.handleSessions)
		mux.HandleFunc("/api/sessions/kill", s.handleSessionKill)
		mux.HandleFunc("/api/policies", s.handlePolicies)
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
		mux.HandleFunc("/api/audit/verify", s.handleAuditVerify)
		mux.HandleFunc("/api/policies/validate", s.handlePolicyValidate)
		mux.HandleFunc("/api/audit/export", s.handleAuditExport)
		mux.HandleFunc("/api/pool/health", s.handlePoolHealth)
		mux.HandleFunc("/api/health/deep", s.handleDeepHealth)
		mux.HandleFunc("/api/dashboard", s.handleDashboard)
		mux.HandleFunc("/api/classify", s.handleClassify)
		mux.HandleFunc("/api/plugins", s.handlePlugins)
		mux.HandleFunc("/api/test/run", handleTestRun)
		// Admin UI — React SPA (with fallback to old dashboard).
		// Both the React SPA and the legacy dashboard use inline scripts,
		// so 'unsafe-inline' is required for script-src and style-src.
		// A future improvement would use a Vite plugin to generate nonce/hash
		// values at build time, removing the need for 'unsafe-inline'.
		cspUI := CSPMiddleware("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'")
		if adminUI := NewAdminUIHandler("/ui"); adminUI != nil {
			mux.Handle("/ui/", cspUI(http.StripPrefix("/ui", adminUI)))
			mux.Handle("/ui", cspUI(http.StripPrefix("/ui", adminUI)))
		} else {
			// Fallback to the old embedded dashboard
			mux.HandleFunc("/ui", cspUI(http.HandlerFunc(HandleDashboardUI)).ServeHTTP)
		}
		mux.HandleFunc("/ui/test", cspUI(http.HandlerFunc(HandleTestRunnerUI)).ServeHTTP)
	}

	// Gateway endpoints (with optional API key middleware) — registered
	// outside admin auth so they are authenticated by API key only.
	if s.enableAdminRoutes && s.gatewayHandler != nil {
		wrapGW := func(h http.HandlerFunc) http.Handler {
			var handler http.Handler = h
			if s.gatewayMiddleware != nil {
				handler = s.gatewayMiddleware(handler)
			}
			return handler
		}
		mux.Handle("/api/gateway/query", wrapGW(s.gatewayHandler.HandleQuery))
		mux.Handle("/api/gateway/approve", wrapGW(s.gatewayHandler.HandleApprove))
		mux.Handle("/api/gateway/allowlist", wrapGW(s.gatewayHandler.HandleAllowlist))
		mux.Handle("/api/gateway/status", wrapGW(s.gatewayHandler.HandleQueryStatus))
		mux.Handle("/api/gateway/dryrun", wrapGW(s.gatewayHandler.HandleDryRun))
	}

	var handler http.Handler = mux

	// Wrap with CORS first (allows dev-mode cross-origin requests)
	if s.enableAdminRoutes {
		handler = NewCORS(handler, false, "http://localhost:5173", "http://127.0.0.1:5173")
	}

	if s.authToken != "" {
		auth := NewAuthMiddleware(s.authToken)
		// Gateway routes skip admin bearer auth — they use their own API key middleware.
		for _, p := range s.GatewayPublicPaths() {
			auth.publicPaths[p] = true
		}
		// WebSocket uses its own first-frame auth (not bearer header),
		// so the HTTP upgrade path must be publicly accessible.
		auth.publicPaths["/api/events/ws"] = true
		// Wire the token validator into the EventStream for first-frame auth.
		s.EventStream.SetAuth(func(token string) bool {
			return subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) == 1
		})
		// Admin UI paths must be public — the entire /ui/ tree is an SPA
		auth.publicPrefixes = append(auth.publicPrefixes, "/ui/")
		if len(s.allowedSources) > 0 {
			auth = auth.WithAllowedSources(s.allowedSources)
		}
		if len(s.trustedProxies) > 0 {
			auth = auth.WithTrustedProxies(s.trustedProxies)
		}
		handler = auth.Wrap(handler)
	}

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	slog.Info("admin/metrics server started", "addr", s.addr)

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin server error", "error", err)
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
		"uptime":          formatUptime(time.Since(startTime)),
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

	// ── Sessions ─────────────────────────────────────────────────────────
	fmt.Fprintf(w, "# HELP argus_active_sessions Current number of active client sessions\n")
	fmt.Fprintf(w, "# TYPE argus_active_sessions gauge\n")
	fmt.Fprintf(w, "argus_active_sessions %d\n", sm.Count())

	// ── Connections ───────────────────────────────────────────────────────
	fmt.Fprintf(w, "# HELP argus_connections_total Total client connections\n")
	fmt.Fprintf(w, "# TYPE argus_connections_total counter\n")
	fmt.Fprintf(w, "argus_connections_total{status=\"success\"} %d\n", m.ConnectionsTotal.Load())
	fmt.Fprintf(w, "argus_connections_total{status=\"failed\"} %d\n", m.ConnectionsFailed.Load())

	// ── Commands ──────────────────────────────────────────────────────────
	fmt.Fprintf(w, "# HELP argus_commands_total Total SQL commands processed\n")
	fmt.Fprintf(w, "# TYPE argus_commands_total counter\n")
	fmt.Fprintf(w, "argus_commands_total{action=\"allowed\"} %d\n", m.CommandsTotal.Load()-m.CommandsBlocked.Load())
	fmt.Fprintf(w, "argus_commands_total{action=\"blocked\"} %d\n", m.CommandsBlocked.Load())
	fmt.Fprintf(w, "argus_commands_total{action=\"masked\"} %d\n", m.CommandsMasked.Load())

	// ── Results ───────────────────────────────────────────────────────────
	fmt.Fprintf(w, "# HELP argus_result_rows_total Total result rows returned to clients\n")
	fmt.Fprintf(w, "# TYPE argus_result_rows_total counter\n")
	fmt.Fprintf(w, "argus_result_rows_total %d\n", m.ResultRowsTotal.Load())

	// ── Policy ────────────────────────────────────────────────────────────
	fmt.Fprintf(w, "# HELP argus_policy_evaluations_total Total policy evaluations\n")
	fmt.Fprintf(w, "# TYPE argus_policy_evaluations_total counter\n")
	fmt.Fprintf(w, "argus_policy_evaluations_total %d\n", m.PolicyEvals.Load())

	fmt.Fprintf(w, "# HELP argus_policy_cache_hits_total Policy evaluation cache hits\n")
	fmt.Fprintf(w, "# TYPE argus_policy_cache_hits_total counter\n")
	fmt.Fprintf(w, "argus_policy_cache_hits_total{result=\"hit\"} %d\n", m.PolicyCacheHits.Load())
	fmt.Fprintf(w, "argus_policy_cache_hits_total{result=\"miss\"} %d\n", m.PolicyCacheMisses.Load())

	// ── Connection pool ───────────────────────────────────────────────────
	fmt.Fprintf(w, "# HELP argus_pool_connections Active and idle pool connections per target\n")
	fmt.Fprintf(w, "# TYPE argus_pool_connections gauge\n")
	for name, ps := range poolStats {
		fmt.Fprintf(w, "argus_pool_connections{target=%q,state=\"active\"} %d\n", name, ps.Active)
		fmt.Fprintf(w, "argus_pool_connections{target=%q,state=\"idle\"} %d\n", name, ps.Idle)
		fmt.Fprintf(w, "argus_pool_connections{target=%q,state=\"total\"} %d\n", name, ps.Total)
	}

	fmt.Fprintf(w, "# HELP argus_pool_healthy Whether each target is healthy (1=healthy, 0=unhealthy)\n")
	fmt.Fprintf(w, "# TYPE argus_pool_healthy gauge\n")
	for name, ps := range poolStats {
		healthy := 0
		if ps.Healthy {
			healthy = 1
		}
		fmt.Fprintf(w, "argus_pool_healthy{target=%q} %d\n", name, healthy)
	}

	// ── Query latency histogram (Prometheus native format) ────────────────
	latency := metrics.QueryLatency.Snapshot()
	bounds := metrics.Bounds()
	fmt.Fprintf(w, "# HELP argus_query_duration_microseconds Query execution latency in microseconds\n")
	fmt.Fprintf(w, "# TYPE argus_query_duration_microseconds histogram\n")
	for i, bound := range bounds {
		fmt.Fprintf(w, "argus_query_duration_microseconds_bucket{le=\"%.0f\"} %d\n", bound, latency.Buckets[i])
	}
	fmt.Fprintf(w, "argus_query_duration_microseconds_bucket{le=\"+Inf\"} %d\n", latency.Count)
	fmt.Fprintf(w, "argus_query_duration_microseconds_sum %.0f\n", float64(latency.SumUS))
	fmt.Fprintf(w, "argus_query_duration_microseconds_count %d\n", latency.Count)

	// ── Pool acquire wait histogram ────────────────────────────────────────
	hist := pool.WaitHistogram.Snapshot()
	fmt.Fprintf(w, "# HELP argus_pool_acquire_wait_microseconds Pool connection acquire wait latency\n")
	fmt.Fprintf(w, "# TYPE argus_pool_acquire_wait_microseconds histogram\n")
	poolBounds := pool.WaitHistogram.Bounds()
	poolBuckets := pool.WaitHistogram.CumulativeBuckets()
	for i, bound := range poolBounds {
		fmt.Fprintf(w, "argus_pool_acquire_wait_microseconds_bucket{le=\"%.0f\"} %d\n", bound, poolBuckets[i])
	}
	fmt.Fprintf(w, "argus_pool_acquire_wait_microseconds_bucket{le=\"+Inf\"} %d\n", hist.Count)
	fmt.Fprintf(w, "argus_pool_acquire_wait_microseconds_sum %d\n", hist.Sum)
	fmt.Fprintf(w, "argus_pool_acquire_wait_microseconds_count %d\n", hist.Count)

	// ── Per-protocol commands ─────────────────────────────────────────────
	ps := metrics.ProtocolStats
	fmt.Fprintf(w, "# HELP argus_protocol_commands_total Commands processed per protocol and type\n")
	fmt.Fprintf(w, "# TYPE argus_protocol_commands_total counter\n")
	fmt.Fprintf(w, "argus_protocol_commands_total{protocol=\"postgresql\",type=\"query\"} %d\n", ps.PGQueries.Load())
	fmt.Fprintf(w, "argus_protocol_commands_total{protocol=\"postgresql\",type=\"extended\"} %d\n", ps.PGExtended.Load())
	fmt.Fprintf(w, "argus_protocol_commands_total{protocol=\"postgresql\",type=\"copy\"} %d\n", ps.PGCopy.Load())
	fmt.Fprintf(w, "argus_protocol_commands_total{protocol=\"mysql\",type=\"query\"} %d\n", ps.MySQLQueries.Load())
	fmt.Fprintf(w, "argus_protocol_commands_total{protocol=\"mysql\",type=\"prepared\"} %d\n", ps.MySQLPrepared.Load())
	fmt.Fprintf(w, "argus_protocol_commands_total{protocol=\"mssql\",type=\"batch\"} %d\n", ps.MSSQLBatches.Load())
	fmt.Fprintf(w, "argus_protocol_commands_total{protocol=\"mongodb\",type=\"command\"} %d\n", ps.MongoDBCommands.Load())

	// ── Per-database stats ────────────────────────────────────────────────
	dbStats := metrics.DatabaseStats.Snapshot()
	if len(dbStats) > 0 {
		fmt.Fprintf(w, "# HELP argus_database_queries_total Queries processed per database\n")
		fmt.Fprintf(w, "# TYPE argus_database_queries_total counter\n")
		for db, stat := range dbStats {
			fmt.Fprintf(w, "argus_database_queries_total{database=%q} %d\n", db, stat["queries"])
		}
		fmt.Fprintf(w, "# HELP argus_database_writes_total Write commands per database\n")
		fmt.Fprintf(w, "# TYPE argus_database_writes_total counter\n")
		for db, stat := range dbStats {
			fmt.Fprintf(w, "argus_database_writes_total{database=%q} %d\n", db, stat["writes"])
		}
		fmt.Fprintf(w, "# HELP argus_database_blocked_total Blocked commands per database\n")
		fmt.Fprintf(w, "# TYPE argus_database_blocked_total counter\n")
		for db, stat := range dbStats {
			fmt.Fprintf(w, "argus_database_blocked_total{database=%q} %d\n", db, stat["blocked"])
		}
		fmt.Fprintf(w, "# HELP argus_database_rows_total Rows returned per database\n")
		fmt.Fprintf(w, "# TYPE argus_database_rows_total counter\n")
		for db, stat := range dbStats {
			fmt.Fprintf(w, "argus_database_rows_total{database=%q} %d\n", db, stat["rows"])
		}
	}

	// ── Go runtime ────────────────────────────────────────────────────────
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fmt.Fprintf(w, "# HELP argus_go_goroutines Current number of goroutines\n")
	fmt.Fprintf(w, "# TYPE argus_go_goroutines gauge\n")
	fmt.Fprintf(w, "argus_go_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP argus_go_alloc_bytes Bytes of allocated heap objects\n")
	fmt.Fprintf(w, "# TYPE argus_go_alloc_bytes gauge\n")
	fmt.Fprintf(w, "argus_go_alloc_bytes %d\n", memStats.Alloc)
	fmt.Fprintf(w, "# HELP argus_go_sys_bytes Total bytes of memory obtained from the OS\n")
	fmt.Fprintf(w, "# TYPE argus_go_sys_bytes gauge\n")
	fmt.Fprintf(w, "argus_go_sys_bytes %d\n", memStats.Sys)
	fmt.Fprintf(w, "# HELP argus_go_gc_runs_total Total number of completed GC cycles\n")
	fmt.Fprintf(w, "# TYPE argus_go_gc_runs_total counter\n")
	fmt.Fprintf(w, "argus_go_gc_runs_total %d\n", memStats.NumGC)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.provider.SessionManager().ActiveSessions()

	type sessionInfo struct {
		ID           string            `json:"id"`
		Username     string            `json:"username"`
		Database     string            `json:"database"`
		ClientIP     string            `json:"client_ip"`
		AuthMethod   string            `json:"auth_method,omitempty"`
		Roles        []string          `json:"roles"`
		Parameters   map[string]string `json:"parameters,omitempty"`
		Duration     string            `json:"duration"`
		IdleDuration string            `json:"idle_duration"`
		CommandCount int64             `json:"command_count"`
		BytesIn      int64             `json:"bytes_in"`
		BytesOut     int64             `json:"bytes_out"`
	}

	result := make([]sessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		cmdCount, bIn, bOut := sess.Stats()
		result = append(result, sessionInfo{
			ID:           sess.ID,
			Username:     sess.Username,
			Database:     sess.Database,
			ClientIP:     sess.ClientIP.String(),
			AuthMethod:   sess.AuthMethod,
			Roles:        sess.Roles,
			Parameters:   sess.Parameters,
			Duration:     sess.Duration().String(),
			IdleDuration: sess.IdleDuration().String(),
			CommandCount: cmdCount,
			BytesIn:      bIn,
			BytesOut:     bOut,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleSessionKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "missing id parameter")
		return
	}

	if err := s.provider.SessionManager().Kill(sessionID); err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}

	if s.onSessionKill != nil {
		s.onSessionKill(sessionID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "killed",
		"session": sessionID,
	})
}

func (s *Server) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	if s.policyReloadFn == nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "policy reload not configured")
		return
	}

	if err := s.policyReloadFn(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reloaded"})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "use GET")
		return
	}
	if s.policyListFn == nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "policy list not available")
		return
	}
	policies := s.policyListFn()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	m := metrics.Global
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	resp := map[string]any{
		"uptime":      formatUptime(time.Since(startTime)),
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
		writeAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if s.approvalFn == nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "approval not configured")
		return
	}
	id := r.URL.Query().Get("id")
	approver := r.URL.Query().Get("approver")
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "missing id")
		return
	}
	if approver == "" {
		approver = "admin"
	}
	if err := s.approvalFn.Approve(id, approver); err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "approved", "id": id})
}

func (s *Server) handleApprovalDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if s.approvalFn == nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "approval not configured")
		return
	}
	id := r.URL.Query().Get("id")
	approver := r.URL.Query().Get("approver")
	reason := r.URL.Query().Get("reason")
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "missing id")
		return
	}
	if approver == "" {
		approver = "admin"
	}
	if err := s.approvalFn.Deny(id, approver, reason); err != nil {
		writeAPIError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "denied", "id": id})
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
			"uptime":            formatUptime(time.Since(startTime)),
			"version":           Version,
			"active_sessions":   sm.Count(),
			"goroutines":        runtime.NumGoroutine(),
			"memory_mb":         memStats.Alloc / 1024 / 1024,
			"healthy_targets":   healthyTargets,
			"unhealthy_targets": unhealthyTargets,
		},
		"traffic": map[string]any{
			"total_connections":  m.ConnectionsTotal.Load(),
			"failed_connections": m.ConnectionsFailed.Load(),
			"total_commands":     m.CommandsTotal.Load(),
			"blocked_commands":   m.CommandsBlocked.Load(),
			"masked_results":     m.CommandsMasked.Load(),
			"total_rows":         m.ResultRowsTotal.Load(),
		},
		"pool": map[string]any{
			"active_connections": totalActive,
			"idle_connections":   totalIdle,
			"wait_p50_us":        histSnap.P50,
			"wait_p95_us":        histSnap.P95,
			"wait_p99_us":        histSnap.P99,
			"targets":            poolStats,
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

func (s *Server) handleDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if s.dryRunFn == nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "dry-run not configured")
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
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if s.configData == nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "config export not configured")
		return
	}

	data, err := s.configData()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
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

// SetPolicyValidator sets the policy validation function.
func (s *Server) SetPolicyValidator(fn func() (any, error)) {
	s.validateFn = fn
}

func (s *Server) handlePolicyValidate(w http.ResponseWriter, r *http.Request) {
	if s.validateFn == nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "policy validation not configured")
		return
	}
	result, err := s.validateFn()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
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

// SetOnSessionKill sets a callback invoked after a session is killed via the admin API.
func (s *Server) SetOnSessionKill(fn func(sessionID string)) {
	s.onSessionKill = fn
}

func (s *Server) handleClassify(w http.ResponseWriter, r *http.Request) {
	if s.classifyFn == nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "classification not configured")
		return
	}
	columns := r.URL.Query()["column"]
	if len(columns) == 0 {
		cols := r.URL.Query().Get("columns")
		if cols != "" {
			columns = append(columns, splitComma(cols)...)
		}
	}
	if len(columns) == 0 {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "provide column names via ?column=x&column=y or ?columns=x,y")
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

// formatUptime formats a duration into a human-friendly string like "2d 5h 14m 3s".
func formatUptime(d time.Duration) string {
	d = d.Truncate(time.Second)
	if d < time.Second {
		return "0s"
	}

	days := int(d.Hours()) / 24
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d.Hours())
	d -= time.Duration(hours) * time.Hour
	minutes := int(d.Minutes())
	d -= time.Duration(minutes) * time.Minute
	seconds := int(d.Seconds())

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	return strings.Join(parts, " ")
}
