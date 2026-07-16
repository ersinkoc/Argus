package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/metrics"
	"github.com/ersinkoc/argus/internal/plan"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/ratelimit"
	"github.com/ersinkoc/argus/internal/session"
)

// Proxy is the main Argus proxy engine.
type Proxy struct {
	cfg               *config.Config
	router            *Router
	sessionManager    *session.Manager
	policyEngine      *policy.Engine
	auditLogger       *audit.Logger
	pools             map[string]*pool.Pool
	poolsMu           sync.RWMutex
	rateLimiters      map[string]*ratelimit.Limiter
	listeners         []*Listener
	piiDetector       *masking.PIIDetector
	anomalyDetector   *inspection.AnomalyDetector
	approvalManager   *ApprovalManager
	queryRecorder     *audit.QueryRecorder
	slowQueryLogger   *audit.SlowQueryLogger
	rewriter          *inspection.Rewriter
	sessionLimiter    *session.ConcurrencyLimiter
	onEvent           func(any) // broadcast callback (e.g. WebSocket)
	rlCleanupStop     chan struct{}
	rlCleanupInterval time.Duration // default 5 min; override in tests
	drainTimeout      time.Duration // default 10s; override in tests
	hookChain         *PipelineHookChain
	identityResolver  IdentityResolver // for proxy auth mode (nil = passthrough)
}

// NewProxy creates a new proxy engine.
func NewProxy(cfg *config.Config, policyEngine *policy.Engine, auditLogger *audit.Logger) *Proxy {
	return &Proxy{
		cfg:             cfg,
		router:          NewRouter(),
		sessionManager:  session.NewManager(cfg.Session.IdleTimeout, cfg.Session.MaxDuration),
		policyEngine:    policyEngine,
		auditLogger:     auditLogger,
		pools:           make(map[string]*pool.Pool),
		rateLimiters:    make(map[string]*ratelimit.Limiter),
		piiDetector:     masking.NewPIIDetector(),
		anomalyDetector: inspection.NewAnomalyDetector(24 * time.Hour),
		approvalManager: NewApprovalManager(cfg.Session.IdleTimeout),
		hookChain:       NewPipelineHookChain(),
	}
}

// SetQueryRecorder enables forensic query recording.
func (p *Proxy) SetQueryRecorder(r *audit.QueryRecorder) {
	p.queryRecorder = r
}

// SetOnEvent sets a broadcast callback for live monitoring.
func (p *Proxy) SetOnEvent(fn func(any)) {
	p.onEvent = fn
}

// SetSlowQueryLogger enables slow query logging.
func (p *Proxy) SetSlowQueryLogger(s *audit.SlowQueryLogger) {
	p.slowQueryLogger = s
}

// SetPipelineHooks replaces the pipeline hook chain with the given hooks.
// Call before Start(). Each call replaces the previous chain entirely.
func (p *Proxy) SetPipelineHooks(hooks ...PipelineHook) {
	p.hookChain = NewPipelineHookChain()
	for _, h := range hooks {
		p.hookChain.Add(h)
	}
}

// SetIdentityResolver sets the identity resolver for proxy auth mode.
// When set, the proxy reads the client startup, calls the resolver to get
// the real target and credential, then performs proxy auth instead of
// the standard passthrough handshake.
func (p *Proxy) SetIdentityResolver(r IdentityResolver) {
	p.identityResolver = r
}

// SetRewriter enables query rewriting.
func (p *Proxy) SetRewriter(r *inspection.Rewriter) {
	p.rewriter = r
}

// SetSessionLimiter sets the per-user concurrent session limiter.
func (p *Proxy) SetSessionLimiter(l *session.ConcurrencyLimiter) {
	p.sessionLimiter = l
}

// SetSessionCheckInterval sets how often session timeouts are checked.
// It must be called before Start.
func (p *Proxy) SetSessionCheckInterval(interval time.Duration) {
	p.sessionManager.SetCheckInterval(interval)
}

// SetDrainTimeout sets how long Stop waits for active sessions to drain.
func (p *Proxy) SetDrainTimeout(timeout time.Duration) {
	if timeout > 0 {
		p.drainTimeout = timeout
	}
}

// ApprovalManager returns the approval manager.
func (p *Proxy) ApprovalManager() *ApprovalManager {
	return p.approvalManager
}

// Start initializes pools, listeners and starts the proxy.
func (p *Proxy) Start() error {
	// Initialize connection pools for each target
	for _, target := range p.cfg.Targets {
		// Server-speaks-first protocols (MySQL, MSSQL) use fresh connections
		// instead of pool, so disable warmup and health check to avoid
		// "aborted connection" warnings from unauthenticated TCP probes.
		minIdle := p.cfg.Pool.MinIdleConnections
		healthInterval := p.cfg.Pool.HealthCheckInterval
		if target.Protocol == "mysql" || target.Protocol == "mssql" {
			minIdle = 0
			healthInterval = 0 // disable TCP health probe for server-speaks-first
		}

		pl := pool.NewPool(
			target.Address(),
			p.cfg.Pool.MaxConnectionsPerTarget,
			minIdle,
			p.cfg.Pool.ConnectionMaxLifetime,
			p.cfg.Pool.ConnectionTimeout,
			healthInterval,
		)

		// Configure TLS for backend connection if enabled
		if target.TLS.Enabled {
			tlsCfg, err := MakeClientTLSConfig(target.TLS)
			if err != nil {
				return fmt.Errorf("backend TLS config for %s: %w", target.Name, err)
			}
			targetAddr := target.Address()
			pl.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
				d := tls.Dialer{Config: tlsCfg}
				return d.DialContext(ctx, "tcp", targetAddr)
			})
		}

		// Apply custom circuit breaker thresholds if configured
		if p.cfg.Pool.CircuitBreakerThreshold > 0 || p.cfg.Pool.CircuitBreakerResetTimeout > 0 {
			threshold := p.cfg.Pool.CircuitBreakerThreshold
			resetTimeout := p.cfg.Pool.CircuitBreakerResetTimeout
			pl.SetCircuitBreaker(threshold, resetTimeout)
		}
		if p.cfg.Pool.CircuitBreakerHalfOpenMax > 0 {
			pl.SetBreakerHalfOpenMax(p.cfg.Pool.CircuitBreakerHalfOpenMax)
		}

		pl.Start()
		p.poolsMu.Lock()
		p.pools[target.Name] = pl
		p.poolsMu.Unlock()
	}

	// Start session manager
	p.sessionManager.OnTimeout(func(s *session.Session, reason string) {
		p.auditLogger.Log(audit.Event{
			EventType: audit.SessionTimeout.String(),
			SessionID: s.ID,
			Username:  s.Username,
			ClientIP:  s.ClientIP.String(),
			Database:  s.Database,
			Action:    "timeout",
			Reason:    reason,
		})
	})
	p.sessionManager.Start()

	// Start periodic rate limiter cleanup to prevent memory leaks
	p.rlCleanupStop = make(chan struct{})
	interval := p.rlCleanupInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				for _, l := range p.rateLimiters {
					l.Cleanup()
				}
			case <-p.rlCleanupStop:
				return
			}
		}
	}()

	// Start listeners
	for _, listenerCfg := range p.cfg.Server.Listeners {
		l := NewListener(listenerCfg)
		protocolName := listenerCfg.Protocol
		l.OnConnection(func(conn net.Conn) {
			p.handleConnection(conn, protocolName)
		})
		if err := l.Start(); err != nil {
			return fmt.Errorf("starting listener: %w", err)
		}
		p.listeners = append(p.listeners, l)
	}

	return nil
}

// Stop gracefully stops the proxy with connection draining.
func (p *Proxy) Stop() {
	slog.Info("shutting down...")

	// Stop rate limiter cleanup goroutine
	if p.rlCleanupStop != nil {
		close(p.rlCleanupStop)
	}

	// Stop accepting new connections
	for _, l := range p.listeners {
		l.Stop()
	}

	// Drain active sessions — wait for in-flight queries
	activeSessions := p.sessionManager.ActiveSessions()
	if len(activeSessions) > 0 {
		slog.Info("draining active sessions", "count", len(activeSessions))
		drainTimeout := p.drainTimeout
		if drainTimeout <= 0 {
			drainTimeout = 10 * time.Second
		}
		deadline := time.After(drainTimeout)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

	drain:
		for {
			select {
			case <-deadline:
				remaining := p.sessionManager.Count()
				if remaining > 0 {
					slog.Warn("drain timeout: force-closing sessions", "count", remaining)
					for _, s := range p.sessionManager.ActiveSessions() {
						p.sessionManager.Kill(s.ID)
					}
				}
				break drain
			case <-ticker.C:
				if p.sessionManager.Count() == 0 {
					slog.Info("all sessions drained")
					break drain
				}
			}
		}
	}

	// Stop session manager
	p.sessionManager.Stop()

	// Close pools
	p.poolsMu.RLock()
	pools := make([]*pool.Pool, 0, len(p.pools))
	for _, pl := range p.pools {
		pools = append(pools, pl)
	}
	p.poolsMu.RUnlock()
	for _, pl := range pools {
		pl.Close()
	}

	slog.Info("shutdown complete")
}

// SessionManager returns the session manager.
func (p *Proxy) SessionManager() *session.Manager {
	return p.sessionManager
}

// PoolStats returns stats for all pools.
func (p *Proxy) PoolStats() map[string]pool.PoolStats {
	p.poolsMu.RLock()
	defer p.poolsMu.RUnlock()
	stats := make(map[string]pool.PoolStats)
	for name, pl := range p.pools {
		stats[name] = pl.Stats()
	}
	return stats
}

// Pools returns a snapshot of the connection pools (for gateway use).
func (p *Proxy) Pools() map[string]*pool.Pool {
	p.poolsMu.RLock()
	defer p.poolsMu.RUnlock()
	pools := make(map[string]*pool.Pool, len(p.pools))
	for name, pl := range p.pools {
		pools[name] = pl
	}
	return pools
}

func (p *Proxy) removePool(name string) {
	p.poolsMu.Lock()
	delete(p.pools, name)
	p.poolsMu.Unlock()
}

// AnomalyDetector returns the anomaly detector.
func (p *Proxy) AnomalyDetector() *inspection.AnomalyDetector {
	return p.anomalyDetector
}

func (p *Proxy) handleConnection(clientConn net.Conn, protocolName string) {
	defer clientConn.Close()

	remoteAddr, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		slog.Warn("non-TCP connection", "remote", clientConn.RemoteAddr())
		return
	}
	handler := p.router.GetHandler(protocolName)
	if handler == nil {
		slog.Warn("no handler for protocol", "protocol", protocolName)
		return
	}

	// Proxy auth mode: read startup, resolve identity, authenticate
	if p.identityResolver != nil {
		switch protocolName {
		case "postgresql":
			p.handleProxyAuthPG(clientConn, remoteAddr, handler)
			return
		case "mysql":
			p.handleProxyAuthMySQL(clientConn, remoteAddr, handler)
			return
		case "mssql":
			p.handleProxyAuthMSSQL(clientConn, remoteAddr, handler)
			return
		}
	}

	// Resolve target — first try protocol-matched target, then default
	var target *config.Target
	for i := range p.cfg.Targets {
		if p.cfg.Targets[i].Protocol == protocolName {
			target = &p.cfg.Targets[i]
			break
		}
	}
	if target == nil {
		target = p.cfg.ResolveTarget("")
	}
	if target == nil {
		slog.Error("no target configured for protocol", "protocol", protocolName)
		handler.WriteError(context.Background(), clientConn, "08001", "No target database configured")
		return
	}

	// Acquire backend connection
	// For server-speaks-first protocols (MySQL, MSSQL), we need a fresh
	// TCP connection because the greeting is sent immediately on connect
	// and pool connections have already consumed the greeting.
	var backendNetConn net.Conn
	var poolConn *pool.Conn
	p.poolsMu.RLock()
	pl := p.pools[target.Name]
	p.poolsMu.RUnlock()

	if protocolName == "mysql" || protocolName == "mssql" {
		// Fresh connection for server-speaks-first protocols
		dialTimeout := p.cfg.Pool.ConnectionTimeout
		if dialTimeout <= 0 {
			dialTimeout = 10 * time.Second
		}
		dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
		defer dialCancel()
		var d net.Dialer
		conn, err := d.DialContext(dialCtx, "tcp", target.Address())
		if err != nil {
			slog.Error("failed to connect to backend", "target", target.Name, "error", err)
			metrics.Global.ConnectionsFailed.Add(1)
			handler.WriteError(context.Background(), clientConn, "08001", "Cannot connect to database")
			return
		}
		backendNetConn = conn
		defer conn.Close()
	} else {
		// Pool connection for client-speaks-first protocols (PostgreSQL)
		if pl == nil {
			slog.Error("no pool for target", "target", target.Name)
			handler.WriteError(context.Background(), clientConn, "08001", "No connection pool for target")
			return
		}
		var err error
		poolConn, err = pl.Acquire(context.Background())
		if err != nil {
			slog.Error("failed to acquire backend connection", "target", target.Name, "error", err)
			metrics.Global.ConnectionsFailed.Add(1)
			handler.WriteError(context.Background(), clientConn, "08001", "Cannot connect to database")
			return
		}
		defer pl.Remove(poolConn)
		backendNetConn = poolConn.NetConn()
	}

	// Log connection open
	p.auditLogger.Log(audit.Event{
		EventType: audit.ConnectionOpen.String(),
		ClientIP:  remoteAddr.IP.String(),
		Action:    "accept",
	})

	// Perform handshake
	ctx := context.Background()
	sessionInfo, err := handler.Handshake(ctx, clientConn, backendNetConn)
	if err != nil {
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(),
			ClientIP:  remoteAddr.IP.String(),
			Action:    "block",
			Error:     err.Error(),
		})
		slog.Error("handshake failed", "error", err)
		return
	}

	sessionInfo.ClientIP = remoteAddr.IP

	// Re-resolve target based on database name (logged for future reconnect support)
	if sessionInfo.Database != "" {
		if newTarget := p.cfg.ResolveTarget(sessionInfo.Database); newTarget != nil && newTarget.Name != target.Name {
			slog.Info("database routing change", "session_id", "pending", "database", sessionInfo.Database, "new_target", newTarget.Name, "current_target", target.Name)
		}
	}

	// Check concurrent session limit
	if p.sessionLimiter != nil {
		if !p.sessionLimiter.Acquire(sessionInfo.Username) {
			handler.WriteError(context.Background(), clientConn, "53300",
				"Too many connections for user "+sessionInfo.Username)
			p.auditLogger.Log(audit.Event{
				EventType: audit.ConnectionClose.String(),
				Username:  sessionInfo.Username,
				ClientIP:  remoteAddr.IP.String(),
				Action:    "rejected",
				Reason:    "concurrent session limit exceeded",
			})
			return
		}
		defer p.sessionLimiter.Release(sessionInfo.Username)
	}

	// Create session
	sess := p.sessionManager.Create(sessionInfo, clientConn)
	sess.BackendConn = backendNetConn

	// Resolve roles from current policy set. If no policies are loaded,
	// Current() returns nil — use an empty map instead of panicking.
	// The policy engine itself will block with "no policies loaded — fail-closed"
	// when Evaluate() is called without policies.
	ps := p.policyEngine.Loader().Current()
	if ps != nil {
		sess.Roles = policy.ResolveUserRoles(sessionInfo.Username, ps.Roles)
	} else {
		sess.Roles = nil
		slog.Warn("no policy set loaded — connections will be blocked until policies are loaded")
	}

	metrics.Global.ConnectionsTotal.Add(1)
	p.auditLogger.Log(audit.Event{
		EventType: audit.AuthSuccess.String(),
		SessionID: sess.ID,
		Username:  sess.Username,
		Roles:     sess.Roles,
		ClientIP:  remoteAddr.IP.String(),
		Database:  sess.Database,
		Action:    "allow",
	})

	slog.Info("session opened", "session_id", sess.ID[:8], "user", sess.Username, "database", sess.Database, "client_ip", remoteAddr.IP)

	// PostAuth hooks (identity resolution, external auth checks, target selection)
	if p.hookChain.Count() > 0 {
		hctx := &HookContext{
			Stage: HookPostAuth,
			Session: &SessionSnapshot{
				ID:       sess.ID,
				Username: sess.Username,
				Database: sess.Database,
				ClientIP: sess.ClientIP.String(),
				Roles:    sess.Roles,
			},
		}
		if err := p.hookChain.RunPostAuth(hctx); err != nil {
			p.auditLogger.Log(audit.Event{
				EventType: audit.AuthFailure.String(),
				SessionID: sess.ID,
				Username:  sess.Username,
				ClientIP:  remoteAddr.IP.String(),
				Action:    "block",
				Error:     err.Error(),
			})
			handler.WriteError(context.Background(), clientConn, "28000", "Access denied: "+err.Error())
			return
		}
	}

	// Command loop
	p.commandLoop(ctx, sess, handler, clientConn, backendNetConn)

	// Session end
	p.sessionManager.Remove(sess.ID)
	p.auditLogger.Log(audit.Event{
		EventType: audit.ConnectionClose.String(),
		SessionID: sess.ID,
		Username:  sess.Username,
		ClientIP:  remoteAddr.IP.String(),
		Database:  sess.Database,
		Action:    "close",
	})

	cmdCount, _, _ := sess.Stats()
	slog.Info("session closed", "session_id", sess.ID[:8], "commands", cmdCount)
}

// handleProxyAuthPG handles the proxy auth flow for PostgreSQL connections.
// It reads the startup, resolves identity via the external resolver, connects to
// the resolved target, performs SASL/SCRAM auth on both sides, then continues
// with the standard session creation and command loop.
func (p *Proxy) handleProxyAuthPG(clientConn net.Conn, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	ctx := context.Background()

	sessionInfo, backendConn, err := p.PostAuthClientAndServer(clientConn, remoteAddr, handler.Name())
	if err != nil {
		slog.Error("proxy auth failed", "error", err)
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(),
			ClientIP:  remoteAddr.IP.String(),
			Action:    "block",
			Error:     err.Error(),
		})
		return
	}

	// Check concurrent session limit
	if p.sessionLimiter != nil {
		if !p.sessionLimiter.Acquire(sessionInfo.Username) {
			handler.WriteError(context.Background(), clientConn, "53300",
				"Too many connections for user "+sessionInfo.Username)
			p.auditLogger.Log(audit.Event{
				EventType: audit.ConnectionClose.String(),
				Username:  sessionInfo.Username,
				ClientIP:  remoteAddr.IP.String(),
				Action:    "rejected",
				Reason:    "concurrent session limit exceeded",
			})
			return
		}
		defer p.sessionLimiter.Release(sessionInfo.Username)
	}

	// Create session
	sess := p.sessionManager.Create(sessionInfo, clientConn)
	sess.BackendConn = backendConn
	ps := p.policyEngine.Loader().Current()
	if ps != nil {
		sess.Roles = policy.ResolveUserRoles(sessionInfo.Username, ps.Roles)
	} else {
		sess.Roles = nil
	}

	metrics.Global.ConnectionsTotal.Add(1)
	p.auditLogger.Log(audit.Event{
		EventType: audit.AuthSuccess.String(),
		SessionID: sess.ID,
		Username:  sess.Username,
		Roles:     sess.Roles,
		ClientIP:  remoteAddr.IP.String(),
		Database:  sess.Database,
		Action:    "allow",
	})

	slog.Info("session opened", "session_id", sess.ID[:8], "user", sess.Username, "database", sess.Database, "client_ip", remoteAddr.IP)

	// Command loop
	p.commandLoop(ctx, sess, handler, clientConn, backendConn)

	// Session end
	p.sessionManager.Remove(sess.ID)
	p.auditLogger.Log(audit.Event{
		EventType: audit.ConnectionClose.String(),
		SessionID: sess.ID,
		Username:  sess.Username,
		ClientIP:  remoteAddr.IP.String(),
		Database:  sess.Database,
		Action:    "close",
	})
	cmdCount, _, _ := sess.Stats()
	slog.Info("session closed", "session_id", sess.ID[:8], "commands", cmdCount)
}

func (p *Proxy) commandLoop(ctx context.Context, sess *session.Session, handler protocol.Handler, client, backend net.Conn) {
	protocolName := handler.Name()

	for {
		// Set read deadline to detect idle/dead clients
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))

		// Read command from client
		cmd, rawMsg, err := handler.ReadCommand(ctx, client)
		if err != nil {
			return // client disconnected or timeout
		}

		// Clear deadline for the rest of the pipeline
		client.SetReadDeadline(time.Time{})

		// Terminate message
		if cmd == nil {
			// Forward terminate
			if rawMsg != nil {
				backend.Write(rawMsg)
			}
			return
		}

		sess.IncrementCommand()
		sess.AddBytes(int64(len(rawMsg)), 0)
		metrics.Global.CommandsTotal.Add(1)

		// Per-protocol metrics
		recordProtocolCommand(protocolName)

		// Query cost estimation (before policy eval so policies can use it)
		costEstimate := inspection.EstimateCost(cmd)

		// Real plan cost via EXPLAIN — for PG and MySQL SELECT when plan_analysis is enabled.
		var planCost float64
		if p.cfg.PlanAnalysis.Enabled &&
			(protocolName == "postgresql" || protocolName == "mysql") &&
			cmd.Type == inspection.CommandSELECT &&
			cmd.Raw != "" && !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(cmd.Raw)), "EXPLAIN") {

			planTimeout := plan.DefaultTimeout
			if p.cfg.PlanAnalysis.Timeout != "" {
				if d, err := time.ParseDuration(p.cfg.PlanAnalysis.Timeout); err == nil {
					planTimeout = d
				}
			}
			planCtx, cancel := context.WithTimeout(ctx, planTimeout)
			var pr *plan.Result
			var planErr error
			if protocolName == "mysql" {
				pr, planErr = plan.ExplainMySQL(planCtx, backend, cmd.Raw, planTimeout)
			} else {
				pr, planErr = plan.ExplainPG(planCtx, backend, cmd.Raw, planTimeout)
			}
			if planErr == nil {
				planCost = pr.TotalCost
			}
			cancel()
		}

		// Build policy context
		policyCtx := &policy.Context{
			Username:    sess.Username,
			Roles:       sess.Roles,
			ClientIP:    sess.ClientIP,
			Database:    sess.Database,
			Tables:      cmd.Tables,
			Columns:     cmd.Columns,
			Timestamp:   time.Now(),
			CommandType: cmd.Type,
			RiskLevel:   cmd.RiskLevel,
			RawSQL:      cmd.Raw,
			HasWhere:    cmd.HasWhere,
			CostScore:   costEstimate.Score,
			PlanCost:    planCost,
		}

		// PreEval hooks (context enrichment before policy evaluation)
		if p.hookChain.Count() > 0 {
			p.hookChain.RunPreEval(&HookContext{
				Stage:     HookPreEval,
				PolicyCtx: policyCtx,
				Command:   cmd,
				Session: &SessionSnapshot{
					ID:       sess.ID,
					Username: sess.Username,
					Database: sess.Database,
					ClientIP: sess.ClientIP.String(),
					Roles:    sess.Roles,
				},
			})
		}

		// Evaluate policy
		decision := p.policyEngine.Evaluate(policyCtx)
		metrics.Global.PolicyEvals.Add(1)

		// Rate limit check
		if decision.RateLimit != nil && decision.Action != policy.ActionBlock {
			limiterKey := decision.PolicyName
			limiter, ok := p.rateLimiters[limiterKey]
			if !ok {
				limiter = ratelimit.NewLimiter(decision.RateLimit.Rate, decision.RateLimit.Burst)
				p.rateLimiters[limiterKey] = limiter
			}
			if !limiter.Allow(sess.Username) {
				decision.Action = policy.ActionBlock
				decision.Reason = "rate limit exceeded"
			}
		}

		// Anomaly detection: record and check
		if p.anomalyDetector != nil {
			now := time.Now()
			p.anomalyDetector.Record(sess.Username, cmd.Type, cmd.Tables, now)
			alerts := p.anomalyDetector.Check(sess.Username, cmd.Type, cmd.Tables, now)
			if len(alerts) > 0 && p.onEvent != nil {
				for _, alert := range alerts {
					p.onEvent(map[string]any{
						"type":  "anomaly",
						"alert": alert,
					})
				}
			}
		}

		// Broadcast high-cost query alert
		if costEstimate.Score >= 80 && p.onEvent != nil {
			p.onEvent(map[string]any{
				"type":     "high_cost_query",
				"username": sess.Username,
				"database": sess.Database,
				"cost":     costEstimate.Score,
				"factors":  costEstimate.Factors,
			})
		}

		// PostEval hooks (after decision, before action)
		if p.hookChain.Count() > 0 {
			p.hookChain.RunPostEval(&HookContext{
				Stage:     HookPostEval,
				Decision:  decision,
				PolicyCtx: policyCtx,
				Command:   cmd,
				Session: &SessionSnapshot{
					ID:       sess.ID,
					Username: sess.Username,
					Database: sess.Database,
					ClientIP: sess.ClientIP.String(),
					Roles:    sess.Roles,
				},
			})
		}

		queryStart := time.Now()

		// Sanitize SQL for audit logging
		sanitizedSQL := audit.SanitizeSQL(cmd.Raw)

		switch decision.Action {
		case policy.ActionBlock:
			metrics.Global.CommandsBlocked.Add(1)
			metrics.DatabaseStats.RecordBlocked(sess.Database)
			// Block the command
			handler.WriteError(ctx, client, "42501",
				fmt.Sprintf("Access denied: %s [policy: %s]", decision.Reason, decision.PolicyName))

			p.auditLogger.Log(audit.Event{
				EventType:   audit.CommandBlocked.String(),
				SessionID:   sess.ID,
				Username:    sess.Username,
				ClientIP:    sess.ClientIP.String(),
				Database:    sess.Database,
				Command:     sanitizedSQL,
				CommandType: cmd.Type.String(),
				Tables:      cmd.Tables,
				RiskLevel:   cmd.RiskLevel.String(),
				PolicyName:  decision.PolicyName,
				Action:      "block",
				Reason:      decision.Reason,
			})

		case policy.ActionMask, policy.ActionAllow, policy.ActionAudit:
			// Note: approval workflow is available via Admin API (ApprovalManager)
			// but not auto-triggered here — auto-triggering on risk level caused
			// production hangs on multi-statement queries.

			// Query rewrite (auto-LIMIT, WHERE injection)
			if p.rewriter != nil && cmd.Type == inspection.CommandSELECT {
				rewritten, rewrites := p.rewriter.Rewrite(cmd.Raw, cmd)
				if len(rewrites) > 0 {
					// Rebuild protocol message with rewritten SQL
					rebuilt := handler.RebuildQuery(rawMsg, rewritten)
					if rebuilt != nil {
						rawMsg = rebuilt
						cmd.Raw = rewritten
					}
					if p.onEvent != nil {
						p.onEvent(map[string]any{
							"type":     "query_rewrite",
							"username": sess.Username,
							"rewrites": rewrites,
						})
					}
				}
			}

			// Forward command to backend
			if err := handler.ForwardCommand(ctx, rawMsg, backend); err != nil {
				slog.Error("forward error", "error", err)
				return
			}

			// Set up masking pipeline
			var pipeline *masking.Pipeline
			maskRules := decision.MaskingRules

			// PII auto-detection: add masking rules from column name patterns
			if p.cfg.Audit.PIIAutoDetect && cmd.Type == inspection.CommandSELECT {
				// Column names aren't known yet (they come from RowDescription),
				// but we can pass the detector via a pipeline that will auto-detect.
				// For now, create an auto-detect pipeline that will be enhanced during result forwarding.
				if pipeline == nil && len(maskRules) == 0 {
					pipeline = masking.NewPipeline(nil, nil, decision.MaxRows)
					pipeline.SetPIIDetector(p.piiDetector)
				}
			}

			if len(maskRules) > 0 {
				pipeline = masking.NewPipeline(maskRules, nil, decision.MaxRows)
				if p.cfg.Audit.PIIAutoDetect {
					pipeline.SetPIIDetector(p.piiDetector)
				}
			}

			// Read and forward result
			stats, err := handler.ReadAndForwardResult(ctx, backend, client, pipeline)
			if err != nil {
				slog.Error("result forward error", "error", err)
				handler.WriteError(ctx, client, "08006", fmt.Sprintf("Backend error: %v", err))
				return
			}

			duration := time.Since(queryStart)
			fingerprint := inspection.FingerprintHashFromCommand(cmd)

			// Per-database metrics
			metrics.DatabaseStats.RecordQuery(sess.Database)
			metrics.DatabaseStats.RecordRows(sess.Database, stats.RowCount)
			sess.AddBytes(0, stats.ByteCount)

			// Track write operations
			switch cmd.Type {
			case inspection.CommandINSERT, inspection.CommandUPDATE,
				inspection.CommandDELETE, inspection.CommandDDL, inspection.CommandDCL:
				metrics.DatabaseStats.RecordWrite(sess.Database)
			}

			// Record query latency
			metrics.QueryLatency.Observe(float64(duration.Microseconds()))

			metrics.Global.ResultRowsTotal.Add(stats.RowCount)
			if len(stats.MaskedCols) > 0 {
				metrics.Global.CommandsMasked.Add(1)
			}

			// Query recording for forensics
			if p.queryRecorder != nil && p.queryRecorder.Enabled() {
				p.queryRecorder.Record(audit.QueryRecord{
					Timestamp:   queryStart,
					SessionID:   sess.ID,
					Username:    sess.Username,
					Database:    sess.Database,
					SQL:         cmd.Raw,
					CommandType: cmd.Type.String(),
					Tables:      cmd.Tables,
					Duration:    duration.Microseconds(),
					RowCount:    stats.RowCount,
					Action:      decision.Action.String(),
					PolicyName:  decision.PolicyName,
					Fingerprint: fingerprint,
				})
			}

			// Audit log
			event := audit.Event{
				EventType:   audit.CommandExecuted.String(),
				SessionID:   sess.ID,
				Username:    sess.Username,
				ClientIP:    sess.ClientIP.String(),
				Database:    sess.Database,
				Command:     sanitizedSQL,
				CommandType: cmd.Type.String(),
				Tables:      cmd.Tables,
				RiskLevel:   cmd.RiskLevel.String(),
				PolicyName:  decision.PolicyName,
				Action:      decision.Action.String(),
				RowCount:    stats.RowCount,
				ByteCount:   stats.ByteCount,
				Duration:    duration,
				MaskedCols:  stats.MaskedCols,
			}

			if stats.Truncated {
				event.EventType = audit.ResultTruncated.String()
			}
			if len(stats.MaskedCols) > 0 {
				event.EventType = audit.ResultMasked.String()
			}

			p.auditLogger.Log(event)

			// Slow query check
			if p.slowQueryLogger != nil {
				p.slowQueryLogger.Check(event, duration)
			}

			// Broadcast event for live monitoring
			if p.onEvent != nil {
				p.onEvent(map[string]any{
					"type":        "command",
					"session_id":  sess.ID,
					"username":    sess.Username,
					"database":    sess.Database,
					"command":     cmd.Type.String(),
					"tables":      cmd.Tables,
					"action":      decision.Action.String(),
					"rows":        stats.RowCount,
					"duration_us": duration.Microseconds(),
					"fingerprint": fingerprint,
				})
			}

			// PostExec hooks (after result forwarded, audited, and broadcast)
			if p.hookChain.Count() > 0 {
				p.hookChain.RunPostExec(&HookContext{
					Stage:    HookPostExec,
					Decision: decision,
					Command:  cmd,
					Session: &SessionSnapshot{
						ID:       sess.ID,
						Username: sess.Username,
						Database: sess.Database,
						ClientIP: sess.ClientIP.String(),
						Roles:    sess.Roles,
					},
				})
			}
		}
	}
}
