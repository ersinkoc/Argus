package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/metrics"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/ratelimit"
	"github.com/ersinkoc/argus/internal/session"
)

// Proxy is the main Argus proxy engine.
// Proxy is the main Argus proxy engine.
type Proxy struct {
	cfg             *config.Config
	router          *Router
	sessionManager  *session.Manager
	policyEngine    *policy.Engine
	auditLogger     *audit.Logger
	pools           map[string]*pool.Pool
	rateLimiters    map[string]*ratelimit.Limiter
	listeners       []*Listener
	piiDetector     *masking.PIIDetector
	approvalManager *ApprovalManager
	queryRecorder   *audit.QueryRecorder
	onEvent         func(any) // broadcast callback (e.g. WebSocket)
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
		approvalManager: NewApprovalManager(cfg.Session.IdleTimeout),
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

// ApprovalManager returns the approval manager.
func (p *Proxy) ApprovalManager() *ApprovalManager {
	return p.approvalManager
}

// Start initializes pools, listeners and starts the proxy.
func (p *Proxy) Start() error {
	// Initialize connection pools for each target
	for _, target := range p.cfg.Targets {
		pl := pool.NewPool(
			target.Address(),
			p.cfg.Pool.MaxConnectionsPerTarget,
			p.cfg.Pool.MinIdleConnections,
			p.cfg.Pool.ConnectionMaxLifetime,
			p.cfg.Pool.ConnectionTimeout,
			p.cfg.Pool.HealthCheckInterval,
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

		pl.Start()
		p.pools[target.Name] = pl
	}

	// Start session manager
	p.sessionManager.OnTimeout(func(s *session.Session) {
		p.auditLogger.Log(audit.Event{
			EventType: audit.SessionTimeout.String(),
			SessionID: s.ID,
			Username:  s.Username,
			ClientIP:  s.ClientIP.String(),
			Database:  s.Database,
			Action:    "timeout",
		})
	})
	p.sessionManager.Start()

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
	log.Println("[argus] shutting down...")

	// Stop accepting new connections
	for _, l := range p.listeners {
		l.Stop()
	}

	// Drain active sessions — wait for in-flight queries
	activeSessions := p.sessionManager.ActiveSessions()
	if len(activeSessions) > 0 {
		log.Printf("[argus] draining %d active session(s)...", len(activeSessions))
		deadline := time.After(10 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

	drain:
		for {
			select {
			case <-deadline:
				remaining := p.sessionManager.Count()
				if remaining > 0 {
					log.Printf("[argus] drain timeout: force-closing %d session(s)", remaining)
					for _, s := range p.sessionManager.ActiveSessions() {
						p.sessionManager.Kill(s.ID)
					}
				}
				break drain
			case <-ticker.C:
				if p.sessionManager.Count() == 0 {
					log.Println("[argus] all sessions drained")
					break drain
				}
			}
		}
	}

	// Stop session manager
	p.sessionManager.Stop()

	// Close pools
	for _, pl := range p.pools {
		pl.Close()
	}

	log.Println("[argus] shutdown complete")
}

// SessionManager returns the session manager.
func (p *Proxy) SessionManager() *session.Manager {
	return p.sessionManager
}

// PoolStats returns stats for all pools.
func (p *Proxy) PoolStats() map[string]pool.PoolStats {
	stats := make(map[string]pool.PoolStats)
	for name, pl := range p.pools {
		stats[name] = pl.Stats()
	}
	return stats
}

func (p *Proxy) handleConnection(clientConn net.Conn, protocolName string) {
	defer clientConn.Close()

	remoteAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	handler := p.router.GetHandler(protocolName)
	if handler == nil {
		log.Printf("[argus] no handler for protocol %q", protocolName)
		return
	}

	// Resolve target (default for now, will be refined after auth)
	target := p.cfg.ResolveTarget("")
	if target == nil {
		log.Printf("[argus] no target configured")
		handler.WriteError(context.Background(), clientConn, "08001", "No target database configured")
		return
	}

	// Acquire backend connection
	pl := p.pools[target.Name]
	if pl == nil {
		log.Printf("[argus] no pool for target %q", target.Name)
		handler.WriteError(context.Background(), clientConn, "08001", "No connection pool for target")
		return
	}

	backendConn, err := pl.Acquire(context.Background())
	if err != nil {
		log.Printf("[argus] failed to acquire backend connection: %v", err)
		handler.WriteError(context.Background(), clientConn, "08001", fmt.Sprintf("Cannot connect to database: %v", err))
		return
	}
	defer pl.Remove(backendConn)

	// Perform handshake
	ctx := context.Background()
	sessionInfo, err := handler.Handshake(ctx, clientConn, backendConn.NetConn())
	if err != nil {
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(),
			ClientIP:  remoteAddr.IP.String(),
			Action:    "block",
			Error:     err.Error(),
		})
		log.Printf("[argus] handshake failed: %v", err)
		return
	}

	sessionInfo.ClientIP = remoteAddr.IP

	// Re-resolve target based on database name
	if sessionInfo.Database != "" {
		newTarget := p.cfg.ResolveTarget(sessionInfo.Database)
		if newTarget != nil && newTarget.Name != target.Name {
			// Need to switch backend - for MVP, we'll keep the initial connection
			// Full implementation would reconnect here
			target = newTarget
		}
	}

	// Create session
	sess := p.sessionManager.Create(sessionInfo, clientConn)
	sess.BackendConn = backendConn.NetConn()
	sess.Roles = policy.ResolveUserRoles(sessionInfo.Username, p.policyEngine.Loader().Current().Roles)

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

	log.Printf("[argus] session %s: user=%s db=%s from=%s",
		sess.ID[:8], sess.Username, sess.Database, remoteAddr.IP)

	// Command loop
	p.commandLoop(ctx, sess, handler, clientConn, backendConn.NetConn())

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

	log.Printf("[argus] session %s closed (commands=%d)", sess.ID[:8], sess.CommandCount)
}

func (p *Proxy) commandLoop(ctx context.Context, sess *session.Session, handler protocol.Handler, client, backend net.Conn) {
	for {
		// Read command from client
		cmd, rawMsg, err := handler.ReadCommand(ctx, client)
		if err != nil {
			return // client disconnected
		}

		// Terminate message
		if cmd == nil {
			// Forward terminate
			if rawMsg != nil {
				backend.Write(rawMsg)
			}
			return
		}

		sess.IncrementCommand()
		metrics.Global.CommandsTotal.Add(1)

		// Build policy context
		policyCtx := &policy.Context{
			Username:    sess.Username,
			Roles:       sess.Roles,
			ClientIP:    sess.ClientIP,
			Database:    sess.Database,
			Tables:      cmd.Tables,
			Columns:     cmd.Columns,
			Timestamp:   time.Now(),
			DayOfWeek:   time.Now().Weekday(),
			CommandType: cmd.Type,
			RiskLevel:   cmd.RiskLevel,
			RawSQL:      cmd.Raw,
			Confidence:  cmd.Confidence,
			HasWhere:    cmd.HasWhere,
		}

		// Evaluate policy
		decision := p.policyEngine.Evaluate(policyCtx)

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

		queryStart := time.Now()

		// Sanitize SQL for audit logging
		sanitizedSQL := audit.SanitizeSQL(cmd.Raw)

		switch decision.Action {
		case policy.ActionBlock:
			metrics.Global.CommandsBlocked.Add(1)
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
			// Approval workflow for high-risk commands
			if cmd.RiskLevel >= inspection.RiskHigh && p.approvalManager != nil && p.approvalManager.Count() >= 0 {
				// Check if policy requires approval (risk >= high and action is not already block)
				if cmd.RiskLevel >= inspection.RiskCritical {
					approvalReq := &ApprovalRequest{
						ID:         fmt.Sprintf("ar-%d", time.Now().UnixNano()),
						SessionID:  sess.ID,
						Username:   sess.Username,
						Database:   sess.Database,
						SQL:        sanitizedSQL,
						RiskLevel:  cmd.RiskLevel.String(),
						PolicyName: decision.PolicyName,
					}

					// Notify via WebSocket
					if p.onEvent != nil {
						p.onEvent(map[string]any{
							"type":    "approval_required",
							"request": approvalReq,
						})
					}

					status, err := p.approvalManager.RequestApproval(ctx, approvalReq)
					if err != nil || status != ApprovalApproved {
						reason := "approval denied or timed out"
						if err != nil {
							reason = err.Error()
						}
						handler.WriteError(ctx, client, "42501",
							fmt.Sprintf("Command requires approval: %s", reason))
						p.auditLogger.Log(audit.Event{
							EventType:   audit.CommandBlocked.String(),
							SessionID:   sess.ID,
							Username:    sess.Username,
							ClientIP:    sess.ClientIP.String(),
							Database:    sess.Database,
							Command:     sanitizedSQL,
							CommandType: cmd.Type.String(),
							RiskLevel:   cmd.RiskLevel.String(),
							Action:      "approval_denied",
							Reason:      reason,
						})
						continue
					}
				}
			}

			// Forward command to backend
			if err := handler.ForwardCommand(ctx, rawMsg, backend); err != nil {
				log.Printf("[argus] forward error: %v", err)
				return
			}

			// Set up masking pipeline if needed
			var pipeline *masking.Pipeline
			if decision.Action == policy.ActionMask && len(decision.MaskingRules) > 0 {
				pipeline = masking.NewPipeline(decision.MaskingRules, nil, decision.MaxRows)
			}

			// Read and forward result
			stats, err := handler.ReadAndForwardResult(ctx, backend, client, pipeline)
			if err != nil {
				log.Printf("[argus] result forward error: %v", err)
				return
			}

			duration := time.Since(queryStart)
			fingerprint := inspection.FingerprintHash(cmd.Raw)

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
		}
	}
}
