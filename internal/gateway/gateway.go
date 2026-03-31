package gateway

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/core"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/ratelimit"
)

// QueryRequest is the inbound HTTP request body for gateway queries.
type QueryRequest struct {
	SQL      string   `json:"sql"`
	Username string   `json:"username"`
	Database string   `json:"database"`
	ClientIP string   `json:"client_ip,omitempty"`
	Roles        []string `json:"-"` // injected by auth middleware, not from JSON
	APIKeyLimit  float64  `json:"-"` // per-key rate limit (queries/sec), 0 = unlimited
}

// QueryResponse is the HTTP response for a gateway query.
type QueryResponse struct {
	Status      string       `json:"status"` // ok, blocked, masked, pending_approval, error
	Columns     []ColumnMeta `json:"columns,omitempty"`
	Rows        [][]any      `json:"rows,omitempty"`
	RowCount    int64        `json:"row_count"`
	Duration    string       `json:"duration,omitempty"`
	Fingerprint string       `json:"fingerprint"`
	ApprovalID  string       `json:"approval_id,omitempty"`
	MaskedCols  []string     `json:"masked_cols,omitempty"`
	Policy      PolicyInfo   `json:"policy"`
	Error       string       `json:"error,omitempty"`
}

// PolicyInfo describes the policy decision for a query.
type PolicyInfo struct {
	Action     string `json:"action"`
	PolicyName string `json:"policy_name"`
	Reason     string `json:"reason"`
	RiskScore  int    `json:"risk_score"`
}

// Gateway is the SQL gateway engine.
type Gateway struct {
	cfg             *config.Config
	policyEngine    *policy.Engine
	auditLogger     *audit.Logger
	approvalManager *core.ApprovalManager
	allowlist       *Allowlist
	apiKeyStore     *APIKeyStore
	pools           map[string]*pool.Pool
	anomalyDetector *inspection.AnomalyDetector
	rateLimiters    map[string]*ratelimit.Limiter
	rlMu            sync.Mutex
	onEvent         func(any)
	webhookNotifier  *WebhookNotifier
	piiDetector      *masking.PIIDetector
	cleanupStop      chan struct{}
}

// GatewayDeps holds the shared infrastructure dependencies.
type GatewayDeps struct {
	Cfg             *config.Config
	PolicyEngine    *policy.Engine
	AuditLogger     *audit.Logger
	ApprovalManager *core.ApprovalManager
	Pools           map[string]*pool.Pool
	AnomalyDetector *inspection.AnomalyDetector
	PIIDetector     *masking.PIIDetector
	OnEvent         func(any)
}

// New creates a new SQL gateway.
func New(deps GatewayDeps) *Gateway {
	gw := &Gateway{
		cfg:             deps.Cfg,
		policyEngine:    deps.PolicyEngine,
		auditLogger:     deps.AuditLogger,
		approvalManager: deps.ApprovalManager,
		pools:           deps.Pools,
		anomalyDetector: deps.AnomalyDetector,
		piiDetector:     deps.PIIDetector,
		onEvent:         deps.OnEvent,
		allowlist:       NewAllowlist(),
		apiKeyStore:     NewAPIKeyStore(),
		rateLimiters:    make(map[string]*ratelimit.Limiter),
	}
	// Start allowlist cleanup goroutine
	gw.cleanupStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				gw.allowlist.Cleanup()
			case <-gw.cleanupStop:
				return
			}
		}
	}()

	for _, keyCfg := range deps.Cfg.Gateway.APIKeys {
		gw.apiKeyStore.Add(&APIKey{
			Key:       keyCfg.Key,
			Username:  keyCfg.Username,
			Roles:     keyCfg.Roles,
			Database:  keyCfg.Database,
			RateLimit: keyCfg.RateLimit,
			Enabled:   keyCfg.Enabled,
		})
	}
	return gw
}

// Close stops the gateway's background goroutines.
func (gw *Gateway) Close() {
	if gw.cleanupStop != nil {
		close(gw.cleanupStop)
	}
}

// SetWebhookNotifier configures the approval webhook notifier.
func (gw *Gateway) SetWebhookNotifier(n *WebhookNotifier) { gw.webhookNotifier = n }

// APIKeyStore returns the API key store (for auth middleware).
func (gw *Gateway) APIKeyStore() *APIKeyStore { return gw.apiKeyStore }

// AllowlistStore returns the allowlist.
func (gw *Gateway) AllowlistStore() *Allowlist { return gw.allowlist }

// ApprovalManager returns the approval manager.
func (gw *Gateway) ApprovalManager() *core.ApprovalManager { return gw.approvalManager }

// ExecuteQuery runs a SQL query through the full Argus pipeline and returns results.
func (gw *Gateway) ExecuteQuery(ctx context.Context, req QueryRequest) QueryResponse {
	start := time.Now()

	// 1. Classify
	cmd := inspection.Classify(req.SQL)
	fingerprint := inspection.FingerprintHash(req.SQL)
	costEstimate := inspection.EstimateCost(cmd)

	// Per-API-key rate limit (before any processing)
	if req.APIKeyLimit > 0 {
		gw.rlMu.Lock()
		keyLimiter, ok := gw.rateLimiters["apikey:"+req.Username]
		if !ok {
			keyLimiter = ratelimit.NewLimiter(req.APIKeyLimit, int(req.APIKeyLimit)+1)
			gw.rateLimiters["apikey:"+req.Username] = keyLimiter
		}
		gw.rlMu.Unlock()
		if !keyLimiter.Allow(req.Username) {
			return QueryResponse{
				Status:      "blocked",
				Fingerprint: fingerprint,
				Error:       "API key rate limit exceeded",
				Policy:      PolicyInfo{Action: "block", Reason: "per-key rate limit"},
			}
		}
	}

	// Reject transactions
	if cmd.Type == inspection.CommandTCL {
		return QueryResponse{
			Status:      "error",
			Fingerprint: fingerprint,
			Error:       "Transactions (BEGIN/COMMIT/ROLLBACK) are not supported via gateway",
			Policy:      PolicyInfo{Action: "block", Reason: "transactions not supported in gateway mode"},
		}
	}

	// 2. Check allowlist (fast path)
	if entry := gw.allowlist.Check(fingerprint, req.Username, req.Database); entry != nil {
		gw.auditLogger.Log(audit.Event{
			EventType: audit.AllowlistUsed.String(),
			Username:  req.Username,
			Database:  req.Database,
			Command:   req.SQL,
			Action:    "allow",
			Reason:    fmt.Sprintf("allowlist entry %s (approved by %s)", entry.ID, entry.CreatedBy),
		})
		result, err := gw.executeOnBackend(ctx, req, nil)
		if err != nil {
			return QueryResponse{Status: "error", Fingerprint: fingerprint, Error: err.Error(), Duration: time.Since(start).String()}
		}
		return QueryResponse{
			Status: "ok", Columns: result.Columns, Rows: result.Rows, RowCount: result.RowCount,
			Fingerprint: fingerprint, Duration: time.Since(start).String(),
			Policy: PolicyInfo{Action: "allow", Reason: "pre-approved via allowlist"},
		}
	}

	// 3. Policy evaluation
	var clientIP net.IP
	if req.ClientIP != "" {
		clientIP = net.ParseIP(req.ClientIP)
	}
	// Resolve roles: prefer API key roles, fall back to policy file roles
	roles := req.Roles
	if len(roles) == 0 {
		roles = policy.ResolveUserRoles(req.Username, gw.policyEngine.Loader().Current().Roles)
	}

	policyCtx := &policy.Context{
		Username:    req.Username,
		Roles:       roles,
		ClientIP:    clientIP,
		Database:    req.Database,
		Tables:      cmd.Tables,
		Columns:     cmd.Columns,
		Timestamp:   time.Now(),
		CommandType: cmd.Type,
		RiskLevel:   cmd.RiskLevel,
		RawSQL:      req.SQL,
		HasWhere:    cmd.HasWhere,
		CostScore:   costEstimate.Score,
	}
	decision := gw.policyEngine.Evaluate(policyCtx)

	// 4. Rate limit
	if decision.RateLimit != nil && decision.Action != policy.ActionBlock {
		gw.rlMu.Lock()
		limiter, ok := gw.rateLimiters[decision.PolicyName]
		if !ok {
			limiter = ratelimit.NewLimiter(decision.RateLimit.Rate, decision.RateLimit.Burst)
			gw.rateLimiters[decision.PolicyName] = limiter
		}
		gw.rlMu.Unlock()
		if !limiter.Allow(req.Username) {
			return QueryResponse{
				Status: "blocked", Fingerprint: fingerprint, Duration: time.Since(start).String(),
				Policy: PolicyInfo{Action: "block", PolicyName: decision.PolicyName, Reason: "rate limit exceeded", RiskScore: decision.RiskScore},
				Error:  "Rate limit exceeded",
			}
		}
	}

	// 5. Anomaly detection
	if gw.anomalyDetector != nil {
		gw.anomalyDetector.Record(req.Username, cmd.Type, cmd.Tables, time.Now())
	}

	policyInfo := PolicyInfo{
		Action: decision.Action.String(), PolicyName: decision.PolicyName,
		Reason: decision.Reason, RiskScore: decision.RiskScore,
	}

	// 6. Check if approval is required
	if gw.needsApproval(cmd) {
		approvalID, err := gw.submitApproval(req, cmd, fingerprint, costEstimate.Score)
		if err != nil {
			return QueryResponse{Status: "error", Fingerprint: fingerprint, Error: err.Error(), Duration: time.Since(start).String(), Policy: policyInfo}
		}
		return QueryResponse{
			Status: "pending_approval", ApprovalID: approvalID, Fingerprint: fingerprint,
			Duration: time.Since(start).String(), Policy: policyInfo,
		}
	}

	// 7. Execute based on decision
	switch decision.Action {
	case policy.ActionBlock:
		gw.auditLogger.Log(audit.Event{
			EventType: audit.GatewayQuery.String(), Username: req.Username, ClientIP: req.ClientIP,
			Database: req.Database, Command: req.SQL, CommandType: cmd.Type.String(),
			Action: "block", PolicyName: decision.PolicyName, Reason: decision.Reason,
		})
		return QueryResponse{
			Status: "blocked", Fingerprint: fingerprint, Duration: time.Since(start).String(),
			Policy: policyInfo,
			Error:  fmt.Sprintf("Access denied: %s [policy: %s]", decision.Reason, decision.PolicyName),
		}

	case policy.ActionAllow, policy.ActionAudit, policy.ActionMask:
		// Pass masking rules to executor (pipeline created after columns are known)
		var maskRules []policy.MaskingRule
		if decision.Action == policy.ActionMask {
			maskRules = decision.MaskingRules
		}

		result, err := gw.executeOnBackend(ctx, req, maskRules)
		if err != nil {
			return QueryResponse{Status: "error", Fingerprint: fingerprint, Error: err.Error(), Duration: time.Since(start).String(), Policy: policyInfo}
		}

		status := "ok"
		if decision.Action == policy.ActionMask || len(result.MaskedCols) > 0 {
			status = "masked"
		}

		gw.auditLogger.Log(audit.Event{
			EventType: audit.GatewayQuery.String(), Username: req.Username, ClientIP: req.ClientIP,
			Database: req.Database, Command: req.SQL, CommandType: cmd.Type.String(),
			Tables: cmd.Tables, Action: decision.Action.String(), PolicyName: decision.PolicyName,
			RowCount: result.RowCount, MaskedCols: result.MaskedCols, Duration: time.Since(start),
		})

		return QueryResponse{
			Status: status, Columns: result.Columns, Rows: result.Rows, RowCount: result.RowCount,
			MaskedCols: result.MaskedCols, Fingerprint: fingerprint, Duration: time.Since(start).String(),
			Policy: policyInfo,
		}
	}

	return QueryResponse{Status: "error", Fingerprint: fingerprint, Error: "Unknown policy action", Policy: policyInfo}
}

// executeOnBackend runs SQL on the appropriate backend pool.
func (gw *Gateway) executeOnBackend(ctx context.Context, req QueryRequest, maskRules []policy.MaskingRule) (*RawResult, error) {
	target := gw.cfg.ResolveTarget(req.Database)
	if target == nil && gw.cfg.Routing.DefaultTarget != "" {
		target = gw.cfg.FindTarget(gw.cfg.Routing.DefaultTarget)
	}
	if target == nil {
		return nil, fmt.Errorf("no target found for database %q", req.Database)
	}
	pl, ok := gw.pools[target.Name]
	if !ok {
		return nil, fmt.Errorf("no connection pool for target %q", target.Name)
	}
	maxRows := gw.cfg.Gateway.MaxResultRows
	if maxRows <= 0 {
		maxRows = 10000
	}

	switch target.Protocol {
	case "postgresql":
		return executePG(ctx, pl, req.SQL, maxRows, maskRules, gw.piiDetector, gw.cfg.Audit.PIIAutoDetect)
	case "mysql":
		return executeMySQL(ctx, pl, req.SQL, maxRows, maskRules, gw.piiDetector, gw.cfg.Audit.PIIAutoDetect)
	default:
		return nil, fmt.Errorf("gateway execution not yet supported for protocol %q", target.Protocol)
	}
}

// needsApproval checks if a query requires admin approval.
func (gw *Gateway) needsApproval(cmd *inspection.Command) bool {
	reqCfg := gw.cfg.Gateway.RequireApproval
	if reqCfg.RiskLevelGTE != "" {
		threshold := inspection.ParseRiskLevel(reqCfg.RiskLevelGTE)
		if cmd.RiskLevel >= threshold {
			return true
		}
	}
	if len(reqCfg.Commands) > 0 {
		cmdStr := cmd.Type.String()
		for _, c := range reqCfg.Commands {
			if c == cmdStr {
				return true
			}
		}
	}
	return false
}

// submitApproval creates a pending approval request and optionally sends webhook.
func (gw *Gateway) submitApproval(req QueryRequest, cmd *inspection.Command, fingerprint string, costScore int) (string, error) {
	approvalReq := &core.ApprovalRequest{
		SessionID: "gateway", Username: req.Username, Database: req.Database,
		SQL: req.SQL, RiskLevel: cmd.RiskLevel.String(),
		Fingerprint: fingerprint, ClientIP: req.ClientIP, CostScore: costScore, Source: "gateway",
	}
	approvalID, err := gw.approvalManager.SubmitForApproval(approvalReq)
	if err != nil {
		return "", err
	}

	gw.auditLogger.Log(audit.Event{
		EventType: audit.ApprovalCreated.String(), Username: req.Username, ClientIP: req.ClientIP,
		Database: req.Database, Command: req.SQL, CommandType: cmd.Type.String(),
		Action: "pending", Reason: "approval required",
	})

	if gw.webhookNotifier != nil {
		gw.webhookNotifier.Notify(ApprovalWebhookPayload{
			EventType: "approval_required", ApprovalID: approvalID, Fingerprint: fingerprint,
			SQL: req.SQL, Username: req.Username, Database: req.Database,
			RiskLevel: cmd.RiskLevel.String(), CostScore: costScore, RequestedAt: time.Now(),
		})
	}
	return approvalID, nil
}
