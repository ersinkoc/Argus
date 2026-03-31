package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/policy"
)

// HandleQuery handles POST /api/gateway/query — submit a SQL query.
func (gw *Gateway) HandleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	if req.SQL == "" {
		http.Error(w, `{"error":"sql is required"}`, http.StatusBadRequest)
		return
	}

	// Resolve username/database/roles from API key context
	var apiKeyRoles []string
	if apiKey, ok := r.Context().Value(gatewayAPIKeyCtx).(*APIKey); ok {
		if req.Username == "" {
			req.Username = apiKey.Username
		}
		if req.Database == "" && apiKey.Database != "" {
			req.Database = apiKey.Database
		}
		apiKeyRoles = apiKey.Roles
	}

	if req.Username == "" {
		http.Error(w, `{"error":"username is required"}`, http.StatusBadRequest)
		return
	}

	req.Roles = apiKeyRoles
	if apiKey, ok := r.Context().Value(gatewayAPIKeyCtx).(*APIKey); ok && apiKey.RateLimit > 0 {
		req.APIKeyLimit = apiKey.RateLimit
	}

	if req.ClientIP == "" {
		req.ClientIP = r.RemoteAddr
	}

	resp := gw.ExecuteQuery(r.Context(), req)

	status := http.StatusOK
	switch resp.Status {
	case "blocked":
		status = http.StatusForbidden
	case "pending_approval":
		status = http.StatusAccepted
	case "error":
		status = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

// ApproveRequest is the request body for POST /api/gateway/approve.
type ApproveRequest struct {
	ApprovalID string `json:"approval_id"`
	Approver   string `json:"approver"`
	Type       string `json:"type"`     // "one_time" or "time_window"
	Duration   string `json:"duration"` // e.g., "30m" for time_window
}

// HandleApprove handles POST /api/gateway/approve — approve a pending query.
func (gw *Gateway) HandleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	if req.ApprovalID == "" {
		http.Error(w, `{"error":"approval_id is required"}`, http.StatusBadRequest)
		return
	}

	// Get the pending approval to extract fingerprint/username/database
	pending := gw.approvalManager.Get(req.ApprovalID)
	if pending == nil {
		http.Error(w, `{"error":"approval not found or already resolved"}`, http.StatusNotFound)
		return
	}

	// Approve the request
	if err := gw.approvalManager.Approve(req.ApprovalID, req.Approver); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Create allowlist entry
	entry := &AllowlistEntry{
		Fingerprint: pending.Fingerprint,
		Username:    pending.Username,
		Database:    pending.Database,
		CreatedBy:   req.Approver,
		ApprovalID:  req.ApprovalID,
	}

	switch req.Type {
	case "one_time":
		entry.Type = AllowlistOneTime
		entry.ExpiresAt = time.Now().Add(1 * time.Hour) // safety expiry
	case "time_window":
		entry.Type = AllowlistTimeWindow
		dur, err := time.ParseDuration(req.Duration)
		if err != nil {
			dur = 30 * time.Minute
		}
		if dur < 30*time.Second {
			dur = 30 * time.Second
		}
		entry.ExpiresAt = time.Now().Add(dur)
	default:
		entry.Type = AllowlistOneTime
		entry.ExpiresAt = time.Now().Add(1 * time.Hour)
	}

	entryID := gw.allowlist.Add(entry)

	// Audit
	gw.auditLogger.Log(audit.Event{
		EventType: audit.ApprovalResolved.String(),
		Username:  pending.Username,
		Database:  pending.Database,
		Command:   pending.SQL,
		Action:    "approved",
		Reason:    fmt.Sprintf("approved by %s, type=%s", req.Approver, req.Type),
	})
	gw.auditLogger.Log(audit.Event{
		EventType: audit.AllowlistAdded.String(),
		Username:  pending.Username,
		Database:  pending.Database,
		Action:    "allow",
		Reason:    fmt.Sprintf("entry %s expires %s", entryID, entry.ExpiresAt.Format(time.RFC3339)),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status": "approved",
		"allowlist_entry": map[string]any{
			"id":          entryID,
			"fingerprint": entry.Fingerprint,
			"type":        req.Type,
			"expires_at":  entry.ExpiresAt,
		},
	})
}

// HandleAllowlist handles GET /api/gateway/allowlist and DELETE /api/gateway/allowlist?id=xxx.
func (gw *Gateway) HandleAllowlist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		entries := gw.allowlist.List()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"entries": entries,
			"count":   len(entries),
		})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, `{"error":"missing id parameter"}`, http.StatusBadRequest)
			return
		}
		if gw.allowlist.Remove(id) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "removed", "id": id})
		} else {
			http.Error(w, `{"error":"entry not found"}`, http.StatusNotFound)
		}

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// HandleQueryStatus handles GET /api/gateway/status?approval_id=xxx — poll approval status.
func (gw *Gateway) HandleQueryStatus(w http.ResponseWriter, r *http.Request) {
	approvalID := r.URL.Query().Get("approval_id")
	if approvalID == "" {
		http.Error(w, `{"error":"missing approval_id parameter"}`, http.StatusBadRequest)
		return
	}

	pending := gw.approvalManager.Get(approvalID)
	w.Header().Set("Content-Type", "application/json")

	if pending != nil {
		json.NewEncoder(w).Encode(map[string]any{
			"approval_id":  approvalID,
			"status":       "pending",
			"username":     pending.Username,
			"database":     pending.Database,
			"sql":          pending.SQL,
			"risk_level":   pending.RiskLevel,
			"fingerprint":  pending.Fingerprint,
			"requested_at": pending.RequestedAt,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]any{
			"approval_id": approvalID,
			"status":      "resolved_or_expired",
		})
	}
}

// HandleDryRun handles POST /api/gateway/dryrun — preview what would happen without executing.
func (gw *Gateway) HandleDryRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}
	if req.SQL == "" || req.Username == "" {
		http.Error(w, `{"error":"sql and username are required"}`, http.StatusBadRequest)
		return
	}

	// Resolve from API key context
	if apiKey, ok := r.Context().Value(gatewayAPIKeyCtx).(*APIKey); ok {
		if req.Username == "" {
			req.Username = apiKey.Username
		}
		if req.Database == "" && apiKey.Database != "" {
			req.Database = apiKey.Database
		}
	}

	// Run the pipeline up to (but not including) execution
	cmd := inspection.Classify(req.SQL)
	fingerprint := inspection.FingerprintHash(req.SQL)
	costEstimate := inspection.EstimateCost(cmd)

	var clientIP net.IP
	if req.ClientIP != "" {
		clientIP = net.ParseIP(req.ClientIP)
	}

	roles := req.Roles
	if len(roles) == 0 && gw.policyEngine.Loader().Current() != nil {
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
	needsApproval := gw.needsApproval(cmd)

	// Check if allowlist would match
	allowlistHit := gw.allowlist.Check(fingerprint, req.Username, req.Database) != nil

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"fingerprint":      fingerprint,
		"command_type":     cmd.Type.String(),
		"tables":           cmd.Tables,
		"risk_level":       cmd.RiskLevel.String(),
		"cost_score":       costEstimate.Score,
		"cost_factors":     costEstimate.Factors,
		"has_where":        cmd.HasWhere,
		"roles":            roles,
		"policy_action":    decision.Action.String(),
		"policy_name":      decision.PolicyName,
		"policy_reason":    decision.Reason,
		"risk_score":       decision.RiskScore,
		"masking_rules":    decision.MaskingRules,
		"max_rows":         decision.MaxRows,
		"needs_approval":   needsApproval,
		"allowlist_hit":    allowlistHit,
		"would_execute":    decision.Action != policy.ActionBlock && !needsApproval || allowlistHit,
	})
}

// gatewayAPIKeyCtx is the context key for the resolved API key.
type contextKey string

const gatewayAPIKeyCtx contextKey = "gateway_api_key"

// ContextWithAPIKey returns a context with the API key set.
func ContextWithAPIKey(ctx context.Context, key *APIKey) context.Context {
	return context.WithValue(ctx, gatewayAPIKeyCtx, key)
}
