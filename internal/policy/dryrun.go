package policy

import (
	"encoding/json"
	"net"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

// DryRunResult captures a simulated policy evaluation without enforcement.
type DryRunResult struct {
	Input    DryRunInput    `json:"input"`
	Decision DryRunDecision `json:"decision"`
	Duration string         `json:"duration"`
}

// DryRunInput is the simulated request.
type DryRunInput struct {
	Username    string   `json:"username"`
	Database    string   `json:"database"`
	SQL         string   `json:"sql"`
	CommandType string   `json:"command_type"`
	Tables      []string `json:"tables"`
	ClientIP    string   `json:"client_ip"`
}

// DryRunDecision is the simulated policy result.
type DryRunDecision struct {
	Action       string           `json:"action"`
	PolicyName   string           `json:"policy_name"`
	Reason       string           `json:"reason"`
	RiskScore    int              `json:"risk_score"`
	MaskingRules []MaskingRule    `json:"masking_rules,omitempty"`
	MaxRows      int64            `json:"max_rows,omitempty"`
	RateLimit    *RateLimitConfig `json:"rate_limit,omitempty"`
}

// DryRun evaluates a simulated request against the current policy set.
func (e *Engine) DryRun(input DryRunInput) *DryRunResult {
	start := time.Now()

	// Classify the SQL if provided
	var cmd *inspection.Command
	if input.SQL != "" {
		cmd = inspection.Classify(input.SQL)
	}

	ctx := &Context{
		Username:   input.Username,
		Database:   input.Database,
		Tables:     input.Tables,
		RawSQL:    input.SQL,
		Timestamp: time.Now(),
	}

	if input.ClientIP != "" {
		ctx.ClientIP = net.ParseIP(input.ClientIP)
	}

	if cmd != nil {
		ctx.CommandType = cmd.Type
		ctx.RiskLevel = cmd.RiskLevel
		ctx.HasWhere = cmd.HasWhere
		if len(ctx.Tables) == 0 {
			ctx.Tables = cmd.Tables
		}
		ctx.Columns = cmd.Columns
	}

	// Parse command type override
	if input.CommandType != "" && cmd == nil {
		cmdTypeMap := map[string]inspection.CommandType{
			"SELECT": inspection.CommandSELECT,
			"INSERT": inspection.CommandINSERT,
			"UPDATE": inspection.CommandUPDATE,
			"DELETE": inspection.CommandDELETE,
			"DDL":    inspection.CommandDDL,
			"DCL":    inspection.CommandDCL,
		}
		if ct, ok := cmdTypeMap[input.CommandType]; ok {
			ctx.CommandType = ct
		}
	}

	decision := e.Evaluate(ctx)

	return &DryRunResult{
		Input: input,
		Decision: DryRunDecision{
			Action:       decision.Action.String(),
			PolicyName:   decision.PolicyName,
			Reason:       decision.Reason,
			RiskScore:    decision.RiskScore,
			MaskingRules: decision.MaskingRules,
			MaxRows:      decision.MaxRows,
			RateLimit:    decision.RateLimit,
		},
		Duration: time.Since(start).String(),
	}
}

// DryRunJSON is a convenience method that returns JSON bytes.
func (e *Engine) DryRunJSON(input DryRunInput) ([]byte, error) {
	result := e.DryRun(input)
	return json.MarshalIndent(result, "", "  ")
}
