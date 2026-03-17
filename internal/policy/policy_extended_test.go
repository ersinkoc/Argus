package policy

import (
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

func TestPolicyCacheInvalidation(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{
			{Name: "allow-all", Match: MatchConfig{}, Action: "allow"},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		RawSQL:      "SELECT 1",
		Timestamp:   time.Now(),
	}

	// First eval — cache miss
	d1 := engine.Evaluate(ctx)
	if d1.Action != ActionAllow {
		t.Errorf("action = %v, want allow", d1.Action)
	}

	// Second eval — cache hit (same context)
	d2 := engine.Evaluate(ctx)
	if d2.PolicyName != d1.PolicyName {
		t.Error("cached result should match")
	}

	// Invalidate cache
	engine.InvalidateCache()

	// Third eval — cache miss again
	d3 := engine.Evaluate(ctx)
	if d3.Action != ActionAllow {
		t.Error("should still allow after cache invalidation")
	}
}

func TestPolicyIPCondition(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{
			{
				Name:  "block-external",
				Match: MatchConfig{},
				Condition: &ConditionConfig{
					SourceIPNotIn: []string{"10.0.0.0/8"},
				},
				Action: "block",
			},
			{Name: "allow-all", Match: MatchConfig{}, Action: "allow"},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	// Internal IP — should be allowed
	ctx := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		ClientIP:    net.ParseIP("10.0.1.50"),
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionAllow {
		t.Errorf("internal IP should be allowed, got %v", d.Action)
	}

	// External IP — should be blocked
	engine.InvalidateCache()
	ctx.ClientIP = net.ParseIP("203.0.113.1")
	d = engine.Evaluate(ctx)
	if d.Action != ActionBlock {
		t.Errorf("external IP should be blocked, got %v", d.Action)
	}
}

func TestPolicyCostCondition(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{
			{
				Name:      "block-expensive",
				Match:     MatchConfig{},
				Condition: &ConditionConfig{MaxCostGTE: 70},
				Action:    "block",
				Reason:    "query too expensive",
			},
			{Name: "allow-all", Match: MatchConfig{}, Action: "allow"},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	// Low cost — allowed
	ctx := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		CostScore:   20,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionAllow {
		t.Errorf("low cost should be allowed, got %v", d.Action)
	}

	// High cost — blocked
	engine.InvalidateCache()
	ctx.CostScore = 85
	d = engine.Evaluate(ctx)
	if d.Action != ActionBlock {
		t.Errorf("high cost should be blocked, got %v (%s)", d.Action, d.PolicyName)
	}
}

func TestPolicyDefaultAction(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "audit", LogLevel: "verbose"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{}, // no rules — defaults apply
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionAudit {
		t.Errorf("should use default action 'audit', got %v", d.Action)
	}
	if d.LogLevel != "verbose" {
		t.Errorf("should use default log_level, got %q", d.LogLevel)
	}
}

func TestPolicyRateLimitInDecision(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{
			{
				Name:      "rate-limited",
				Match:     MatchConfig{},
				Action:    "allow",
				RateLimit: &RateLimitConfig{Rate: 10, Burst: 5},
			},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.RateLimit == nil {
		t.Error("decision should include rate limit config")
	}
	if d.RateLimit.Rate != 10 {
		t.Errorf("rate = %v, want 10", d.RateLimit.Rate)
	}
}
