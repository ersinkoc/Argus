package policy

import (
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

func TestMatchConditionAllPaths(t *testing.T) {
	// sql_contains not found
	ctx := &Context{RawSQL: "SELECT * FROM users", Timestamp: time.Now()}
	cond := &ConditionConfig{SQLContains: []string{"DROP"}}
	if matchCondition(ctx, cond) {
		t.Error("SELECT should not match sql_contains DROP")
	}

	// sql_contains found
	ctx.RawSQL = "DROP TABLE users"
	if !matchCondition(ctx, cond) {
		t.Error("DROP TABLE should match sql_contains DROP")
	}

	// source_ip_in match
	ctx.ClientIP = net.ParseIP("10.0.0.5")
	cond2 := &ConditionConfig{SourceIPIn: []string{"10.0.0.0/8"}}
	if !matchCondition(ctx, cond2) {
		t.Error("10.0.0.5 should be in 10.0.0.0/8")
	}

	// source_ip_in not match
	ctx.ClientIP = net.ParseIP("192.168.1.1")
	if matchCondition(ctx, cond2) {
		t.Error("192.168.1.1 should NOT be in 10.0.0.0/8")
	}

	// source_ip_not_in
	cond3 := &ConditionConfig{SourceIPNotIn: []string{"192.168.0.0/16"}}
	if matchCondition(ctx, cond3) {
		t.Error("192.168.1.1 IS in 192.168.0.0/16, should NOT match")
	}

	// max_cost_gte not reached
	ctx.CostScore = 30
	cond4 := &ConditionConfig{MaxCostGTE: 50}
	if matchCondition(ctx, cond4) {
		t.Error("cost 30 < 50 threshold")
	}

	// max_cost_gte reached
	ctx.CostScore = 80
	if !matchCondition(ctx, cond4) {
		t.Error("cost 80 >= 50 threshold")
	}

	// sql_regex match
	cond5 := &ConditionConfig{SQLRegex: []string{`(?i)DROP\s+TABLE`}}
	ctx.RawSQL = "DROP TABLE users"
	if !matchCondition(ctx, cond5) {
		t.Error("regex should match DROP TABLE")
	}
	ctx.RawSQL = "SELECT 1"
	if matchCondition(ctx, cond5) {
		t.Error("regex should NOT match SELECT")
	}
}

func TestEngineEvaluateCacheHit(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{{Name: "allow", Match: MatchConfig{}, Action: "allow"}},
	}
	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{Username: "u", CommandType: inspection.CommandSELECT, Timestamp: time.Now()}

	// First eval — cache miss
	d1 := engine.Evaluate(ctx)
	// Second eval — cache hit (same key)
	d2 := engine.Evaluate(ctx)

	if d1.PolicyName != d2.PolicyName {
		t.Error("cache should return same result")
	}
}

func TestMergePolicySetsDefaults(t *testing.T) {
	base := &PolicySet{
		Version:  "1",
		Defaults: DefaultsConfig{Action: "allow", LogLevel: "standard"},
	}
	overlay := &PolicySet{} // empty overlay

	merged := MergePolicySets(base, overlay)
	if merged.Defaults.Action != "allow" {
		t.Error("empty overlay should keep base defaults")
	}
}

func TestLoaderStartNoInterval(t *testing.T) {
	loader := NewLoader(nil, 0)
	loader.Start() // reloadInterval=0 → should not start goroutine
	loader.Stop()
}

func TestDryRunNoSQL(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{{Name: "a", Match: MatchConfig{}, Action: "allow"}},
	}
	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	result := engine.DryRun(DryRunInput{Username: "u", CommandType: "SELECT"})
	if result.Decision.Action != "allow" {
		t.Errorf("action = %q", result.Decision.Action)
	}
}
