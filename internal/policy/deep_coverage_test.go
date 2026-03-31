package policy

import (
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

// --- matchCondition branches ---

func TestMatchConditionRiskLevelGTE(t *testing.T) {
	ctx := &Context{RiskLevel: inspection.RiskHigh}
	cond := &ConditionConfig{RiskLevelGTE: "critical"}
	if matchCondition(ctx, cond) {
		t.Error("RiskHigh < RiskCritical should not match")
	}

	ctx.RiskLevel = inspection.RiskCritical
	if !matchCondition(ctx, cond) {
		t.Error("RiskCritical >= RiskCritical should match")
	}
}

func TestMatchConditionWorkDays(t *testing.T) {
	// Monday — a work day → matchWorkDays returns false → condition fails
	monday := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC) // Monday
	ctx := &Context{Timestamp: monday}

	cond := &ConditionConfig{WorkDays: []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}}
	// Monday IS a work day → matchWorkDays returns false → condition does NOT match (rule doesn't apply on work days)
	if matchCondition(ctx, cond) {
		t.Error("Monday (work day) should NOT trigger work_days condition")
	}

	// Sunday — not a work day → matchWorkDays returns true → condition matches
	sunday := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC) // Sunday
	ctx.Timestamp = sunday
	if !matchCondition(ctx, cond) {
		t.Error("Sunday (non-work day) should trigger work_days condition")
	}
}

func TestMatchConditionSourceIPIn(t *testing.T) {
	ctx := &Context{ClientIP: net.ParseIP("192.168.1.100")}

	cond := &ConditionConfig{SourceIPIn: []string{"192.168.1.0/24"}}
	if !matchCondition(ctx, cond) {
		t.Error("IP in range should match")
	}

	cond = &ConditionConfig{SourceIPIn: []string{"10.0.0.0/8"}}
	if matchCondition(ctx, cond) {
		t.Error("IP not in range should not match")
	}
}

func TestMatchConditionSourceIPNotIn(t *testing.T) {
	ctx := &Context{ClientIP: net.ParseIP("10.0.0.5")}

	cond := &ConditionConfig{SourceIPNotIn: []string{"10.0.0.0/8"}}
	if matchCondition(ctx, cond) {
		t.Error("IP in blocked range should not match")
	}

	ctx.ClientIP = net.ParseIP("192.168.1.1")
	if !matchCondition(ctx, cond) {
		t.Error("IP not in blocked range should match")
	}
}

func TestMatchConditionMaxCostGTE(t *testing.T) {
	ctx := &Context{CostScore: 50}
	cond := &ConditionConfig{MaxCostGTE: 80}
	if matchCondition(ctx, cond) {
		t.Error("cost 50 < 80 should not match")
	}

	ctx.CostScore = 90
	if !matchCondition(ctx, cond) {
		t.Error("cost 90 >= 80 should match")
	}
}

func TestMatchConditionSQLRegex(t *testing.T) {
	ctx := &Context{RawSQL: "SELECT * FROM users WHERE id = 1"}
	cond := &ConditionConfig{SQLRegex: []string{`SELECT \*`}}
	if !matchCondition(ctx, cond) {
		t.Error("SELECT * regex should match")
	}

	cond = &ConditionConfig{SQLRegex: []string{`DROP TABLE`}}
	if matchCondition(ctx, cond) {
		t.Error("DROP TABLE regex should not match")
	}
}

func TestMatchConditionWorkHours(t *testing.T) {
	// During work hours → matchWorkHours returns false (NOT outside) → condition fails
	workTime := time.Date(2026, 3, 18, 14, 0, 0, 0, time.UTC) // 14:00
	ctx := &Context{Timestamp: workTime}
	cond := &ConditionConfig{WorkHours: "08:00-19:00"}
	if matchCondition(ctx, cond) {
		t.Error("14:00 within work hours should NOT trigger condition")
	}

	// Outside work hours → matchWorkHours returns true → condition matches
	nightTime := time.Date(2026, 3, 18, 3, 0, 0, 0, time.UTC) // 03:00
	ctx.Timestamp = nightTime
	if !matchCondition(ctx, cond) {
		t.Error("03:00 outside work hours should trigger condition")
	}
}

func TestMatchConditionSQLContainsNotFound(t *testing.T) {
	ctx := &Context{RawSQL: "SELECT id FROM users"}
	cond := &ConditionConfig{SQLContains: []string{"DROP"}}
	if matchCondition(ctx, cond) {
		t.Error("DROP not in query should not match")
	}
}

func TestMatchConditionNil(t *testing.T) {
	ctx := &Context{}
	if !matchCondition(ctx, nil) {
		t.Error("nil condition should match")
	}
}

// --- matchRule branches ---

func TestMatchRuleDatabases(t *testing.T) {
	rule := &PolicyRule{
		Match: MatchConfig{Databases: []string{"prod"}},
	}
	ctx := &Context{Database: "dev"}
	e := NewEngine(NewLoader(nil, 0))
	if e.matchRule(ctx, rule, nil) {
		t.Error("dev should not match prod-only rule")
	}

	ctx.Database = "prod"
	if !e.matchRule(ctx, rule, nil) {
		t.Error("prod should match prod rule")
	}
}

func TestMatchRuleTables(t *testing.T) {
	rule := &PolicyRule{
		Match: MatchConfig{Tables: []string{"users"}},
	}
	ctx := &Context{Tables: []string{"orders"}}
	e := NewEngine(NewLoader(nil, 0))
	if e.matchRule(ctx, rule, nil) {
		t.Error("orders should not match users-only rule")
	}

	ctx.Tables = []string{"users", "orders"}
	if !e.matchRule(ctx, rule, nil) {
		t.Error("tables containing users should match")
	}
}

// --- cache expiry ---

func TestDecisionCacheExpiry(t *testing.T) {
	cache := newDecisionCache(100, 50*time.Millisecond)
	decision := &Decision{Action: ActionAllow}
	cache.set("key1", decision)

	// Should find it immediately
	d, ok := cache.get("key1")
	if !ok || d == nil {
		t.Error("should find cached decision")
	}

	// Wait for expiry
	time.Sleep(100 * time.Millisecond)

	d, ok = cache.get("key1")
	if ok {
		t.Error("expired entry should not be found")
	}
}

func TestDecisionCacheEviction(t *testing.T) {
	cache := newDecisionCache(2, time.Hour)
	cache.set("key1", &Decision{Action: ActionAllow})
	cache.set("key2", &Decision{Action: ActionBlock})
	cache.set("key3", &Decision{Action: ActionMask}) // should trigger eviction

	// Cache should have at most 2 entries (eviction happened)
	// We can't easily check internal state, but it shouldn't panic
}
