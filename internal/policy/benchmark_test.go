package policy

import (
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

func BenchmarkPolicyEvaluate(b *testing.B) {
	ps := &PolicySet{
		Version:  "1",
		Defaults: DefaultsConfig{Action: "allow", LogLevel: "minimal"},
		Roles: map[string]Role{
			"dba":       {Users: []string{"admin"}},
			"developer": {Users: []string{"dev_*"}},
			"support":   {Users: []string{"support_*"}},
		},
		Policies: []PolicyRule{
			{
				Name:  "block-ddl",
				Match: MatchConfig{Roles: []string{"!dba"}, Commands: []string{"DDL"}},
				Condition: &ConditionConfig{SQLContains: []string{"DROP"}},
				Action: "block",
			},
			{
				Name:  "mask-support",
				Match: MatchConfig{Roles: []string{"support"}, Commands: []string{"SELECT"}},
				Masking: []MaskingRule{{Column: "email", Transformer: "partial_email"}},
			},
			{
				Name:   "allow-read",
				Match:  MatchConfig{Commands: []string{"SELECT"}},
				Action: "allow",
			},
			{
				Name:   "allow-write",
				Match:  MatchConfig{Commands: []string{"INSERT", "UPDATE", "DELETE"}},
				Action: "allow",
			},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "dev_john",
		CommandType: inspection.CommandSELECT,
		RawSQL:      "SELECT * FROM users",
		Tables:      []string{"users"},
		Database:    "production",
		ClientIP:    net.ParseIP("10.0.1.50"),
		Timestamp:   time.Now(),
	}

	b.ResetTimer()
	for b.Loop() {
		engine.Evaluate(ctx)
	}
}

func BenchmarkPolicyEvaluateNoCache(b *testing.B) {
	ps := &PolicySet{
		Version:  "1",
		Defaults: DefaultsConfig{Action: "allow", LogLevel: "minimal"},
		Roles:    map[string]Role{"developer": {Users: []string{"dev_*"}}},
		Policies: []PolicyRule{
			{Name: "allow-all", Match: MatchConfig{}, Action: "allow"},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	b.ResetTimer()
	for b.Loop() {
		// Different username each time to bust cache
		ctx := &Context{
			Username:    "dev_john",
			CommandType: inspection.CommandSELECT,
			RawSQL:      "SELECT * FROM users",
			Tables:      []string{"users"},
			Timestamp:   time.Now(),
		}
		engine.InvalidateCache()
		engine.Evaluate(ctx)
	}
}

func BenchmarkWildcardMatch(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		matchWildcard("dev_*", "dev_john_smith")
	}
}

func BenchmarkRoleResolve(b *testing.B) {
	roles := map[string]Role{
		"dba":       {Users: []string{"admin", "postgres_admin"}},
		"developer": {Users: []string{"dev_*"}},
		"support":   {Users: []string{"support_*"}},
		"finance":   {Users: []string{"finance_*"}},
		"qa":        {Users: []string{"qa_*"}},
	}

	b.ResetTimer()
	for b.Loop() {
		ResolveUserRoles("dev_john", roles)
	}
}
