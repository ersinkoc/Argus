package policy

import "testing"

func TestDryRun(t *testing.T) {
	ps := &PolicySet{
		Version:  "1",
		Defaults: DefaultsConfig{Action: "allow", LogLevel: "standard"},
		Roles: map[string]Role{
			"dba":     {Users: []string{"admin"}},
			"support": {Users: []string{"support_*"}},
		},
		Policies: []PolicyRule{
			{
				Name:  "block-ddl",
				Match: MatchConfig{Roles: []string{"!dba"}, Commands: []string{"DDL"}},
				Condition: &ConditionConfig{SQLContains: []string{"DROP"}},
				Action: "block",
				Reason: "DBA only",
			},
			{
				Name:  "mask-support",
				Match: MatchConfig{Roles: []string{"support"}, Commands: []string{"SELECT"}},
				Masking: []MaskingRule{{Column: "email", Transformer: "partial_email"}},
			},
			{
				Name:   "allow-all",
				Match:  MatchConfig{},
				Action: "allow",
			},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	t.Run("block DDL for non-DBA", func(t *testing.T) {
		result := engine.DryRun(DryRunInput{
			Username: "dev_john",
			SQL:      "DROP TABLE users",
		})
		if result.Decision.Action != "block" {
			t.Errorf("action = %q, want block", result.Decision.Action)
		}
		if result.Decision.PolicyName != "block-ddl" {
			t.Errorf("policy = %q, want block-ddl", result.Decision.PolicyName)
		}
	})

	t.Run("allow DDL for DBA", func(t *testing.T) {
		result := engine.DryRun(DryRunInput{
			Username: "admin",
			SQL:      "DROP TABLE users",
		})
		if result.Decision.Action == "block" {
			t.Error("DBA should not be blocked")
		}
	})

	t.Run("mask for support", func(t *testing.T) {
		result := engine.DryRun(DryRunInput{
			Username: "support_jane",
			SQL:      "SELECT * FROM users",
		})
		if result.Decision.Action != "mask" {
			t.Errorf("action = %q, want mask", result.Decision.Action)
		}
		if len(result.Decision.MaskingRules) == 0 {
			t.Error("should have masking rules")
		}
	})

	t.Run("simple select", func(t *testing.T) {
		result := engine.DryRun(DryRunInput{
			Username: "dev_john",
			SQL:      "SELECT * FROM orders",
		})
		if result.Decision.Action != "allow" {
			t.Errorf("action = %q, want allow", result.Decision.Action)
		}
		if result.Duration == "" {
			t.Error("duration should not be empty")
		}
	})

	t.Run("with command type override", func(t *testing.T) {
		engine.InvalidateCache() // clear cache from previous tests
		result := engine.DryRun(DryRunInput{
			Username:    "dev_john",
			CommandType: "DDL",
			SQL:         "CREATE TABLE test (id INT)", // DDL without DROP
			Tables:      []string{"test"},
		})
		// block-ddl requires sql_contains: ["DROP"] — CREATE doesn't contain DROP
		if result.Decision.Action == "block" {
			t.Errorf("CREATE TABLE should not be blocked by block-ddl policy, got action=%s policy=%s",
				result.Decision.Action, result.Decision.PolicyName)
		}
	})
}

func TestDryRunJSON(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{{Name: "allow-all", Match: MatchConfig{}, Action: "allow"}},
	}
	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	data, err := engine.DryRunJSON(DryRunInput{Username: "test", SQL: "SELECT 1"})
	if err != nil {
		t.Fatalf("DryRunJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON output should not be empty")
	}
}
