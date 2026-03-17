package policy

import "testing"

func TestValidatePolicySet(t *testing.T) {
	t.Run("valid policy set", func(t *testing.T) {
		ps := &PolicySet{
			Roles: map[string]Role{"dba": {Users: []string{"admin"}}},
			Policies: []PolicyRule{
				{Name: "rule1", Match: MatchConfig{Roles: []string{"dba"}}, Action: "allow"},
				{Name: "rule2", Match: MatchConfig{Commands: []string{"SELECT"}}, Action: "allow"},
			},
		}
		issues := ValidatePolicySet(ps)
		errors := countLevel(issues, "error")
		if errors > 0 {
			t.Errorf("expected no errors, got %d: %v", errors, issues)
		}
	})

	t.Run("duplicate names", func(t *testing.T) {
		ps := &PolicySet{
			Roles: map[string]Role{},
			Policies: []PolicyRule{
				{Name: "rule1", Match: MatchConfig{Commands: []string{"SELECT"}}, Action: "allow"},
				{Name: "rule1", Match: MatchConfig{Commands: []string{"DDL"}}, Action: "block"},
			},
		}
		issues := ValidatePolicySet(ps)
		if countLevel(issues, "error") < 1 {
			t.Errorf("expected at least 1 duplicate name error, got %v", issues)
		}
	})

	t.Run("shadowed rules", func(t *testing.T) {
		ps := &PolicySet{
			Policies: []PolicyRule{
				{Name: "catch-all", Match: MatchConfig{}, Action: "allow"},
				{Name: "specific", Match: MatchConfig{Roles: []string{"dba"}}, Action: "block"},
			},
		}
		issues := ValidatePolicySet(ps)
		if countLevel(issues, "warning") == 0 {
			t.Error("expected shadow warning for catch-all before specific rule")
		}
	})

	t.Run("undefined role", func(t *testing.T) {
		ps := &PolicySet{
			Roles: map[string]Role{},
			Policies: []PolicyRule{
				{Name: "rule1", Match: MatchConfig{Roles: []string{"nonexistent"}}, Action: "allow"},
			},
		}
		issues := ValidatePolicySet(ps)
		if countLevel(issues, "warning") == 0 {
			t.Error("expected warning for undefined role")
		}
	})

	t.Run("negated undefined role", func(t *testing.T) {
		ps := &PolicySet{
			Roles: map[string]Role{},
			Policies: []PolicyRule{
				{Name: "rule1", Match: MatchConfig{Roles: []string{"!admin"}}, Action: "block"},
			},
		}
		issues := ValidatePolicySet(ps)
		found := false
		for _, issue := range issues {
			if issue.Message == `role "admin" is referenced but not defined` {
				found = true
			}
		}
		if !found {
			t.Error("expected warning for negated undefined role")
		}
	})

	t.Run("empty masking column", func(t *testing.T) {
		ps := &PolicySet{
			Policies: []PolicyRule{
				{Name: "rule1", Masking: []MaskingRule{{Column: "", Transformer: "redact"}}},
			},
		}
		issues := ValidatePolicySet(ps)
		if countLevel(issues, "error") == 0 {
			t.Error("expected error for empty masking column")
		}
	})

	t.Run("block-all danger", func(t *testing.T) {
		ps := &PolicySet{
			Policies: []PolicyRule{
				{Name: "danger", Match: MatchConfig{}, Action: "block"},
			},
		}
		issues := ValidatePolicySet(ps)
		if countLevel(issues, "error") == 0 {
			t.Error("expected error for unconditional block-all rule")
		}
	})

	t.Run("nil policy set", func(t *testing.T) {
		issues := ValidatePolicySet(nil)
		if len(issues) != 1 {
			t.Errorf("nil policy should produce 1 error, got %d", len(issues))
		}
	})

	t.Run("unnamed rule", func(t *testing.T) {
		ps := &PolicySet{
			Policies: []PolicyRule{{Action: "allow"}},
		}
		issues := ValidatePolicySet(ps)
		if countLevel(issues, "warning") == 0 {
			t.Error("expected warning for unnamed rule")
		}
	})
}

func countLevel(issues []ValidationIssue, level string) int {
	n := 0
	for _, i := range issues {
		if i.Level == level {
			n++
		}
	}
	return n
}
