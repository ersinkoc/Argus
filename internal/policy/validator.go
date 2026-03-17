package policy

import "fmt"

// ValidationIssue represents a problem found during policy validation.
type ValidationIssue struct {
	Level   string `json:"level"`   // "error", "warning", "info"
	Rule    string `json:"rule"`    // policy rule name
	Message string `json:"message"`
}

// ValidatePolicySet checks a policy set for common issues.
func ValidatePolicySet(ps *PolicySet) []ValidationIssue {
	var issues []ValidationIssue

	if ps == nil {
		return []ValidationIssue{{Level: "error", Message: "policy set is nil"}}
	}

	// Check for duplicate rule names
	names := make(map[string]int)
	for i, rule := range ps.Policies {
		if rule.Name == "" {
			issues = append(issues, ValidationIssue{
				Level:   "warning",
				Rule:    fmt.Sprintf("policy[%d]", i),
				Message: "policy rule has no name",
			})
			continue
		}
		if prev, ok := names[rule.Name]; ok {
			issues = append(issues, ValidationIssue{
				Level:   "error",
				Rule:    rule.Name,
				Message: fmt.Sprintf("duplicate rule name (first at index %d, duplicate at %d)", prev, i),
			})
		}
		names[rule.Name] = i
	}

	// Check for shadowed rules (unreachable rules)
	for i, rule := range ps.Policies {
		if isWildcardMatch(rule.Match) && i < len(ps.Policies)-1 {
			issues = append(issues, ValidationIssue{
				Level:   "warning",
				Rule:    rule.Name,
				Message: fmt.Sprintf("catch-all rule at index %d shadows %d rule(s) after it", i, len(ps.Policies)-i-1),
			})
		}
	}

	// Check for roles referenced in rules but not defined
	for _, rule := range ps.Policies {
		for _, roleName := range rule.Match.Roles {
			cleanName := roleName
			if len(cleanName) > 0 && cleanName[0] == '!' {
				cleanName = cleanName[1:]
			}
			if _, ok := ps.Roles[cleanName]; !ok {
				issues = append(issues, ValidationIssue{
					Level:   "warning",
					Rule:    rule.Name,
					Message: fmt.Sprintf("role %q is referenced but not defined", cleanName),
				})
			}
		}
	}

	// Check masking rules reference valid transformers
	validTransformers := map[string]bool{
		"redact": true, "partial_email": true, "partial_phone": true,
		"partial_card": true, "partial_iban": true, "partial_tc": true,
		"hash": true, "null": true,
	}
	for _, rule := range ps.Policies {
		for _, mr := range rule.Masking {
			if mr.Column == "" {
				issues = append(issues, ValidationIssue{
					Level:   "error",
					Rule:    rule.Name,
					Message: "masking rule has empty column name",
				})
			}
			if !validTransformers[mr.Transformer] && mr.Transformer != "" {
				issues = append(issues, ValidationIssue{
					Level:   "warning",
					Rule:    rule.Name,
					Message: fmt.Sprintf("unknown transformer %q (may be custom)", mr.Transformer),
				})
			}
		}
	}

	// Check for rules with action but no match criteria (too broad)
	for _, rule := range ps.Policies {
		if rule.Action == "block" && isWildcardMatch(rule.Match) && rule.Condition == nil {
			issues = append(issues, ValidationIssue{
				Level:   "error",
				Rule:    rule.Name,
				Message: "block action with no match criteria or conditions will block ALL queries",
			})
		}
	}

	return issues
}

func isWildcardMatch(m MatchConfig) bool {
	return len(m.Roles) == 0 && len(m.Commands) == 0 &&
		len(m.Databases) == 0 && len(m.Tables) == 0
}
