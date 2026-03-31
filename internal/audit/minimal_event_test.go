package audit

import "testing"

func TestIsMinimalEvent(t *testing.T) {
	// Events that should pass at minimal level
	minimal := []string{
		"connection_open", "connection_close",
		"auth_success", "auth_failure",
		"command_blocked", "session_timeout",
		"session_killed", "policy_reloaded",
		"gateway_query", "approval_created",
		"approval_resolved", "allowlist_added",
		"allowlist_used",
	}
	for _, evt := range minimal {
		if !isMinimalEvent(evt) {
			t.Errorf("isMinimalEvent(%q) = false, want true", evt)
		}
	}

	// Events that should be filtered at minimal level
	filtered := []string{
		"command_executed", "result_masked",
		"result_truncated", "policy_violation",
		"unknown_event",
	}
	for _, evt := range filtered {
		if isMinimalEvent(evt) {
			t.Errorf("isMinimalEvent(%q) = true, want false", evt)
		}
	}
}
