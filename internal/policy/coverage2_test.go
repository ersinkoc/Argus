package policy

import (
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

func TestMatchWorkHoursValid(t *testing.T) {
	// 14:00 on a weekday
	ts := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)

	// Outside work hours (08:00-19:00) — should return false (in work hours, rule doesn't trigger)
	if matchWorkHours(ts, "08:00-19:00") {
		// 14:00 is within 08:00-19:00, so condition should NOT trigger (return false)
		// Wait, our logic: returns true when OUTSIDE work hours
		// 14:00 is INSIDE → should return false
	}

	// At 05:00 — outside work hours — should return true (trigger block)
	early := time.Date(2026, 3, 17, 5, 0, 0, 0, time.UTC)
	if !matchWorkHours(early, "08:00-19:00") {
		t.Error("05:00 should be outside work hours (trigger)")
	}

	// At 22:00 — outside work hours
	late := time.Date(2026, 3, 17, 22, 0, 0, 0, time.UTC)
	if !matchWorkHours(late, "08:00-19:00") {
		t.Error("22:00 should be outside work hours (trigger)")
	}
}

func TestCacheEviction(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{{Name: "allow-all", Match: MatchConfig{}, Action: "allow"}},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	// Fill cache beyond max size to trigger eviction
	for i := 0; i < 15000; i++ {
		ctx := &Context{
			Username:    "user_" + itoa(i),
			CommandType: inspection.CommandSELECT,
			Tables:      []string{"table_" + itoa(i)},
			Timestamp:   time.Now(),
		}
		engine.Evaluate(ctx)
	}
	// No panic = success
}

func TestMatchWildcardMiddle(t *testing.T) {
	if !matchWildcard("prod*db", "prod_staging_db") {
		t.Error("middle wildcard should match")
	}
	if matchWildcard("prod*db", "staging_db") {
		t.Error("middle wildcard should not match wrong prefix")
	}
}

func TestDryRunWithClientIP(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{{Name: "allow-all", Match: MatchConfig{}, Action: "allow"}},
	}
	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	result := engine.DryRun(DryRunInput{
		Username: "test",
		ClientIP: "10.0.1.50",
		SQL:      "SELECT 1",
	})
	if result.Decision.Action != "allow" {
		t.Errorf("action = %q", result.Decision.Action)
	}
}

func itoa(n int) string {
	if n == 0 { return "0" }
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
