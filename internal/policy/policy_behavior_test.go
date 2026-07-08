package policy

import (
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

func TestActionString(t *testing.T) {
	tests := []struct {
		a    Action
		want string
	}{
		{ActionAllow, "allow"}, {ActionBlock, "block"},
		{ActionMask, "mask"}, {ActionAudit, "audit"},
		{Action(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.a.String(); got != tt.want {
			t.Errorf("Action(%d).String() = %q, want %q", tt.a, got, tt.want)
		}
	}
}

func TestParseActionAll(t *testing.T) {
	if ParseAction("block") != ActionBlock {
		t.Error("should parse block")
	}
	if ParseAction("mask") != ActionMask {
		t.Error("should parse mask")
	}
	if ParseAction("audit") != ActionAudit {
		t.Error("should parse audit")
	}
	if ParseAction("unknown") != ActionAllow {
		t.Error("unknown should default to allow")
	}
}

func TestMatchWorkHoursEdgeCases(t *testing.T) {
	// Invalid format
	if !matchWorkHours(time.Now(), "invalid") {
		t.Error("invalid format should return true (no restriction)")
	}
	if !matchWorkHours(time.Now(), "08:00") {
		t.Error("single value should return true")
	}
}

func TestMatchWorkDaysInWorkDay(t *testing.T) {
	// Monday at 10:00
	monday := time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC) // Monday
	days := []string{"monday", "tuesday", "wednesday", "thursday", "friday"}

	// matchWorkDays returns true when OUTSIDE work days (to trigger block)
	if matchWorkDays(monday, days) {
		t.Error("Monday should be a work day, condition should NOT trigger")
	}

	// Sunday
	sunday := time.Date(2026, 3, 22, 10, 0, 0, 0, time.UTC) // Sunday
	if !matchWorkDays(sunday, days) {
		t.Error("Sunday should NOT be a work day, condition should trigger")
	}
}

func TestPolicyMaskingCumulative(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{"support": {Users: []string{"support_*"}}},
		Policies: []PolicyRule{
			{
				Name:    "mask-email",
				Match:   MatchConfig{Roles: []string{"support"}},
				Masking: []MaskingRule{{Column: "email", Transformer: "partial_email"}},
			},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "support_jane",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionMask {
		t.Errorf("action = %v, want mask", d.Action)
	}
	if len(d.MaskingRules) != 1 {
		t.Errorf("masking rules = %d, want 1", len(d.MaskingRules))
	}
}

func TestPolicyRegexCondition(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{
			{
				Name:      "block-schema-scan",
				Match:     MatchConfig{},
				Condition: &ConditionConfig{SQLRegex: []string{`(?i)information_schema`}},
				Action:    "block",
			},
			{Name: "allow-all", Match: MatchConfig{}, Action: "allow"},
		},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	// Matching regex
	ctx := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		RawSQL:      "SELECT * FROM information_schema.tables",
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionBlock {
		t.Errorf("should block information_schema access, got %v", d.Action)
	}

	// Non-matching
	engine.InvalidateCache()
	ctx.RawSQL = "SELECT * FROM users"
	d = engine.Evaluate(ctx)
	if d.Action != ActionAllow {
		t.Errorf("normal query should be allowed, got %v", d.Action)
	}
}

func TestLoaderSetCurrent(t *testing.T) {
	loader := NewLoader(nil, 0)
	ps := &PolicySet{Version: "test"}
	loader.SetCurrent(ps)

	got := loader.Current()
	if got.Version != "test" {
		t.Error("SetCurrent should work")
	}
}
