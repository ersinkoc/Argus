package classify

import "testing"

func TestClassifyColumnPII(t *testing.T) {
	e := NewEngine()

	tests := []struct {
		column string
		level  SensitivityLevel
		cat    string
	}{
		{"email", Confidential, "pii"},
		{"user_email", Confidential, "pii"},
		{"phone_number", Confidential, "pii"},
		{"salary", Restricted, "financial"},
		{"tc_kimlik_no", Restricted, "pii"},
		{"credit_card_number", Restricted, "pii"},
		{"iban", Restricted, "pii"},
		{"password_hash", Critical, "credential"},
		{"api_key", Critical, "credential"},
		{"date_of_birth", Confidential, "pii"},
		{"home_address", Confidential, "pii"},
		{"id", Public, "general"},
		{"created_at", Public, "general"},
		{"status", Public, "general"},
	}

	for _, tt := range tests {
		t.Run(tt.column, func(t *testing.T) {
			c := e.ClassifyColumn(tt.column)
			if c.Level != tt.level {
				t.Errorf("%s: level = %s, want %s", tt.column, c.LevelName, tt.level.String())
			}
			if c.Category != tt.cat {
				t.Errorf("%s: category = %s, want %s", tt.column, c.Category, tt.cat)
			}
		})
	}
}

func TestClassifyColumns(t *testing.T) {
	e := NewEngine()
	results := e.ClassifyColumns([]string{"id", "email", "salary", "name"})
	if len(results) != 4 {
		t.Fatalf("results = %d", len(results))
	}
	if results[1].Level != Confidential {
		t.Error("email should be confidential")
	}
	if results[2].Level != Restricted {
		t.Error("salary should be restricted")
	}
}

func TestClassifyTable(t *testing.T) {
	e := NewEngine()
	results := e.ClassifyTable("users", []string{"id", "email", "password"})
	for _, r := range results {
		if r.TableName != "users" {
			t.Errorf("table = %q, want users", r.TableName)
		}
	}
}

func TestSensitiveCols(t *testing.T) {
	e := NewEngine()
	cols := []string{"id", "name", "email", "salary", "password", "created_at"}
	sensitive := e.SensitiveCols(cols, Confidential)

	if len(sensitive) < 3 {
		t.Errorf("sensitive = %d, want >= 3 (email, salary, password)", len(sensitive))
	}
}

func TestSummary(t *testing.T) {
	e := NewEngine()
	cols := []string{"id", "email", "phone", "salary", "password", "status"}
	s := e.Summary(cols)

	if s.Total != 6 {
		t.Errorf("total = %d", s.Total)
	}
	if s.Sensitive < 3 {
		t.Errorf("sensitive = %d, want >= 3", s.Sensitive)
	}
	if s.NeedsMasking < 3 {
		t.Errorf("needs masking = %d, want >= 3", s.NeedsMasking)
	}
}

func TestAddCustomRule(t *testing.T) {
	e := NewEngine()

	err := e.AddRule(`(?i)custom_field`, "business", Restricted, "redact", 0.99)
	if err != nil {
		t.Fatal(err)
	}

	c := e.ClassifyColumn("custom_field")
	if c.Level != Restricted {
		t.Errorf("custom rule: level = %s", c.LevelName)
	}
	if c.Category != "business" {
		t.Errorf("category = %s", c.Category)
	}
}

func TestAddCustomRuleInvalidRegex(t *testing.T) {
	e := NewEngine()
	err := e.AddRule("[invalid", "x", Public, "", 0)
	if err == nil {
		t.Error("invalid regex should fail")
	}
}

func TestParseLevel(t *testing.T) {
	if ParseLevel("restricted") != Restricted {
		t.Error("should parse restricted")
	}
	if ParseLevel("CRITICAL") != Critical {
		t.Error("should parse CRITICAL (case insensitive)")
	}
	if ParseLevel("unknown") != Public {
		t.Error("unknown should default to public")
	}
}

func TestSensitivityLevelString(t *testing.T) {
	if Critical.String() != "critical" {
		t.Error("critical")
	}
	if SensitivityLevel(99).String() != "unknown" {
		t.Error("99 should be unknown")
	}
}
