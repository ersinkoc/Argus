package policy

import "testing"

func TestMatchSQLRegex(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		patterns []string
		want     bool
	}{
		{"simple match", "SELECT * FROM users", []string{`SELECT.*FROM users`}, true},
		{"no match", "INSERT INTO logs VALUES (1)", []string{`SELECT.*FROM users`}, false},
		{"multiple patterns", "DROP TABLE users", []string{`INSERT`, `DROP\s+TABLE`}, true},
		{"case sensitive", "select * from users", []string{`(?i)SELECT.*FROM`}, true},
		{"empty patterns", "SELECT 1", nil, false},
		{"invalid regex", "SELECT 1", []string{`[invalid`}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchSQLRegex(tt.sql, tt.patterns)
			if got != tt.want {
				t.Errorf("MatchSQLRegex(%q, %v) = %v, want %v", tt.sql, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestGetRegexCache(t *testing.T) {
	// First call compiles
	re1, err := GetRegex(`\bSELECT\b`)
	if err != nil {
		t.Fatal(err)
	}

	// Second call returns cached
	re2, err := GetRegex(`\bSELECT\b`)
	if err != nil {
		t.Fatal(err)
	}

	if re1 != re2 {
		t.Error("second call should return same compiled regex (cached)")
	}
}

func TestGetRegexInvalid(t *testing.T) {
	_, err := GetRegex(`[unclosed`)
	if err == nil {
		t.Error("should return error for invalid regex")
	}
}

func BenchmarkMatchSQLRegex(b *testing.B) {
	patterns := []string{`(?i)SELECT.*FROM\s+users`, `DROP\s+TABLE`, `TRUNCATE`}
	sql := "SELECT u.id, u.name FROM users u WHERE u.active = true"
	for b.Loop() {
		MatchSQLRegex(sql, patterns)
	}
}
