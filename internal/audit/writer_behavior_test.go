package audit

import "testing"

func TestSanitizeSQLEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{"empty", "", ""},
		{"no literals", "SELECT * FROM users", "SELECT * FROM users"},
		{"table with number", "SELECT col1 FROM t2", "SELECT col1 FROM t2"},
		{"standalone number", "WHERE x = 42", "WHERE x = $1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeSQL(tt.sql)
			if got != tt.want {
				t.Errorf("SanitizeSQL(%q) = %q, want %q", tt.sql, got, tt.want)
			}
		})
	}
}

func TestSlowQueryLoggerNilLogger(t *testing.T) {
	slow := NewSlowQueryLogger(0, nil) // 0 threshold = everything is slow
	event := Event{SessionID: "s1", Command: "SELECT 1"}
	// Should not panic with nil logger
	result := slow.Check(event, 100)
	if !result {
		t.Error("0 threshold should flag everything as slow")
	}
}

func TestLoggerNewWithDefaults(t *testing.T) {
	// Test with 0/negative values — should use defaults
	logger := NewLogger(0, LevelStandard, 0)
	if cap(logger.eventCh) != 10000 {
		t.Errorf("buffer = %d, want 10000", cap(logger.eventCh))
	}
	if logger.sqlMaxLen != 4096 {
		t.Errorf("sqlMaxLen = %d, want 4096", logger.sqlMaxLen)
	}
}

func TestTruncateFunc(t *testing.T) {
	if truncate("short", 100) != "short" {
		t.Error("short string should not be truncated")
	}
	result := truncate("this is a very long string", 10)
	if len(result) != 13 { // 10 + "..."
		t.Errorf("truncated length = %d", len(result))
	}
}
