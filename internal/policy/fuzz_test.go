package policy

import (
	"strings"
	"testing"
)

// FuzzSQLInjectionDetector tests that the SQL injection detection functions
// never panic on arbitrary input and produce deterministic results.
// The detector processes attacker-controlled SQL — a crash here would be a
// denial-of-service vector, and non-deterministic behavior could lead to
// policy bypasses.
//
// Run:
//
//	go test -fuzz FuzzSQLInjectionDetector -fuzztime=30s ./internal/policy/
//	go test -fuzz FuzzNormalizeSQL -fuzztime=30s ./internal/policy/
func FuzzSQLInjectionDetector(f *testing.F) {
	// Seed corpus: SQL injection payloads + normal SQL
	seeds := []string{
		"SELECT * FROM users WHERE id = 1",
		"SELECT * FROM users WHERE id = 1 OR 1=1",
		"SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
		"SELECT * FROM users; DROP TABLE users; --",
		"1 UNION SELECT * FROM users",
		"' OR SLEEP(5) --",
		"admin'--",
		"xp_cmdshell 'dir'",
		"SELECT * FROM information_schema.tables",
		"LOAD_FILE('/etc/passwd')",
		"",
		"   ",
		"\x00\x01\x02\xFF",
		strings.Repeat("A", 10000),
		"' OR '1'='1' /* comment */ --",
		"SELECT BENCHMARK(1000000, MD5('test'))",
		"admin' UNION SELECT @@version,user(),database() --",
		"1 AND 1=1",
		"1 AND 1=2",
		"CHAR(65,66,67)",
		"WAITFOR DELAY '0:0:10'",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, sql string) {
		// Must never panic
		result := detectSQLInjection(sql)
		// Result must be deterministic for the same input
		result2 := detectSQLInjection(sql)
		if result != result2 {
			t.Errorf("non-deterministic result for %q: first=%v second=%v", sql, result, result2)
		}
		// Must not panic on the uppercase variant either
		_ = detectSQLInjectionUpper(sql)
	})
}

// FuzzNormalizeSQL tests that normalizeSQL never panics on arbitrary input.
// normalizeSQL is the preprocessing step that strips comments and string
// literals before injection pattern matching — a crash here would bypass
// all injection detection for that query.
func FuzzNormalizeSQL(f *testing.F) {
	seeds := []string{
		"SELECT * FROM users",
		"' OR '1'='1",
		"SELECT /* nested /* comment */ test */ 1",
		"SELECT 'string' FROM t WHERE 'a' = 'b'",
		"-- line comment\nSELECT 1",
		"",
		strings.Repeat("A", 10000),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		// Must never panic
		_ = normalizeSQL(s)
		// Must be deterministic (same input always produces same output)
		a := normalizeSQL(s)
		b := normalizeSQL(s)
		if a != b {
			t.Errorf("non-deterministic normalizeSQL for %q", s)
		}
	})
}
