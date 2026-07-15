package inspection

import (
	"testing"
	"unicode"
)

// FuzzTokenizer tests that the SQL tokenizer never panics on arbitrary input.
// The tokenizer is the first line of defense against malicious SQL — a crash
// here would take down the entire proxy.  No property assertions: Go's fuzz
// engine treats any panic as a failure, which is the correct oracle.
//
// Run:
//
//	go test -fuzz FuzzTokenizer -fuzztime=60s ./internal/inspection/
func FuzzTokenizer(f *testing.F) {
	seeds := []string{
		"SELECT * FROM users",
		"SELECT id, name FROM users WHERE id = 1",
		"INSERT INTO logs (msg) VALUES ('hello')",
		"UPDATE accounts SET balance = 0 WHERE id = 1",
		"DELETE FROM sessions WHERE expired = true",
		"DROP TABLE users; SELECT 1",
		"SELECT /* comment */ 1",
		"SELECT -- line comment\n1",
		"' OR '1'='1",
		"1; DROP TABLE users",
		"SELECT SLEEP(5)",
		"WAITFOR DELAY '0:0:5'",
		"",
		"   ",
		"\x00\x01\x02",
		"SELECT * FROM `users` WHERE name = \"john\"",
		"SELECT * FROM [users] WHERE name = 'john'",
		"SELECT $$tag$$raw$$tag$$",
		// Edge cases found during fuzzing
		"$\"",
		"'",
		"$$",
		"\v",
		"\u00a0",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, sql string) {
		// Determine if input has non-whitespace content (matching the
		// tokenizer's own skipWhitespace which uses unicode.IsSpace).
		hasContent := false
		for _, r := range sql {
			if !unicode.IsSpace(r) {
				hasContent = true
				break
			}
		}

		// Must never panic.  Tokenize and (if there was content) check
		// that at least one non-EOF token was produced.
		tok := NewTokenizer(sql)
		tokens := tok.Tokenize()

		if hasContent && len(tokens) == 0 {
			t.Errorf("empty tokens from input with content %q", sql)
		}

		// All token values must be non-empty (zero-length tokens signal a
		// parser edge case that will confuse downstream consumers).
		for _, tok := range tokens {
			if tok.Type != TokenEOF && len(tok.Value) == 0 {
				t.Errorf("zero-length token (type %d) for input %q", tok.Type, sql)
			}
		}
	})
}
