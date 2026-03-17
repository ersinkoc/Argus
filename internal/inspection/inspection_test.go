package inspection

import (
	"testing"
)

func TestTokenizer(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantLen  int
		wantFirst TokenType
	}{
		{"simple select", "SELECT * FROM users", 4, TokenKeyword},
		{"quoted identifier", `SELECT "user_name" FROM users`, 4, TokenKeyword},
		{"string literal", "SELECT * FROM users WHERE name = 'John'", 8, TokenKeyword},
		{"line comment", "SELECT * FROM users -- this is a comment", 5, TokenKeyword},
		{"block comment", "SELECT /* comment */ * FROM users", 5, TokenKeyword},
		{"multi-statement", "SELECT 1; SELECT 2", 5, TokenKeyword},
		{"number", "SELECT 42", 2, TokenKeyword},
		{"empty", "", 0, TokenEOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenizer := NewTokenizer(tt.sql)
			tokens := tokenizer.Tokenize()
			if len(tokens) != tt.wantLen {
				t.Errorf("got %d tokens, want %d. Tokens: %v", len(tokens), tt.wantLen, tokens)
			}
			if tt.wantLen > 0 && tokens[0].Type != tt.wantFirst {
				t.Errorf("first token type = %v, want %v", tokens[0].Type, tt.wantFirst)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantType CommandType
		wantRisk RiskLevel
	}{
		{"select", "SELECT * FROM users", CommandSELECT, RiskNone},
		{"insert", "INSERT INTO users (name) VALUES ('John')", CommandINSERT, RiskLow},
		{"update with where", "UPDATE users SET name = 'Jane' WHERE id = 1", CommandUPDATE, RiskLow},
		{"update without where", "UPDATE users SET name = 'Jane'", CommandUPDATE, RiskMedium},
		{"delete with where", "DELETE FROM users WHERE id = 1", CommandDELETE, RiskLow},
		{"delete without where", "DELETE FROM users", CommandDELETE, RiskMedium},
		{"drop table", "DROP TABLE users", CommandDDL, RiskHigh},
		{"truncate", "TRUNCATE TABLE users", CommandDDL, RiskHigh},
		{"create table", "CREATE TABLE users (id INT)", CommandDDL, RiskMedium},
		{"grant", "GRANT SELECT ON users TO reader", CommandDCL, RiskHigh},
		{"begin", "BEGIN", CommandTCL, RiskNone},
		{"commit", "COMMIT", CommandTCL, RiskNone},
		{"explain", "EXPLAIN SELECT * FROM users", CommandADMIN, RiskNone},
		{"multi-statement", "SELECT 1; DROP TABLE users", CommandSELECT, RiskCritical},
		{"cte select", "WITH cte AS (SELECT 1) SELECT * FROM cte", CommandSELECT, RiskNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Classify(tt.sql)
			if cmd.Type != tt.wantType {
				t.Errorf("type = %v, want %v", cmd.Type, tt.wantType)
			}
			if cmd.RiskLevel != tt.wantRisk {
				t.Errorf("risk = %v, want %v", cmd.RiskLevel, tt.wantRisk)
			}
		})
	}
}

func TestExtractTables(t *testing.T) {
	tests := []struct {
		sql        string
		wantTables []string
	}{
		{"SELECT * FROM users", []string{"users"}},
		{"SELECT * FROM users u JOIN orders o ON u.id = o.user_id", []string{"users", "orders"}},
		{"INSERT INTO logs (msg) VALUES ('test')", []string{"logs"}},
		{"UPDATE accounts SET balance = 0 WHERE id = 1", []string{"accounts"}},
		{"DELETE FROM sessions WHERE expired = true", []string{"sessions"}},
	}

	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			cmd := Classify(tt.sql)
			if len(cmd.Tables) != len(tt.wantTables) {
				t.Errorf("tables = %v, want %v", cmd.Tables, tt.wantTables)
				return
			}
			for i, want := range tt.wantTables {
				if cmd.Tables[i] != want {
					t.Errorf("table[%d] = %q, want %q", i, cmd.Tables[i], want)
				}
			}
		})
	}
}

func TestDangerousPatterns(t *testing.T) {
	tests := []struct {
		sql         string
		wantWarning bool
	}{
		{"SELECT /* DROP TABLE users */ * FROM t", true},
		{"SELECT * FROM users -- normal comment", false},
		{"SELECT 1; DROP TABLE users", true},
	}

	for _, tt := range tests {
		t.Run(tt.sql, func(t *testing.T) {
			cmd := Classify(tt.sql)
			hasWarning := len(cmd.Warnings) > 0
			if hasWarning != tt.wantWarning {
				t.Errorf("warnings = %v, wantWarning = %v", cmd.Warnings, tt.wantWarning)
			}
		})
	}
}
