package inspection

import "testing"

func TestRiskLevelString(t *testing.T) {
	tests := []struct {
		r    RiskLevel
		want string
	}{
		{RiskNone, "none"}, {RiskLow, "low"}, {RiskMedium, "medium"},
		{RiskHigh, "high"}, {RiskCritical, "critical"}, {RiskLevel(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestParseRiskLevel(t *testing.T) {
	if ParseRiskLevel("high") != RiskHigh {
		t.Error("should parse high")
	}
	if ParseRiskLevel("unknown_value") != RiskNone {
		t.Error("unknown should default to none")
	}
}

func TestCommandTypeString(t *testing.T) {
	if CommandSELECT.String() != "SELECT" {
		t.Error("SELECT")
	}
	if CommandType(99).String() != "UNKNOWN" {
		t.Error("unknown should be UNKNOWN")
	}
}

func TestTokenizerDollarQuoted(t *testing.T) {
	tokens := NewTokenizer("SELECT $$hello world$$").Tokenize()
	found := false
	for _, tok := range tokens {
		if tok.Type == TokenLiteral && tok.Value == "hello world" {
			found = true
		}
	}
	if !found {
		t.Error("should parse dollar-quoted string")
	}
}

func TestTokenizerBracketIdentifier(t *testing.T) {
	tokens := NewTokenizer("SELECT [Column Name] FROM t").Tokenize()
	found := false
	for _, tok := range tokens {
		if tok.Type == TokenIdentifier && tok.Value == "Column Name" {
			found = true
		}
	}
	if !found {
		t.Error("should parse bracket identifier")
	}
}

func TestTokenizerNestedBlockComment(t *testing.T) {
	tokens := NewTokenizer("SELECT /* outer /* inner */ still comment */ 1").Tokenize()
	// Should have SELECT, comment, 1
	if len(tokens) < 2 {
		t.Errorf("got %d tokens", len(tokens))
	}
}

func TestTokenizerTwoCharOperators(t *testing.T) {
	ops := []string{"<>", "!=", "<=", ">=", "::", "||"}
	for _, op := range ops {
		tokens := NewTokenizer("a " + op + " b").Tokenize()
		found := false
		for _, tok := range tokens {
			if tok.Type == TokenOperator && tok.Value == op {
				found = true
			}
		}
		if !found {
			t.Errorf("should parse operator %q", op)
		}
	}
}

func TestClassifyStartTransaction(t *testing.T) {
	cmd := Classify("START TRANSACTION")
	if cmd.Type != CommandTCL {
		t.Errorf("START should be TCL, got %v", cmd.Type)
	}
}

func TestClassifyWithRecursive(t *testing.T) {
	cmd := Classify("WITH RECURSIVE cte AS (SELECT 1) SELECT * FROM cte")
	if cmd.Type != CommandSELECT {
		t.Errorf("WITH RECURSIVE should be SELECT, got %v", cmd.Type)
	}
}

func TestInjectWhereAndNoExistingWhere(t *testing.T) {
	r := NewRewriter()
	r.SetForceWhere("deleted = false")
	cmd := Classify("DELETE FROM users")
	result, _ := r.Rewrite("DELETE FROM users", cmd)
	if result != "DELETE FROM users WHERE deleted = false" {
		t.Errorf("got %q", result)
	}
}

func TestSplitStatementsParenDepth(t *testing.T) {
	// Semicolons inside parens should not split
	stmts := SplitStatements("INSERT INTO t VALUES (1; 2)")
	if len(stmts) != 1 {
		t.Errorf("got %d statements, want 1 (semicolon in parens)", len(stmts))
	}
}

func TestAnomalyDetectorCustomWindow(t *testing.T) {
	d := NewAnomalyDetector(0) // 0 should default to 24h
	if d.window.Hours() != 24 {
		t.Errorf("default window = %v, want 24h", d.window)
	}
}
