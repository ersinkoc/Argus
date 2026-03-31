package inspection

import (
	"testing"
	"time"
)

// --- anomaly.go: Record peak minute update (line 77-79) ---

func TestAnomalyRecordPeakMinuteUpdate(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)

	// Record queries in the first minute window
	ts1 := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		d.Record("user1", CommandSELECT, []string{"t"}, ts1)
	}

	// Verify recentMinute is 20
	d.mu.RLock()
	p := d.profiles["user1"]
	recent := p.recentMinute
	d.mu.RUnlock()
	if recent != 20 {
		t.Errorf("recentMinute = %d, want 20", recent)
	}

	// Now record in a new minute window (>1 minute later).
	// This should trigger the peak minute update (recentMinute > peakMinute).
	ts2 := ts1.Add(2 * time.Minute)
	d.Record("user1", CommandSELECT, []string{"t"}, ts2)

	d.mu.RLock()
	peak := d.profiles["user1"].peakMinute
	d.mu.RUnlock()
	if peak != 20 {
		t.Errorf("peakMinute = %d, want 20 (updated from previous minute)", peak)
	}
}

// --- anomaly.go: Check unusual_hour (lines 132-140) ---

func TestAnomalyCheckUnusualHour(t *testing.T) {
	d := NewAnomalyDetector(24 * time.Hour)

	// Record all 200 queries at hour 14 (2pm)
	ts := time.Date(2026, 3, 17, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 200; i++ {
		d.Record("user2", CommandSELECT, []string{"t"}, ts)
	}

	// Now check at hour 3 (3am) — never used before
	// hourCounts[3] = 0, avgPerHour = 200/24 ~= 8.3, 0 < 8.3*0.1 = 0.83 => true
	nightTime := time.Date(2026, 3, 17, 3, 0, 0, 0, time.UTC)
	alerts := d.Check("user2", CommandSELECT, []string{"t"}, nightTime)
	found := false
	for _, a := range alerts {
		if a.Type == "unusual_hour" {
			found = true
		}
	}
	if !found {
		t.Error("expected unusual_hour alert for query at 3am when all history is at 2pm")
	}
}

// --- classifier.go: WITH ... INSERT/UPDATE/DELETE CTE paths (lines 171-180) ---

func TestClassifyWithCTEInsert(t *testing.T) {
	// Use a CTE where the first keyword after WITH...AS(...) is INSERT, not SELECT
	cmd := Classify("WITH data(n) AS (VALUES (1)) INSERT INTO t SELECT * FROM data")
	// VALUES is not a keyword that triggers SELECT, so scanner should find INSERT
	if cmd.Type != CommandINSERT {
		t.Errorf("WITH...INSERT = %v, want INSERT", cmd.Type)
	}
}

func TestClassifyWithCTEUpdate(t *testing.T) {
	cmd := Classify("WITH data(n) AS (VALUES (1)) UPDATE t SET x = 1")
	if cmd.Type != CommandUPDATE {
		t.Errorf("WITH...UPDATE = %v, want UPDATE", cmd.Type)
	}
}

func TestClassifyWithCTEDelete(t *testing.T) {
	cmd := Classify("WITH data(n) AS (VALUES (1)) DELETE FROM t")
	if cmd.Type != CommandDELETE {
		t.Errorf("WITH...DELETE = %v, want DELETE", cmd.Type)
	}
}

// --- cost.go: tokens == nil retokenize (lines 28-31) ---

func TestEstimateCostNilTokens(t *testing.T) {
	// Create a Command with nil Tokens to force retokenization
	cmd := &Command{
		Raw:    "SELECT * FROM users JOIN orders ON users.id = orders.user_id",
		Type:   CommandSELECT,
		Tables: []string{"users", "orders"},
		Tokens: nil, // force retokenization path
	}
	est := EstimateCost(cmd)
	if !est.HasJoin {
		t.Error("should detect JOIN even with nil tokens (retokenized)")
	}
}

// --- cost.go: score > 100 cap (lines 123-125) ---

func TestEstimateCostScoreCap(t *testing.T) {
	// Build a maximally expensive query to exceed score 100:
	// multiple tables (30) + JOIN (15) + subquery (20) + ORDER BY (10) +
	// GROUP BY (15) + DISTINCT (10) + UNION (15) + no WHERE (20) = 135
	sql := "SELECT DISTINCT * FROM a JOIN b ON a.id = b.id JOIN c ON b.id = c.id " +
		"WHERE x IN (SELECT id FROM d) " +
		"GROUP BY a.name ORDER BY a.name " +
		"UNION SELECT * FROM e"
	cmd := Classify(sql)
	est := EstimateCost(cmd)
	if est.Score > 100 {
		t.Errorf("score = %d, should be capped at 100", est.Score)
	}
	// Verify it hits the cap: remove WHERE to add 20 more
	sql2 := "SELECT DISTINCT * FROM a JOIN b ON a.id = b.id JOIN c ON b.id = c.id JOIN d ON c.id = d.id " +
		"GROUP BY a.name ORDER BY a.name " +
		"UNION SELECT * FROM (SELECT id FROM e)"
	cmd2 := Classify(sql2)
	est2 := EstimateCost(cmd2)
	if est2.Score != 100 {
		t.Errorf("score = %d, want exactly 100 (capped)", est2.Score)
	}
}

// --- extractor.go: readTableNames idx >= len(tokens) (line 37-39) ---

func TestReadTableNamesEmptyAfterKeyword(t *testing.T) {
	// FROM at end of tokens with nothing after
	tokens := NewTokenizer("SELECT * FROM").Tokenize()
	tables := extractTables(tokens)
	// Should return empty (no table name after FROM)
	_ = tables // no panic is the test
}

// --- extractor.go: semicolon stop (line 64-65) ---

func TestReadTableNamesSemicolonStop(t *testing.T) {
	tokens := NewTokenizer("DELETE FROM users; DROP TABLE orders").Tokenize()
	cmd := Classify("DELETE FROM users; DROP TABLE orders")
	// First table should be "users", semicolon should stop reading tables for that clause
	foundUsers := false
	for _, tbl := range cmd.Tables {
		if tbl == "users" {
			foundUsers = true
		}
	}
	if !foundUsers {
		t.Errorf("tables = %v, should contain 'users'", cmd.Tables)
	}
	// "orders" might also be found due to the DROP TABLE clause
	_ = tokens
}

// --- extractor.go: extractInsertColumns nested parens (line 188-190) ---

func TestExtractInsertColumnsNestedParens(t *testing.T) {
	// INSERT with nested parentheses inside the column list.
	// When the parser encounters "(" inside the already-open column list paren,
	// it increments parenDepth (line 188-190).
	sql := `INSERT INTO t (a, (b)) VALUES (1, 2)`
	cmd := Classify(sql)
	// "a" should be extracted (at parenDepth==1), "b" is at parenDepth==2
	foundA := false
	for _, col := range cmd.Columns {
		if col == "a" {
			foundA = true
		}
	}
	if !foundA {
		t.Errorf("columns = %v, should contain 'a'", cmd.Columns)
	}
}

// --- tokenizer.go: backtick quoted identifier (line 117-119) ---

func TestTokenizerBacktickIdentifier(t *testing.T) {
	tokens := NewTokenizer("SELECT `my column` FROM `my table`").Tokenize()
	foundCol := false
	foundTbl := false
	for _, tok := range tokens {
		if tok.Type == TokenIdentifier && tok.Value == "my column" {
			foundCol = true
		}
		if tok.Type == TokenIdentifier && tok.Value == "my table" {
			foundTbl = true
		}
	}
	if !foundCol {
		t.Error("should parse backtick-quoted column identifier")
	}
	if !foundTbl {
		t.Error("should parse backtick-quoted table identifier")
	}
}

// --- tokenizer.go: unknown character fallthrough (lines 152-153) ---

func TestTokenizerUnknownCharacter(t *testing.T) {
	// Use a character that doesn't match any known token type.
	// The @ character is not a letter, digit, operator, quote, or punctuation.
	tokens := NewTokenizer("SELECT @var FROM t").Tokenize()
	// @var should produce a punctuation token for @ and an identifier for var
	foundAt := false
	for _, tok := range tokens {
		if tok.Value == "@" {
			foundAt = true
		}
	}
	if !foundAt {
		t.Error("should handle unknown character '@' as punctuation")
	}
}

// --- tokenizer.go: readDollarQuoted invalid tag character (lines 204-208) ---

func TestTokenizerDollarQuotedInvalidTag(t *testing.T) {
	// $ followed by an invalid tag character (e.g., a space or special char)
	// should treat $ as an operator, not start a dollar-quoted string.
	tokens := NewTokenizer("SELECT $  FROM t").Tokenize()
	foundOp := false
	for _, tok := range tokens {
		if tok.Type == TokenOperator && tok.Value == "$" {
			foundOp = true
		}
	}
	if !foundOp {
		t.Error("$ followed by space should be treated as operator")
	}
}

// --- extractor.go: schema.table as separate tokens (line 74-76) ---

func TestReadTableNamesSchemaQualifiedSeparateTokens(t *testing.T) {
	// When using quoted identifiers, the tokenizer produces separate tokens:
	// "schema" (identifier), . (operator), "table" (identifier)
	// This exercises the schema.table dot handling branch in readTableNames.
	sql := `SELECT * FROM "myschema"."mytable" WHERE 1=1`
	cmd := Classify(sql)
	// Should extract "myschema" as a table name (the first identifier)
	if len(cmd.Tables) == 0 {
		t.Error("should extract table from schema-qualified quoted identifiers")
	}
}

func TestTokenizerDollarQuotedInvalidTagChar(t *testing.T) {
	// $ followed by a character that's not valid in a tag (not letter/digit/_)
	// The specific branch: the loop finds a character that's not alphanumeric/underscore
	// before finding the closing $
	tokens := NewTokenizer("SELECT $tag+notag$ FROM t").Tokenize()
	foundOp := false
	for _, tok := range tokens {
		if tok.Type == TokenOperator && tok.Value == "$" {
			foundOp = true
			break
		}
	}
	if !foundOp {
		t.Error("$tag+ should treat $ as operator due to invalid tag char '+'")
	}
}
