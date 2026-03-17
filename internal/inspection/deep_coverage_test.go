package inspection

import (
	"testing"
)

// --- readTableNames edge cases ---

func TestReadTableNamesWithASAlias(t *testing.T) {
	tokens := NewTokenizer("SELECT * FROM orders AS o WHERE o.id = 1").Tokenize()
	tables := extractTables(tokens)
	if len(tables) == 0 {
		t.Fatal("should extract table")
	}
	if tables[0] != "orders" {
		t.Errorf("table = %q, want 'orders'", tables[0])
	}
}

func TestReadTableNamesPlainAlias(t *testing.T) {
	tokens := NewTokenizer("SELECT * FROM users u WHERE u.id = 1").Tokenize()
	tables := extractTables(tokens)
	if len(tables) == 0 {
		t.Fatal("should extract table")
	}
	if tables[0] != "users" {
		t.Errorf("table = %q, want 'users'", tables[0])
	}
}

func TestReadTableNamesCommaSeparated(t *testing.T) {
	tokens := NewTokenizer("SELECT * FROM users, orders, products WHERE 1=1").Tokenize()
	tables := extractTables(tokens)
	if len(tables) != 3 {
		t.Errorf("tables = %v, want 3", tables)
	}
}

func TestReadTableNamesNestedSubquery(t *testing.T) {
	tokens := NewTokenizer("SELECT * FROM (SELECT * FROM (SELECT 1) AS inner_sq) AS outer_sq, items").Tokenize()
	tables := extractTables(tokens)
	found := false
	for _, tbl := range tables {
		if tbl == "items" {
			found = true
		}
	}
	if !found {
		t.Errorf("tables = %v, should contain 'items'", tables)
	}
}

// --- needsSpace / tokensToSQL edge cases ---

func TestNeedsSpaceDotOperator(t *testing.T) {
	tokens := NewTokenizer("SELECT t.id FROM schema_t.table_t t").Tokenize()
	sql := tokensToSQL(tokens)
	if sql == "" {
		t.Fatal("empty sql")
	}
}

func TestNeedsSpaceParens(t *testing.T) {
	tokens := NewTokenizer("SELECT COUNT(id) FROM users").Tokenize()
	sql := tokensToSQL(tokens)
	if sql == "" {
		t.Fatal("empty sql")
	}
}

func TestNeedsSpaceComma(t *testing.T) {
	tokens := NewTokenizer("SELECT a, b, c FROM t").Tokenize()
	sql := tokensToSQL(tokens)
	if sql == "" {
		t.Fatal("empty sql")
	}
}

func TestTokensToSQLNil(t *testing.T) {
	if tokensToSQL(nil) != "" {
		t.Error("nil tokens should return empty")
	}
}

func TestNeedsSpaceBeforeCloseParen(t *testing.T) {
	tokens := NewTokenizer("SELECT (1 + 2)").Tokenize()
	sql := tokensToSQL(tokens)
	if sql == "" {
		t.Fatal("empty sql")
	}
}

func TestNeedsSpaceSemicolon(t *testing.T) {
	tokens := NewTokenizer("SELECT 1; SELECT 2").Tokenize()
	sql := tokensToSQL(tokens)
	if sql == "" {
		t.Fatal("empty sql")
	}
}

// --- SplitStatements ---

func TestSplitStatementsWithDots(t *testing.T) {
	stmts := SplitStatements("SELECT s.t.col FROM s.t; SELECT 1")
	if len(stmts) != 2 {
		t.Errorf("stmts = %d, want 2", len(stmts))
	}
}

// --- Classify edge cases ---

func TestClassifyTruncateTable(t *testing.T) {
	cmd := Classify("TRUNCATE TABLE users")
	if cmd.Type != CommandDDL {
		t.Errorf("type = %v, want DDL", cmd.Type)
	}
}

func TestClassifyAlterTable(t *testing.T) {
	cmd := Classify("ALTER TABLE users ADD COLUMN age INT")
	if cmd.Type != CommandDDL {
		t.Errorf("type = %v, want DDL", cmd.Type)
	}
}

func TestClassifyGrant(t *testing.T) {
	cmd := Classify("GRANT SELECT ON users TO readonly")
	if cmd.Type != CommandDCL {
		t.Errorf("type = %v, want DCL", cmd.Type)
	}
}

func TestClassifyRevoke(t *testing.T) {
	cmd := Classify("REVOKE ALL ON users FROM baduser")
	if cmd.Type != CommandDCL {
		t.Errorf("type = %v, want DCL", cmd.Type)
	}
}

func TestClassifyTCL(t *testing.T) {
	for _, sql := range []string{"BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT sp1"} {
		cmd := Classify(sql)
		if cmd.Type != CommandTCL {
			t.Errorf("Classify(%q) = %v, want TCL", sql, cmd.Type)
		}
	}
}
