package inspection

import "testing"

func TestSplitStatements(t *testing.T) {
	tests := []struct {
		name  string
		sql   string
		count int
	}{
		{"single", "SELECT 1", 1},
		{"single with semicolon", "SELECT 1;", 1},
		{"two statements", "SELECT 1; SELECT 2", 2},
		{"three statements", "INSERT INTO t VALUES (1); UPDATE t SET x = 2; DELETE FROM t WHERE x = 3", 3},
		{"semicolon in subquery", "SELECT * FROM (SELECT 1; SELECT 2)", 1}, // semicolons inside parens stay together
		{"empty", "", 0},
		{"just semicolons", ";;;", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmts := SplitStatements(tt.sql)
			if len(stmts) != tt.count {
				t.Errorf("got %d statements, want %d: %v", len(stmts), tt.count, stmts)
			}
		})
	}
}

func TestClassifyMulti(t *testing.T) {
	cmds := ClassifyMulti("SELECT 1; INSERT INTO t VALUES (1); DROP TABLE t")
	if len(cmds) != 3 {
		t.Fatalf("got %d commands, want 3", len(cmds))
	}

	if cmds[0].Type != CommandSELECT {
		t.Errorf("cmd 0 type = %v, want SELECT", cmds[0].Type)
	}
	if cmds[1].Type != CommandINSERT {
		t.Errorf("cmd 1 type = %v, want INSERT", cmds[1].Type)
	}
	if cmds[2].Type != CommandDDL {
		t.Errorf("cmd 2 type = %v, want DDL", cmds[2].Type)
	}

	// All should be marked as multi
	for i, cmd := range cmds {
		if !cmd.IsMulti {
			t.Errorf("cmd %d should be marked as multi-statement", i)
		}
	}
}

func TestClassifyMultiSingle(t *testing.T) {
	cmds := ClassifyMulti("SELECT * FROM users")
	if len(cmds) != 1 {
		t.Fatalf("got %d, want 1", len(cmds))
	}
	if cmds[0].Type != CommandSELECT {
		t.Errorf("type = %v, want SELECT", cmds[0].Type)
	}
}

func BenchmarkSplitStatements(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1; INSERT INTO logs (msg) VALUES ('test'); UPDATE stats SET count = count + 1 WHERE name = 'pageviews'"
	for b.Loop() {
		SplitStatements(sql)
	}
}
