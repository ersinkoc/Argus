package policy

import (
	"testing"

	"github.com/ersinkoc/argus/internal/inspection"
)

func TestDetectSQLInjectionTautology(t *testing.T) {
	tests := []struct {
		sql  string
		want bool
	}{
		{"SELECT * FROM users WHERE id=1 OR 1=1", true},
		{"SELECT * FROM users WHERE id=1 OR '1'='1'", true},
		{"SELECT * FROM users WHERE id=1 OR 'a'='a'", true},
		{"SELECT * FROM users WHERE id=1 OR TRUE", true},
		{"SELECT * FROM users WHERE id=1", false},
		{"SELECT * FROM users WHERE name='alice'", false},
	}
	for _, tt := range tests {
		got := detectSQLInjection(tt.sql)
		if got != tt.want {
			t.Errorf("detectSQLInjection(%q) = %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestDetectSQLInjectionUnion(t *testing.T) {
	tests := []struct {
		sql  string
		want bool
	}{
		{"SELECT name FROM users WHERE id=1 UNION SELECT password FROM admin", true},
		{"SELECT name FROM users UNION ALL SELECT credit_card FROM payments", true},
		{"SELECT name FROM users WHERE id=1", false},
	}
	for _, tt := range tests {
		got := detectSQLInjection(tt.sql)
		if got != tt.want {
			t.Errorf("detectSQLInjection(%q) = %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestDetectSQLInjectionStacked(t *testing.T) {
	tests := []struct {
		sql  string
		want bool
	}{
		{"SELECT 1; DROP TABLE users", true},
		{"SELECT 1; DELETE FROM users", true},
		{"SELECT 1; EXEC xp_cmdshell('whoami')", true},
		{"SELECT 1; GRANT ALL TO public", true},
		{"SELECT 1; SHUTDOWN", true},
		{"SELECT 1", false},
		{"BEGIN; COMMIT", false}, // TCL is not flagged
	}
	for _, tt := range tests {
		got := detectSQLInjection(tt.sql)
		if got != tt.want {
			t.Errorf("detectSQLInjection(%q) = %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestDetectSQLInjectionBlind(t *testing.T) {
	tests := []struct {
		sql  string
		want bool
	}{
		{"SELECT * FROM users WHERE id=1 AND SLEEP(5)", true},
		{"SELECT * FROM users WHERE id=1 AND BENCHMARK(10000000,SHA1('test'))", true},
		{"SELECT * FROM users WHERE id=1; WAITFOR DELAY '00:00:05'", true},
		{"SELECT pg_sleep(5)", true},
		{"SELECT * FROM users WHERE id=1", false},
	}
	for _, tt := range tests {
		got := detectSQLInjection(tt.sql)
		if got != tt.want {
			t.Errorf("detectSQLInjection(%q) = %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestDetectSQLInjectionSystemCommands(t *testing.T) {
	tests := []struct {
		sql  string
		want bool
	}{
		{"EXEC xp_cmdshell 'dir'", true},
		{"SELECT * INTO OUTFILE '/tmp/data.csv' FROM users", true},
		{"SELECT LOAD_FILE('/etc/passwd')", true},
		{"SELECT * INTO DUMPFILE '/tmp/shell.php' FROM users", true},
		{"SELECT * FROM users", false},
	}
	for _, tt := range tests {
		got := detectSQLInjection(tt.sql)
		if got != tt.want {
			t.Errorf("detectSQLInjection(%q) = %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestDetectSQLInjectionCommentTermination(t *testing.T) {
	tests := []struct {
		sql  string
		want bool
	}{
		{"SELECT * FROM users WHERE name='admin'--' AND password='x'", true},
		{"SELECT * FROM users WHERE name=\"admin\"--", true},
		{"SELECT * FROM users WHERE name='admin'#", true},
		{"SELECT * FROM users WHERE name='admin'", false},
	}
	for _, tt := range tests {
		got := detectSQLInjection(tt.sql)
		if got != tt.want {
			t.Errorf("detectSQLInjection(%q) = %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestDetectSQLInjectionEncoding(t *testing.T) {
	tests := []struct {
		sql  string
		want bool
	}{
		{"SELECT CHAR(68,82,79,80) FROM dual", true},         // CHAR() with multi-args (building strings)
		{"SELECT * FROM users UNION SELECT CONCAT('a','b')", true}, // CONCAT + UNION
		{"SELECT name FROM users WHERE id=1", false},          // normal query
		{"UPDATE users SET name=CONCAT('a','b')", false},      // CONCAT without UNION/DROP/EXEC
	}
	for _, tt := range tests {
		got := detectSQLInjection(tt.sql)
		if got != tt.want {
			t.Errorf("detectSQLInjection(%q) = %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestCountJoins(t *testing.T) {
	tests := []struct {
		sql  string
		want int
	}{
		{"SELECT * FROM users", 0},
		{"SELECT * FROM users JOIN orders ON users.id=orders.user_id", 1},
		{"SELECT * FROM a JOIN b ON a.id=b.id LEFT JOIN c ON b.id=c.id", 2},
		{"SELECT * FROM a INNER JOIN b ON a.id=b.id CROSS JOIN c", 2},
		{"SELECT * FROM a JOIN b ON 1=1 JOIN c ON 1=1 JOIN d ON 1=1", 3},
	}
	for _, tt := range tests {
		got := countJoins(tt.sql)
		if got != tt.want {
			t.Errorf("countJoins(%q) = %d, want %d", tt.sql, got, tt.want)
		}
	}
}

func TestConditionMaxQueryLength(t *testing.T) {
	ctx := &Context{RawSQL: "SELECT 1"}
	cond := &ConditionConfig{MaxQueryLength: 5}
	if !matchCondition(ctx, cond) {
		t.Error("8-byte query should trigger max_query_length=5")
	}

	cond2 := &ConditionConfig{MaxQueryLength: 100}
	if matchCondition(ctx, cond2) {
		t.Error("8-byte query should NOT trigger max_query_length=100")
	}
}

func TestConditionMaxTables(t *testing.T) {
	ctx := &Context{Tables: []string{"users", "orders", "products"}}
	cond := &ConditionConfig{MaxTables: 2}
	if !matchCondition(ctx, cond) {
		t.Error("3 tables should trigger max_tables=2")
	}

	cond2 := &ConditionConfig{MaxTables: 5}
	if matchCondition(ctx, cond2) {
		t.Error("3 tables should NOT trigger max_tables=5")
	}
}

func TestConditionRequireWhere(t *testing.T) {
	// No WHERE → condition triggers
	ctx := &Context{HasWhere: false, CommandType: inspection.CommandDELETE}
	cond := &ConditionConfig{RequireWhere: true}
	if !matchCondition(ctx, cond) {
		t.Error("missing WHERE should trigger require_where")
	}

	// Has WHERE → condition does NOT trigger
	ctx2 := &Context{HasWhere: true, CommandType: inspection.CommandDELETE}
	if matchCondition(ctx2, cond) {
		t.Error("has WHERE should NOT trigger require_where")
	}
}

func TestConditionMaxJoins(t *testing.T) {
	ctx := &Context{RawSQL: "SELECT * FROM a JOIN b ON 1=1 JOIN c ON 1=1 JOIN d ON 1=1"}
	cond := &ConditionConfig{MaxJoins: 2}
	if !matchCondition(ctx, cond) {
		t.Error("3 JOINs should trigger max_joins=2")
	}

	cond2 := &ConditionConfig{MaxJoins: 5}
	if matchCondition(ctx, cond2) {
		t.Error("3 JOINs should NOT trigger max_joins=5")
	}
}

func TestConditionSQLInjection(t *testing.T) {
	ctx := &Context{RawSQL: "SELECT * FROM users WHERE id=1 OR 1=1"}
	cond := &ConditionConfig{SQLInjection: true}
	if !matchCondition(ctx, cond) {
		t.Error("tautology should trigger sql_injection condition")
	}

	ctx2 := &Context{RawSQL: "SELECT * FROM users WHERE id=1"}
	if matchCondition(ctx2, cond) {
		t.Error("normal query should NOT trigger sql_injection condition")
	}
}

func TestConditionSQLNotContains(t *testing.T) {
	// SQL does NOT contain "WHERE" → condition matches
	ctx := &Context{RawSQL: "DELETE FROM users"}
	cond := &ConditionConfig{SQLNotContains: []string{"WHERE"}}
	if !matchCondition(ctx, cond) {
		t.Error("DELETE without WHERE should trigger sql_not_contains=['WHERE']")
	}

	// SQL does contain "WHERE" → condition does NOT match
	ctx2 := &Context{RawSQL: "DELETE FROM users WHERE id=1"}
	if matchCondition(ctx2, cond) {
		t.Error("DELETE with WHERE should NOT trigger sql_not_contains=['WHERE']")
	}
}

func TestWAFPolicyFileLoads(t *testing.T) {
	loader := NewLoader([]string{"../../configs/policies/waf.json"}, 0)
	if err := loader.Load(); err != nil {
		t.Fatalf("failed to load waf.json: %v", err)
	}
	ps := loader.Current()
	if ps == nil {
		t.Fatal("policy set is nil")
	}
	if len(ps.Policies) < 20 {
		t.Errorf("expected 20+ policies, got %d", len(ps.Policies))
	}
	if len(ps.Roles) < 5 {
		t.Errorf("expected 5+ roles, got %d", len(ps.Roles))
	}
}
