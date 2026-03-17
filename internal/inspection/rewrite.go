package inspection

import (
	"fmt"
	"strings"
)

// RewriteRule defines a query transformation rule.
type RewriteRule struct {
	Type  RewriteType
	Value string
}

// RewriteType identifies the kind of rewrite.
type RewriteType int

const (
	RewriteAddLimit    RewriteType = iota // add LIMIT if missing
	RewriteAddWhere                       // inject WHERE condition
	RewriteSetTimeout                     // add statement_timeout
)

// Rewriter applies transformations to SQL queries.
type Rewriter struct {
	maxLimit    int    // auto-add LIMIT N to SELECT without LIMIT
	forceWhere  string // inject WHERE condition (e.g. "tenant_id = 42")
}

// NewRewriter creates a query rewriter.
func NewRewriter() *Rewriter {
	return &Rewriter{}
}

// SetMaxLimit configures automatic LIMIT injection for SELECTs without LIMIT.
func (r *Rewriter) SetMaxLimit(limit int) {
	r.maxLimit = limit
}

// SetForceWhere configures a WHERE condition to inject into all queries.
func (r *Rewriter) SetForceWhere(condition string) {
	r.forceWhere = condition
}

// Rewrite applies all configured transformations to a SQL query.
// Returns the modified SQL and a list of applied rewrites.
func (r *Rewriter) Rewrite(sql string, cmd *Command) (string, []string) {
	var applied []string

	// Auto-add LIMIT to SELECT without LIMIT
	if r.maxLimit > 0 && cmd.Type == CommandSELECT && !hasKeyword(sql, "LIMIT") {
		sql = addLimit(sql, r.maxLimit)
		applied = append(applied, fmt.Sprintf("added LIMIT %d", r.maxLimit))
	}

	// Inject WHERE condition for multi-tenant isolation
	if r.forceWhere != "" && (cmd.Type == CommandSELECT || cmd.Type == CommandUPDATE || cmd.Type == CommandDELETE) {
		if cmd.HasWhere {
			sql = injectWhereAnd(sql, r.forceWhere)
		} else {
			sql = injectWhere(sql, r.forceWhere)
		}
		applied = append(applied, "injected WHERE condition")
	}

	return sql, applied
}

func hasKeyword(sql, keyword string) bool {
	upper := strings.ToUpper(sql)
	kw := strings.ToUpper(keyword)
	// Simple check — not inside quotes
	idx := strings.LastIndex(upper, kw)
	return idx >= 0
}

func addLimit(sql string, limit int) string {
	sql = strings.TrimRight(sql, "; \t\n")
	return fmt.Sprintf("%s LIMIT %d", sql, limit)
}

func injectWhere(sql string, condition string) string {
	// Find position after FROM clause table name(s)
	upper := strings.ToUpper(sql)
	// Look for ORDER BY, GROUP BY, HAVING, LIMIT, UNION — insert WHERE before them
	insertPoints := []string{"ORDER BY", "GROUP BY", "HAVING", "LIMIT", "UNION"}
	for _, point := range insertPoints {
		idx := strings.Index(upper, point)
		if idx > 0 {
			return sql[:idx] + "WHERE " + condition + " " + sql[idx:]
		}
	}
	// No clause found — append at end
	sql = strings.TrimRight(sql, "; \t\n")
	return sql + " WHERE " + condition
}

func injectWhereAnd(sql string, condition string) string {
	upper := strings.ToUpper(sql)
	idx := strings.Index(upper, "WHERE")
	if idx < 0 {
		return injectWhere(sql, condition)
	}
	// Insert after WHERE
	insertAt := idx + 6 // len("WHERE ")
	return sql[:insertAt] + condition + " AND " + sql[insertAt:]
}
