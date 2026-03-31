package inspection

import (
	"fmt"
	"strings"
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
	return indexKeywordOutsideQuotes(strings.ToUpper(sql), strings.ToUpper(keyword)) >= 0
}

// indexKeywordOutsideQuotes finds a SQL keyword in the string, skipping
// content inside quoted literals or identifiers:
//   - Single quotes (SQL string literals: 'value')
//   - Double quotes (SQL identifiers: "column")
//   - Backticks (MySQL identifiers: `column`)
func indexKeywordOutsideQuotes(upper, keyword string) int {
	var quoteChar byte // 0 = not in quote
	klen := len(keyword)
	for i := 0; i < len(upper); i++ {
		ch := upper[i]
		// Track quote state for ', ", `
		if ch == '\'' || ch == '"' || ch == '`' {
			if quoteChar == 0 {
				quoteChar = ch // entering quote
			} else if quoteChar == ch {
				quoteChar = 0 // leaving quote
			}
			continue
		}
		if quoteChar != 0 {
			continue // inside a quoted section
		}
		if i+klen <= len(upper) && upper[i:i+klen] == keyword {
			// Check word boundaries
			before := i == 0 || upper[i-1] == ' ' || upper[i-1] == '\n' || upper[i-1] == '\t' || upper[i-1] == '('
			after := i+klen == len(upper) || upper[i+klen] == ' ' || upper[i+klen] == '\n' || upper[i+klen] == '\t' || upper[i+klen] == ')'
			if before && after {
				return i
			}
		}
	}
	return -1
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
		idx := indexKeywordOutsideQuotes(upper, point)
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
	idx := indexKeywordOutsideQuotes(upper, "WHERE")
	if idx < 0 {
		return injectWhere(sql, condition)
	}
	// Insert after WHERE
	insertAt := idx + 6 // len("WHERE ")
	return sql[:insertAt] + condition + " AND " + sql[insertAt:]
}
