package policy

import "strings"

// countJoins counts JOIN keywords in SQL.
func countJoins(sql string) int {
	return countJoinsUpper(strings.ToUpper(sql))
}

func countJoinsUpper(upper string) int {
	return strings.Count(upper, " JOIN ")
}

// normalizeSQL strips inline comments (/* ... */) and line comments (--),
// removes string literals, and collapses all whitespace to defeat obfuscation.
// Order matters: strip comments first, then remove string literals.
func normalizeSQL(s string) string {
	// Strip /* ... */ comments
	for {
		start := strings.Index(s, "/*")
		if start == -1 {
			break
		}
		end := strings.Index(s[start+2:], "*/")
		if end == -1 {
			break
		}
		s = s[:start] + " " + s[start+2+end+2:]
	}

	// Strip -- line comments (must be followed by whitespace or end)
	for {
		idx := strings.Index(s, "--")
		if idx == -1 {
			break
		}
		end := idx + 2
		for end < len(s) && s[end] != '\n' && s[end] != '\r' {
			end++
		}
		s = s[:idx] + " " + s[end:]
	}

	// Remove string literals to prevent quoting-based bypass
	s = removeStringLiterals(s)

	// Collapse whitespace (tabs, newlines, multiple spaces → single space)
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(c)
			prevSpace = false
		}
	}
	return b.String()
}

// removeStringLiterals replaces SQL string literals with @ placeholder.
// 'hello' becomes @, '1'='1' becomes @=@ after this processing.
func removeStringLiterals(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inQuote := false
	quoteChar := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inQuote && (c == '\'' || c == '"') {
			inQuote = true
			quoteChar = c
			b.WriteByte('@')
		} else if inQuote && c == quoteChar {
			if i+1 < len(s) && s[i+1] == quoteChar {
				i++
			} else {
				inQuote = false
			}
		} else if !inQuote {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// detectSQLInjection checks for common SQL injection patterns.
func detectSQLInjection(sql string) bool {
	return detectSQLInjectionUpper(strings.ToUpper(sql))
}

func detectSQLInjectionUpper(upper string) bool {
	if strings.Contains(upper, "'--") || strings.Contains(upper, "'#") ||
		strings.Contains(upper, "\"--") || strings.Contains(upper, "\"#") {
		return true
	}

	upper = normalizeSQL(upper)

	for _, pattern := range sqliTautologyPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}

	if strings.Contains(upper, "UNION") && strings.Contains(upper, "SELECT") {
		unionIdx := strings.Index(upper, "UNION")
		selectAfter := strings.Contains(upper[unionIdx:], "SELECT")
		if selectAfter {
			return true
		}
	}

	if idx := strings.Index(upper, ";"); idx >= 0 && idx < len(upper)-1 {
		after := strings.TrimSpace(upper[idx+1:])
		for _, cmd := range []string{"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "EXEC", "CREATE", "GRANT", "SHUTDOWN"} {
			if strings.HasPrefix(after, cmd) {
				return true
			}
		}
	}

	if strings.Contains(upper, "CHAR(") || strings.Contains(upper, "CHR(") || strings.Contains(upper, "CONCAT(") {
		if strings.Contains(upper, "UNION") || strings.Contains(upper, "DROP") || strings.Contains(upper, "EXEC") {
			return true
		}
		for _, fn := range []string{"CHAR(", "CHR("} {
			if idx := strings.Index(upper, fn); idx >= 0 {
				rest := upper[idx+len(fn):]
				limit := len(rest)
				if limit > 30 {
					limit = 30
				}
				if strings.Contains(rest[:limit], ",") {
					return true
				}
			}
		}
	}

	if strings.Contains(upper, "SLEEP(") || strings.Contains(upper, "BENCHMARK(") ||
		strings.Contains(upper, "PG_SLEEP(") || strings.Contains(upper, "WAITFOR DELAY") {
		return true
	}

	if strings.Contains(upper, "XP_CMDSHELL") || strings.Contains(upper, "INTO OUTFILE") ||
		strings.Contains(upper, "INTO DUMPFILE") || strings.Contains(upper, "LOAD_FILE(") {
		return true
	}

	return false
}

// sqliTautologyPatterns are common tautology injection patterns.
// After string literal removal, '1'='1' becomes @=@, 'a'='a' becomes @=@, etc.
var sqliTautologyPatterns = []string{
	"OR 1=1", "OR @=@", "OR TRUE", "OR FALSE",
	"OR 1 =1", "OR 1= 1", "OR 1 = 1",
	"OR ''='", "OR \"\"=\"",
	"' OR '1", "' OR '", "\" OR \"",
	"OR 1>0", "OR 1<2", "OR 1>=1", "OR 1<=1",
	"OR NULL=NULL", "OR 0=0",
	"AND 1=1", "AND @=@", "AND TRUE", "AND FALSE",
}
