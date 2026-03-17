package audit

import (
	"strings"
	"unicode"
)

// SanitizeSQL replaces string literals and numeric values in SQL with
// positional parameters ($1, $2, ...) for safe audit logging.
// This prevents sensitive data from appearing in audit logs.
func SanitizeSQL(sql string) string {
	if sql == "" {
		return sql
	}

	var result strings.Builder
	result.Grow(len(sql))
	paramCount := 0
	i := 0
	runes := []rune(sql)

	for i < len(runes) {
		ch := runes[i]

		// String literal (single-quoted)
		if ch == '\'' {
			paramCount++
			result.WriteString("$")
			result.WriteString(itoa(paramCount))
			i++
			// Skip until closing quote
			for i < len(runes) {
				if runes[i] == '\'' {
					if i+1 < len(runes) && runes[i+1] == '\'' {
						i += 2 // escaped quote
						continue
					}
					i++ // closing quote
					break
				}
				i++
			}
			continue
		}

		// Dollar-quoted string (PostgreSQL)
		if ch == '$' && i+1 < len(runes) && runes[i+1] == '$' {
			paramCount++
			result.WriteString("$")
			result.WriteString(itoa(paramCount))
			// Find closing $$
			i += 2
			for i < len(runes)-1 {
				if runes[i] == '$' && runes[i+1] == '$' {
					i += 2
					break
				}
				i++
			}
			continue
		}

		// Numeric literal (standalone numbers, not part of identifiers)
		if unicode.IsDigit(ch) && (i == 0 || !isIdentChar(runes[i-1])) {
			paramCount++
			result.WriteString("$")
			result.WriteString(itoa(paramCount))
			// Skip entire number
			for i < len(runes) && (unicode.IsDigit(runes[i]) || runes[i] == '.' || runes[i] == 'e' || runes[i] == 'E') {
				i++
			}
			continue
		}

		result.WriteRune(ch)
		i++
	}

	return result.String()
}

func isIdentChar(ch rune) bool {
	return unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '_'
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	// Simple int to string for small numbers
	digits := make([]byte, 0, 4)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
