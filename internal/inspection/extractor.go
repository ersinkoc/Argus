package inspection

import "strings"

// extractTables extracts table names from tokens.
// Looks for tables after FROM, INTO, UPDATE, JOIN, and TABLE keywords.
func extractTables(tokens []Token) []string {
	var tables []string
	seen := make(map[string]bool)

	for i, tok := range tokens {
		if tok.Type != TokenKeyword {
			continue
		}

		switch tok.Upper {
		case "FROM", "JOIN", "INTO", "TABLE", "UPDATE":
			// Next non-keyword token(s) should be table name(s)
			names := readTableNames(tokens, i+1)
			for _, name := range names {
				lower := strings.ToLower(name)
				if !seen[lower] {
					seen[lower] = true
					tables = append(tables, name)
				}
			}
		}
	}

	return tables
}

// readTableNames reads one or more table names starting from position idx.
// Handles: schema.table, table alias, table1, table2 (comma-separated after FROM)
func readTableNames(tokens []Token, idx int) []string {
	var names []string
	if idx >= len(tokens) {
		return names
	}

	for i := idx; i < len(tokens); i++ {
		tok := tokens[i]

		// Skip parentheses (subqueries)
		if tok.Value == "(" {
			depth := 1
			for i++; i < len(tokens) && depth > 0; i++ {
				if tokens[i].Value == "(" {
					depth++
				}
				if tokens[i].Value == ")" {
					depth--
				}
			}
			continue
		}

		// Stop at keywords that end the table list
		if tok.Type == TokenKeyword && isTableListTerminator(tok.Upper) {
			break
		}

		// Stop at semicolons
		if tok.Type == TokenPunctuation && tok.Value == ";" {
			break
		}

		// Identifier = table name
		if tok.Type == TokenIdentifier {
			name := tok.Value
			// Check for schema.table (already handled by tokenizer if dot is part of word)
			if !strings.Contains(name, ".") && i+2 < len(tokens) &&
				tokens[i+1].Type == TokenOperator && tokens[i+1].Value == "." &&
				tokens[i+2].Type == TokenIdentifier {
				// But our tokenizer includes dots in identifiers, so this case is rare
			}
			names = append(names, name)

			// Skip alias (AS alias or just alias)
			if i+1 < len(tokens) {
				next := tokens[i+1]
				if next.Type == TokenKeyword && next.Upper == "AS" {
					i += 2 // skip AS and alias
				} else if next.Type == TokenIdentifier && !isTableListTerminator(next.Upper) {
					i++ // skip alias
				}
			}
		}

		// Comma means more tables follow
		if tok.Type == TokenPunctuation && tok.Value == "," {
			continue
		}
	}

	return names
}

func isTableListTerminator(kw string) bool {
	terminators := map[string]bool{
		"WHERE": true, "SET": true, "ORDER": true, "GROUP": true,
		"HAVING": true, "LIMIT": true, "OFFSET": true, "UNION": true,
		"ON": true, "USING": true, "VALUES": true, "SELECT": true,
		"INNER": true, "LEFT": true, "RIGHT": true, "OUTER": true,
		"CROSS": true, "NATURAL": true, "JOIN": true, "RETURNING": true,
		"FOR": true, "INTO": true, "FROM": true,
	}
	return terminators[kw]
}

// extractColumns extracts column names from the SELECT list or relevant clauses.
func extractColumns(tokens []Token, cmdType CommandType) []string {
	var columns []string
	seen := make(map[string]bool)

	switch cmdType {
	case CommandSELECT:
		columns = extractSelectColumns(tokens, seen)
	case CommandINSERT:
		columns = extractInsertColumns(tokens, seen)
	case CommandUPDATE:
		columns = extractUpdateColumns(tokens, seen)
	}

	return columns
}

func extractSelectColumns(tokens []Token, seen map[string]bool) []string {
	var columns []string
	// Find SELECT ... FROM
	inSelect := false
	for _, tok := range tokens {
		if tok.Type == TokenKeyword && tok.Upper == "SELECT" {
			inSelect = true
			continue
		}
		if tok.Type == TokenKeyword && tok.Upper == "DISTINCT" && inSelect {
			continue
		}
		if tok.Type == TokenKeyword && (tok.Upper == "FROM" || tok.Upper == "INTO") {
			break
		}
		if inSelect && tok.Type == TokenIdentifier {
			name := tok.Value
			// Handle table.column
			if parts := strings.Split(name, "."); len(parts) > 1 {
				name = parts[len(parts)-1]
			}
			if !seen[name] {
				seen[name] = true
				columns = append(columns, name)
			}
		}
	}
	return columns
}

func extractInsertColumns(tokens []Token, seen map[string]bool) []string {
	var columns []string
	// Find column list in INSERT INTO table (col1, col2, ...)
	inParens := false
	parenDepth := 0
	passedInto := false
	passedTable := false

	for _, tok := range tokens {
		if tok.Type == TokenKeyword && tok.Upper == "INTO" {
			passedInto = true
			continue
		}
		if passedInto && !passedTable && tok.Type == TokenIdentifier {
			passedTable = true
			continue
		}
		if passedTable && tok.Value == "(" && parenDepth == 0 {
			inParens = true
			parenDepth = 1
			continue
		}
		if inParens {
			if tok.Value == ")" {
				parenDepth--
				if parenDepth == 0 {
					break
				}
			}
			if tok.Value == "(" {
				parenDepth++
			}
			if tok.Type == TokenIdentifier && parenDepth == 1 {
				if !seen[tok.Value] {
					seen[tok.Value] = true
					columns = append(columns, tok.Value)
				}
			}
		}
	}
	return columns
}

func extractUpdateColumns(tokens []Token, seen map[string]bool) []string {
	var columns []string
	// Find SET col1 = ..., col2 = ...
	inSet := false
	for _, tok := range tokens {
		if tok.Type == TokenKeyword && tok.Upper == "SET" {
			inSet = true
			continue
		}
		if tok.Type == TokenKeyword && tok.Upper == "WHERE" {
			break
		}
		if inSet && tok.Type == TokenIdentifier {
			name := tok.Value
			if !seen[name] {
				seen[name] = true
				columns = append(columns, name)
			}
		}
	}
	return columns
}
