package inspection

// SplitStatements splits a multi-statement SQL string into individual statements.
// Each statement is classified independently so policies can be applied per-statement.
func SplitStatements(sql string) []string {
	tokenizer := NewTokenizer(sql)
	tokens := tokenizer.Tokenize()

	var statements []string
	var current []Token
	depth := 0 // parenthesis depth

	for _, tok := range tokens {
		if tok.Value == "(" {
			depth++
		}
		if tok.Value == ")" && depth > 0 {
			depth--
		}

		// Semicolons at depth 0 separate statements
		if tok.Type == TokenPunctuation && tok.Value == ";" && depth == 0 {
			if len(current) > 0 {
				statements = append(statements, tokensToSQL(current))
				current = nil
			}
			continue
		}

		current = append(current, tok)
	}

	// Last statement (without trailing semicolon)
	if len(current) > 0 {
		statements = append(statements, tokensToSQL(current))
	}

	return statements
}

// ClassifyMulti classifies each statement in a multi-statement SQL string.
func ClassifyMulti(sql string) []*Command {
	stmts := SplitStatements(sql)
	if len(stmts) <= 1 {
		// Single statement — use normal classify
		return []*Command{Classify(sql)}
	}

	commands := make([]*Command, 0, len(stmts))
	for _, stmt := range stmts {
		cmd := Classify(stmt)
		cmd.IsMulti = true
		commands = append(commands, cmd)
	}
	return commands
}

func tokensToSQL(tokens []Token) string {
	if len(tokens) == 0 {
		return ""
	}

	// Reconstruct SQL from tokens with proper spacing
	var result []byte
	for i, tok := range tokens {
		if i > 0 && needsSpace(tokens[i-1], tok) {
			result = append(result, ' ')
		}
		result = append(result, []byte(tok.Value)...)
	}
	return string(result)
}

func needsSpace(prev, cur Token) bool {
	// No space after/before punctuation
	if prev.Type == TokenPunctuation && (prev.Value == "(" || prev.Value == ",") {
		return false
	}
	if cur.Type == TokenPunctuation && (cur.Value == ")" || cur.Value == "," || cur.Value == ";") {
		return false
	}
	// No space between operator and operand in some cases
	if prev.Type == TokenOperator && prev.Value == "." {
		return false
	}
	if cur.Type == TokenOperator && cur.Value == "." {
		return false
	}
	return true
}
