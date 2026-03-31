package inspection

// CostEstimate provides a lightweight heuristic cost estimate for a query.
// This is NOT a real query planner — it uses structural analysis to flag
// potentially expensive queries before they reach the database.
type CostEstimate struct {
	Score       int      `json:"score"`       // 0-100, higher = more expensive
	Factors     []string `json:"factors"`     // what contributed to the score
	TableCount  int      `json:"table_count"`
	HasSubquery bool     `json:"has_subquery"`
	HasJoin     bool     `json:"has_join"`
	HasOrderBy  bool     `json:"has_order_by"`
	HasGroupBy  bool     `json:"has_group_by"`
	HasWildcard bool     `json:"has_wildcard"` // SELECT *
	HasNoWhere  bool     `json:"has_no_where"`
	HasDistinct bool     `json:"has_distinct"`
	HasUnion    bool     `json:"has_union"`
}

// EstimateCost analyzes a classified command and returns a cost estimate.
func EstimateCost(cmd *Command) *CostEstimate {
	est := &CostEstimate{
		TableCount: len(cmd.Tables),
	}

	// Reuse tokens from Classify if available (avoids re-tokenization)
	tokens := cmd.Tokens
	if tokens == nil {
		tokenizer := NewTokenizer(cmd.Raw)
		tokens = tokenizer.Tokenize()
	}

	depth := 0
	for _, tok := range tokens {
		if tok.Value == "(" {
			depth++
		}
		if tok.Value == ")" && depth > 0 {
			depth--
		}

		if tok.Type != TokenKeyword {
			continue
		}

		// A SELECT keyword inside parentheses indicates a subquery.
		// This avoids false positives from function calls like COUNT(*).
		if depth > 0 && tok.Upper == "SELECT" {
			est.HasSubquery = true
		}

		switch tok.Upper {
		case "JOIN", "INNER", "LEFT", "RIGHT", "CROSS", "NATURAL":
			est.HasJoin = true
		case "ORDER":
			est.HasOrderBy = true
		case "GROUP":
			est.HasGroupBy = true
		case "DISTINCT":
			est.HasDistinct = true
		case "UNION":
			est.HasUnion = true
		}
	}

	// Check for SELECT *
	for i, tok := range tokens {
		if tok.Upper == "SELECT" && i+1 < len(tokens) && tokens[i+1].Type == TokenWildcard {
			est.HasWildcard = true
		}
	}

	est.HasNoWhere = !cmd.HasWhere

	// Calculate score
	score := 0

	if est.TableCount > 1 {
		score += est.TableCount * 10
		est.Factors = append(est.Factors, "multiple tables")
	}

	if est.HasJoin {
		score += 15
		est.Factors = append(est.Factors, "JOIN")
	}

	if est.HasSubquery {
		score += 20
		est.Factors = append(est.Factors, "subquery")
	}

	if est.HasOrderBy {
		score += 10
		est.Factors = append(est.Factors, "ORDER BY")
	}

	if est.HasGroupBy {
		score += 15
		est.Factors = append(est.Factors, "GROUP BY")
	}

	if est.HasDistinct {
		score += 10
		est.Factors = append(est.Factors, "DISTINCT")
	}

	if est.HasUnion {
		score += 15
		est.Factors = append(est.Factors, "UNION")
	}

	if est.HasWildcard && cmd.Type == CommandSELECT {
		score += 5
		est.Factors = append(est.Factors, "SELECT *")
	}

	if est.HasNoWhere && (cmd.Type == CommandSELECT || cmd.Type == CommandUPDATE || cmd.Type == CommandDELETE) {
		score += 20
		est.Factors = append(est.Factors, "no WHERE clause")
	}

	if score > 100 {
		score = 100
	}
	est.Score = score

	return est
}
