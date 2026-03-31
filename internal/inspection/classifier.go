package inspection

import "strings"

// CommandType classifies a SQL command.
type CommandType int

const (
	CommandSELECT  CommandType = iota // SELECT queries
	CommandINSERT                     // INSERT statements
	CommandUPDATE                     // UPDATE statements
	CommandDELETE                     // DELETE statements
	CommandDDL                        // CREATE, ALTER, DROP, TRUNCATE
	CommandDCL                        // GRANT, REVOKE
	CommandTCL                        // BEGIN, COMMIT, ROLLBACK, SAVEPOINT
	CommandADMIN                      // SET, SHOW, EXPLAIN, ANALYZE
	CommandUTILITY                    // COPY, LOAD, VACUUM, REINDEX
	CommandUNKNOWN                    // unrecognized
)

var commandTypeNames = map[CommandType]string{
	CommandSELECT:  "SELECT",
	CommandINSERT:  "INSERT",
	CommandUPDATE:  "UPDATE",
	CommandDELETE:  "DELETE",
	CommandDDL:     "DDL",
	CommandDCL:     "DCL",
	CommandTCL:     "TCL",
	CommandADMIN:   "ADMIN",
	CommandUTILITY: "UTILITY",
	CommandUNKNOWN: "UNKNOWN",
}

func (c CommandType) String() string {
	if s, ok := commandTypeNames[c]; ok {
		return s
	}
	return "UNKNOWN"
}

// RiskLevel indicates the danger level of a command.
type RiskLevel int

const (
	RiskNone     RiskLevel = iota // normal read operations
	RiskLow                       // standard write operations
	RiskMedium                    // DDL, bulk operations
	RiskHigh                      // destructive operations, privilege changes
	RiskCritical                  // multi-statement, potential injection patterns
)

var riskLevelNames = map[RiskLevel]string{
	RiskNone:     "none",
	RiskLow:      "low",
	RiskMedium:   "medium",
	RiskHigh:     "high",
	RiskCritical: "critical",
}

func (r RiskLevel) String() string {
	if s, ok := riskLevelNames[r]; ok {
		return s
	}
	return "unknown"
}

// ParseRiskLevel parses a risk level string.
func ParseRiskLevel(s string) RiskLevel {
	for r, name := range riskLevelNames {
		if name == s {
			return r
		}
	}
	return RiskNone
}

// Command represents an inspected SQL command.
type Command struct {
	Raw         string
	Type        CommandType
	Tables      []string
	Columns     []string
	RiskLevel   RiskLevel
	Confidence  float64
	HasWhere    bool
	IsMulti     bool // multiple statements
	Warnings    []string
}

// Classify analyzes a SQL string and returns a Command.
func Classify(sql string) *Command {
	tokenizer := NewTokenizer(sql)
	tokens := tokenizer.Tokenize()

	cmd := &Command{
		Raw:        sql,
		Type:       CommandUNKNOWN,
		Confidence: 1.0,
	}

	// Filter out comments and collect meaningful tokens
	var meaningful []Token
	hasCommentWithSQL := false
	for _, tok := range tokens {
		if tok.Type == TokenComment {
			// Check for SQL keywords inside comments (suspicious)
			// Strip comment markers before re-tokenizing
			content := tok.Value
			if strings.HasPrefix(content, "/*") {
				content = strings.TrimPrefix(content, "/*")
				content = strings.TrimSuffix(content, "*/")
			} else if strings.HasPrefix(content, "--") {
				content = strings.TrimPrefix(content, "--")
			}
			commentTokenizer := NewTokenizer(content)
			commentTokens := commentTokenizer.Tokenize()
			for _, ct := range commentTokens {
				if ct.Type == TokenKeyword && isDangerousKeyword(ct.Upper) {
					hasCommentWithSQL = true
				}
			}
			continue
		}
		meaningful = append(meaningful, tok)
	}

	if len(meaningful) == 0 {
		return cmd
	}

	// Check for multiple statements
	semiCount := 0
	for _, tok := range meaningful {
		if tok.Type == TokenPunctuation && tok.Value == ";" {
			semiCount++
		}
	}
	cmd.IsMulti = semiCount > 1 || (semiCount == 1 && meaningful[len(meaningful)-1].Value != ";")

	// Classify by first keyword
	first := meaningful[0]
	if first.Type == TokenKeyword || first.Type == TokenIdentifier {
		switch first.Upper {
		case "SELECT":
			cmd.Type = CommandSELECT
		case "INSERT":
			cmd.Type = CommandINSERT
		case "UPDATE":
			cmd.Type = CommandUPDATE
		case "DELETE":
			cmd.Type = CommandDELETE
		case "CREATE", "ALTER", "DROP", "TRUNCATE":
			cmd.Type = CommandDDL
		case "GRANT", "REVOKE":
			cmd.Type = CommandDCL
		case "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "START":
			cmd.Type = CommandTCL
		case "SET", "SHOW", "EXPLAIN", "ANALYZE":
			cmd.Type = CommandADMIN
		case "COPY", "LOAD", "VACUUM", "REINDEX":
			cmd.Type = CommandUTILITY
		case "WITH":
			// WITH ... SELECT (CTE)
			for _, t := range meaningful[1:] {
				if t.Type == TokenKeyword && t.Upper == "SELECT" {
					cmd.Type = CommandSELECT
					break
				}
				if t.Type == TokenKeyword && (t.Upper == "INSERT" || t.Upper == "UPDATE" || t.Upper == "DELETE") {
					switch t.Upper {
					case "INSERT":
						cmd.Type = CommandINSERT
					case "UPDATE":
						cmd.Type = CommandUPDATE
					case "DELETE":
						cmd.Type = CommandDELETE
					}
					break
				}
			}
			if cmd.Type == CommandUNKNOWN {
				cmd.Type = CommandSELECT // default CTE to SELECT
			}
		}
	}

	// Check for WHERE clause
	for _, tok := range meaningful {
		if tok.Type == TokenKeyword && tok.Upper == "WHERE" {
			cmd.HasWhere = true
			break
		}
	}

	// Assign risk level
	cmd.RiskLevel = assessRisk(cmd, meaningful, hasCommentWithSQL)

	// Extract tables
	cmd.Tables = extractTables(meaningful)
	cmd.Columns = extractColumns(meaningful, cmd.Type)

	return cmd
}

func assessRisk(cmd *Command, tokens []Token, hasCommentWithSQL bool) RiskLevel {
	risk := RiskNone

	switch cmd.Type {
	case CommandSELECT:
		risk = RiskNone
	case CommandINSERT:
		risk = RiskLow
	case CommandUPDATE:
		if !cmd.HasWhere {
			risk = RiskMedium // bulk update
		} else {
			risk = RiskLow
		}
	case CommandDELETE:
		if !cmd.HasWhere {
			risk = RiskMedium // bulk delete
		} else {
			risk = RiskLow
		}
	case CommandDDL:
		risk = RiskMedium
		// Check for destructive DDL
		for _, tok := range tokens {
			if tok.Upper == "DROP" || tok.Upper == "TRUNCATE" {
				risk = RiskHigh
				break
			}
		}
	case CommandDCL:
		risk = RiskHigh
	}

	// Multi-statement is always critical
	if cmd.IsMulti {
		risk = RiskCritical
		cmd.Warnings = append(cmd.Warnings, "multiple statements detected")
	}

	// Comment with SQL keywords
	if hasCommentWithSQL {
		if risk < RiskHigh {
			risk = RiskHigh
		}
		cmd.Warnings = append(cmd.Warnings, "SQL keywords found inside comment")
	}

	return risk
}

var dangerousKeywords = map[string]bool{
	"DROP": true, "TRUNCATE": true, "DELETE": true,
	"UPDATE": true, "INSERT": true, "ALTER": true,
	"GRANT": true, "REVOKE": true, "EXEC": true,
	"EXECUTE": true,
}

func isDangerousKeyword(kw string) bool {
	return dangerousKeywords[kw]
}
