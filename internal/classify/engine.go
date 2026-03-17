package classify

import (
	"regexp"
	"strings"
	"sync"
)

// SensitivityLevel represents data sensitivity.
type SensitivityLevel int

const (
	Public       SensitivityLevel = iota // non-sensitive data
	Internal                              // internal business data
	Confidential                          // business confidential
	Restricted                            // highly restricted (PII, financial)
	Critical                              // critical secrets (credentials, keys)
)

var levelNames = map[SensitivityLevel]string{
	Public:       "public",
	Internal:     "internal",
	Confidential: "confidential",
	Restricted:   "restricted",
	Critical:     "critical",
}

func (l SensitivityLevel) String() string {
	if s, ok := levelNames[l]; ok {
		return s
	}
	return "unknown"
}

// Classification represents a classified column.
type Classification struct {
	ColumnName  string           `json:"column_name"`
	TableName   string           `json:"table_name,omitempty"`
	Level       SensitivityLevel `json:"level"`
	LevelName   string           `json:"level_name"`
	Category    string           `json:"category"`    // "pii", "financial", "credential", "health"
	Transformer string           `json:"transformer"` // recommended masking transformer
	Confidence  float64          `json:"confidence"`  // 0.0-1.0
}

// Rule defines a classification rule.
type Rule struct {
	Pattern     *regexp.Regexp
	Category    string
	Level       SensitivityLevel
	Transformer string
	Confidence  float64
}

// Engine classifies database columns by sensitivity level.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewEngine creates a classification engine with built-in rules.
func NewEngine() *Engine {
	e := &Engine{}

	// Built-in classification rules (ordered by specificity)
	builtinRules := []struct {
		pattern     string
		category    string
		level       SensitivityLevel
		transformer string
		confidence  float64
	}{
		// Critical — credentials and secrets
		{`(?i)password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token`, "credential", Critical, "redact", 0.95},

		// Restricted — PII
		{`(?i)ssn|social[_-]?sec|tc[_-]?kimlik|identity[_-]?no|national[_-]?id`, "pii", Restricted, "partial_tc", 0.95},
		{`(?i)credit[_-]?card|card[_-]?num|pan|card[_-]?no`, "pii", Restricted, "partial_card", 0.95},
		{`(?i)iban`, "pii", Restricted, "partial_iban", 0.90},

		// Restricted — financial
		{`(?i)salary|wage|income|compensation|pay[_-]?rate|bonus`, "financial", Restricted, "redact", 0.90},
		{`(?i)bank[_-]?account|account[_-]?no|routing[_-]?num`, "financial", Restricted, "redact", 0.90},
		{`(?i)tax[_-]?id|vat[_-]?id|ein|tin`, "financial", Restricted, "redact", 0.85},

		// Confidential — contact info
		{`(?i)e[-_]?mail`, "pii", Confidential, "partial_email", 0.90},
		{`(?i)phone|mobile|tel|gsm|cep`, "pii", Confidential, "partial_phone", 0.85},
		{`(?i)address|street|city|zip|postal`, "pii", Confidential, "redact", 0.80},

		// Confidential — personal
		{`(?i)birth[_-]?(date|day)|dob|date[_-]?of[_-]?birth`, "pii", Confidential, "redact", 0.85},
		{`(?i)gender|sex|race|ethnicity|religion`, "pii", Confidential, "redact", 0.80},
		{`(?i)medical|diagnosis|prescription|health`, "health", Confidential, "redact", 0.85},

		// Internal — identifiers
		{`(?i)first[_-]?name|last[_-]?name|full[_-]?name|surname`, "pii", Internal, "hash", 0.70},
		{`(?i)user[_-]?name|login|display[_-]?name`, "pii", Internal, "hash", 0.60},
		{`(?i)ip[_-]?address|client[_-]?ip|remote[_-]?addr`, "technical", Internal, "redact", 0.70},
	}

	for _, r := range builtinRules {
		e.rules = append(e.rules, Rule{
			Pattern:     regexp.MustCompile(r.pattern),
			Category:    r.category,
			Level:       r.level,
			Transformer: r.transformer,
			Confidence:  r.confidence,
		})
	}

	return e
}

// ClassifyColumn classifies a single column by name.
func (e *Engine) ClassifyColumn(columnName string) *Classification {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if rule.Pattern.MatchString(columnName) {
			return &Classification{
				ColumnName:  columnName,
				Level:       rule.Level,
				LevelName:   rule.Level.String(),
				Category:    rule.Category,
				Transformer: rule.Transformer,
				Confidence:  rule.Confidence,
			}
		}
	}

	return &Classification{
		ColumnName:  columnName,
		Level:       Public,
		LevelName:   Public.String(),
		Category:    "general",
		Transformer: "",
		Confidence:  1.0,
	}
}

// ClassifyColumns classifies multiple columns.
func (e *Engine) ClassifyColumns(columns []string) []*Classification {
	result := make([]*Classification, len(columns))
	for i, col := range columns {
		result[i] = e.ClassifyColumn(col)
	}
	return result
}

// ClassifyTable classifies all columns of a table.
func (e *Engine) ClassifyTable(tableName string, columns []string) []*Classification {
	result := e.ClassifyColumns(columns)
	for _, c := range result {
		c.TableName = tableName
	}
	return result
}

// AddRule adds a custom classification rule.
func (e *Engine) AddRule(pattern, category string, level SensitivityLevel, transformer string, confidence float64) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Insert at beginning (custom rules take priority)
	e.rules = append([]Rule{{
		Pattern:     re,
		Category:    category,
		Level:       level,
		Transformer: transformer,
		Confidence:  confidence,
	}}, e.rules...)

	return nil
}

// SensitiveCols returns only columns classified above a threshold level.
func (e *Engine) SensitiveCols(columns []string, minLevel SensitivityLevel) []*Classification {
	var result []*Classification
	for _, col := range columns {
		c := e.ClassifyColumn(col)
		if c.Level >= minLevel {
			result = append(result, c)
		}
	}
	return result
}

// Summary returns classification statistics for a set of columns.
type ClassificationSummary struct {
	Total        int            `json:"total"`
	ByLevel      map[string]int `json:"by_level"`
	ByCategory   map[string]int `json:"by_category"`
	Sensitive    int            `json:"sensitive"` // Confidential+Restricted+Critical
	NeedsMasking int            `json:"needs_masking"`
}

func (e *Engine) Summary(columns []string) *ClassificationSummary {
	s := &ClassificationSummary{
		Total:      len(columns),
		ByLevel:    make(map[string]int),
		ByCategory: make(map[string]int),
	}

	for _, col := range columns {
		c := e.ClassifyColumn(col)
		s.ByLevel[c.LevelName]++
		s.ByCategory[c.Category]++
		if c.Level >= Confidential {
			s.Sensitive++
		}
		if c.Transformer != "" {
			s.NeedsMasking++
		}
	}

	return s
}

// ParseLevel parses a sensitivity level string.
func ParseLevel(s string) SensitivityLevel {
	for level, name := range levelNames {
		if strings.EqualFold(name, s) {
			return level
		}
	}
	return Public
}
