package inspection

import (
	"strings"
	"unicode"
)

// TokenType represents the type of SQL token.
type TokenType int

const (
	TokenKeyword    TokenType = iota // SQL keyword (SELECT, INSERT, etc.)
	TokenIdentifier                  // table name, column name
	TokenOperator                    // =, <, >, !=, etc.
	TokenLiteral                     // string or number literal
	TokenComment                     // -- or /* */ comment
	TokenPunctuation                 // (, ), ,, ;
	TokenWildcard                    // *
	TokenEOF                         // end of input
)

// Token represents a single SQL token.
type Token struct {
	Type  TokenType
	Value string
	Upper string // uppercase value for keywords
}

// Tokenizer breaks SQL strings into tokens.
type Tokenizer struct {
	input []rune
	pos   int
}

// NewTokenizer creates a tokenizer for the given SQL string.
func NewTokenizer(sql string) *Tokenizer {
	return &Tokenizer{
		input: []rune(sql),
		pos:   0,
	}
}

// sqlKeywords is the set of SQL keywords we care about.
var sqlKeywords = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"FROM": true, "INTO": true, "SET": true, "WHERE": true,
	"JOIN": true, "INNER": true, "LEFT": true, "RIGHT": true,
	"OUTER": true, "CROSS": true, "ON": true, "AS": true,
	"AND": true, "OR": true, "NOT": true, "IN": true,
	"IS": true, "NULL": true, "LIKE": true, "BETWEEN": true,
	"EXISTS": true, "HAVING": true, "GROUP": true, "BY": true,
	"ORDER": true, "LIMIT": true, "OFFSET": true, "UNION": true,
	"ALL": true, "DISTINCT": true, "VALUES": true,
	"CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true,
	"TABLE": true, "INDEX": true, "VIEW": true, "DATABASE": true,
	"SCHEMA": true, "SEQUENCE": true, "FUNCTION": true, "PROCEDURE": true,
	"TRIGGER": true, "TYPE": true, "EXTENSION": true,
	"GRANT": true, "REVOKE": true,
	"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "SAVEPOINT": true,
	"EXPLAIN": true, "ANALYZE": true, "VACUUM": true, "REINDEX": true,
	"SHOW": true, "COPY": true, "LOAD": true,
	"WITH": true, "RECURSIVE": true, "RETURNING": true,
	"CASCADE": true, "RESTRICT": true, "IF": true,
	"PRIMARY": true, "KEY": true, "REFERENCES": true, "FOREIGN": true,
	"CONSTRAINT": true, "UNIQUE": true, "CHECK": true, "DEFAULT": true,
	"NATURAL": true, "USING": true, "CASE": true, "WHEN": true,
	"THEN": true, "ELSE": true, "END": true,
}

// Tokenize returns all tokens from the SQL string.
func (t *Tokenizer) Tokenize() []Token {
	var tokens []Token
	for {
		tok := t.Next()
		if tok.Type == TokenEOF {
			break
		}
		tokens = append(tokens, tok)
	}
	return tokens
}

// Next returns the next token.
func (t *Tokenizer) Next() Token {
	t.skipWhitespace()

	if t.pos >= len(t.input) {
		return Token{Type: TokenEOF}
	}

	ch := t.input[t.pos]

	// Line comment
	if ch == '-' && t.pos+1 < len(t.input) && t.input[t.pos+1] == '-' {
		return t.readLineComment()
	}

	// Block comment
	if ch == '/' && t.pos+1 < len(t.input) && t.input[t.pos+1] == '*' {
		return t.readBlockComment()
	}

	// String literal
	if ch == '\'' {
		return t.readStringLiteral()
	}

	// Dollar-quoted string (PostgreSQL)
	if ch == '$' {
		return t.readDollarQuoted()
	}

	// Quoted identifier
	if ch == '"' {
		return t.readQuotedIdentifier('"')
	}
	if ch == '`' {
		return t.readQuotedIdentifier('`')
	}
	if ch == '[' {
		return t.readBracketIdentifier()
	}

	// Number
	if unicode.IsDigit(ch) || (ch == '.' && t.pos+1 < len(t.input) && unicode.IsDigit(t.input[t.pos+1])) {
		return t.readNumber()
	}

	// Wildcard
	if ch == '*' {
		t.pos++
		return Token{Type: TokenWildcard, Value: "*", Upper: "*"}
	}

	// Punctuation
	if ch == '(' || ch == ')' || ch == ',' || ch == ';' {
		t.pos++
		return Token{Type: TokenPunctuation, Value: string(ch), Upper: string(ch)}
	}

	// Operators
	if isOperator(ch) {
		return t.readOperator()
	}

	// Keyword or identifier
	if unicode.IsLetter(ch) || ch == '_' {
		return t.readWord()
	}

	// Unknown character, skip
	t.pos++
	return Token{Type: TokenPunctuation, Value: string(ch), Upper: string(ch)}
}

func (t *Tokenizer) skipWhitespace() {
	for t.pos < len(t.input) && unicode.IsSpace(t.input[t.pos]) {
		t.pos++
	}
}

func (t *Tokenizer) readWord() Token {
	start := t.pos
	for t.pos < len(t.input) && (unicode.IsLetter(t.input[t.pos]) || unicode.IsDigit(t.input[t.pos]) || t.input[t.pos] == '_' || t.input[t.pos] == '.') {
		t.pos++
	}
	value := string(t.input[start:t.pos])
	upper := strings.ToUpper(value)

	// Check for schema-qualified names: handle the dot within identifiers
	if sqlKeywords[upper] {
		return Token{Type: TokenKeyword, Value: value, Upper: upper}
	}
	return Token{Type: TokenIdentifier, Value: value, Upper: upper}
}

func (t *Tokenizer) readStringLiteral() Token {
	t.pos++ // skip opening quote
	var sb strings.Builder
	for t.pos < len(t.input) {
		ch := t.input[t.pos]
		if ch == '\'' {
			if t.pos+1 < len(t.input) && t.input[t.pos+1] == '\'' {
				// Escaped quote
				sb.WriteRune('\'')
				t.pos += 2
				continue
			}
			t.pos++ // skip closing quote
			break
		}
		sb.WriteRune(ch)
		t.pos++
	}
	return Token{Type: TokenLiteral, Value: sb.String(), Upper: sb.String()}
}

func (t *Tokenizer) readDollarQuoted() Token {
	start := t.pos
	t.pos++ // skip first $
	// Read tag
	tagStart := t.pos
	for t.pos < len(t.input) && t.input[t.pos] != '$' {
		if !unicode.IsLetter(t.input[t.pos]) && !unicode.IsDigit(t.input[t.pos]) && t.input[t.pos] != '_' {
			// Not a dollar-quoted string, treat $ as operator
			t.pos = start + 1
			return Token{Type: TokenOperator, Value: "$", Upper: "$"}
		}
		t.pos++
	}
	if t.pos >= len(t.input) {
		return Token{Type: TokenOperator, Value: "$", Upper: "$"}
	}
	t.pos++ // skip closing $ of tag
	tag := "$" + string(t.input[tagStart:t.pos-1]) + "$"

	// Read until closing tag
	var sb strings.Builder
	for t.pos < len(t.input) {
		remaining := string(t.input[t.pos:])
		if strings.HasPrefix(remaining, tag) {
			t.pos += len([]rune(tag))
			break
		}
		sb.WriteRune(t.input[t.pos])
		t.pos++
	}
	return Token{Type: TokenLiteral, Value: sb.String(), Upper: sb.String()}
}

func (t *Tokenizer) readQuotedIdentifier(quote rune) Token {
	t.pos++ // skip opening quote
	var sb strings.Builder
	for t.pos < len(t.input) {
		ch := t.input[t.pos]
		if ch == quote {
			if t.pos+1 < len(t.input) && t.input[t.pos+1] == quote {
				sb.WriteRune(quote)
				t.pos += 2
				continue
			}
			t.pos++
			break
		}
		sb.WriteRune(ch)
		t.pos++
	}
	value := sb.String()
	return Token{Type: TokenIdentifier, Value: value, Upper: strings.ToUpper(value)}
}

func (t *Tokenizer) readBracketIdentifier() Token {
	t.pos++ // skip [
	var sb strings.Builder
	for t.pos < len(t.input) && t.input[t.pos] != ']' {
		sb.WriteRune(t.input[t.pos])
		t.pos++
	}
	if t.pos < len(t.input) {
		t.pos++ // skip ]
	}
	value := sb.String()
	return Token{Type: TokenIdentifier, Value: value, Upper: strings.ToUpper(value)}
}

func (t *Tokenizer) readNumber() Token {
	start := t.pos
	for t.pos < len(t.input) && (unicode.IsDigit(t.input[t.pos]) || t.input[t.pos] == '.' || t.input[t.pos] == 'e' || t.input[t.pos] == 'E') {
		t.pos++
	}
	value := string(t.input[start:t.pos])
	return Token{Type: TokenLiteral, Value: value, Upper: value}
}

func (t *Tokenizer) readLineComment() Token {
	start := t.pos
	for t.pos < len(t.input) && t.input[t.pos] != '\n' {
		t.pos++
	}
	value := string(t.input[start:t.pos])
	return Token{Type: TokenComment, Value: value, Upper: value}
}

func (t *Tokenizer) readBlockComment() Token {
	start := t.pos
	t.pos += 2 // skip /*
	depth := 1
	for t.pos < len(t.input) && depth > 0 {
		if t.input[t.pos] == '/' && t.pos+1 < len(t.input) && t.input[t.pos+1] == '*' {
			depth++
			t.pos += 2
			continue
		}
		if t.input[t.pos] == '*' && t.pos+1 < len(t.input) && t.input[t.pos+1] == '/' {
			depth--
			t.pos += 2
			continue
		}
		t.pos++
	}
	value := string(t.input[start:t.pos])
	return Token{Type: TokenComment, Value: value, Upper: value}
}

func (t *Tokenizer) readOperator() Token {
	start := t.pos
	t.pos++
	// Two-char operators
	if t.pos < len(t.input) {
		twoChar := string(t.input[start : t.pos+1])
		if twoChar == "<>" || twoChar == "!=" || twoChar == "<=" || twoChar == ">=" || twoChar == "::" || twoChar == "||" {
			t.pos++
			return Token{Type: TokenOperator, Value: twoChar, Upper: twoChar}
		}
	}
	value := string(t.input[start:t.pos])
	return Token{Type: TokenOperator, Value: value, Upper: value}
}

func isOperator(ch rune) bool {
	return ch == '=' || ch == '<' || ch == '>' || ch == '!' || ch == '+' || ch == '-' ||
		ch == '/' || ch == '%' || ch == '|' || ch == '&' || ch == '^' || ch == '~' || ch == ':'
}
