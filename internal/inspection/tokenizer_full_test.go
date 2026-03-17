package inspection

import "testing"

func TestTokenizerEscapedQuote(t *testing.T) {
	tokens := NewTokenizer("SELECT 'it''s' FROM t").Tokenize()
	found := false
	for _, tok := range tokens {
		if tok.Type == TokenLiteral && tok.Value == "it's" {
			found = true
		}
	}
	if !found {
		t.Error("should parse escaped single quote")
	}
}

func TestTokenizerDoubleQuotedEscape(t *testing.T) {
	tokens := NewTokenizer(`SELECT "col""name" FROM t`).Tokenize()
	found := false
	for _, tok := range tokens {
		if tok.Type == TokenIdentifier && tok.Value == `col"name` {
			found = true
		}
	}
	if !found {
		t.Error("should parse escaped double quote in identifier")
	}
}

func TestTokenizerDollarInvalid(t *testing.T) {
	// $ followed by non-alphanumeric — should be operator
	tokens := NewTokenizer("SELECT $").Tokenize()
	if len(tokens) < 2 {
		t.Error("should have at least 2 tokens")
	}
}
