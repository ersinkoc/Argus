package inspection

import "testing"

// --- needsSpace: exercise all branches ---

func TestNeedsSpaceAfterOpenParen(t *testing.T) {
	prev := Token{Type: TokenPunctuation, Value: "("}
	cur := Token{Type: TokenIdentifier, Value: "x"}
	if needsSpace(prev, cur) {
		t.Error("no space after (")
	}
}

func TestNeedsSpaceAfterComma(t *testing.T) {
	prev := Token{Type: TokenPunctuation, Value: ","}
	cur := Token{Type: TokenIdentifier, Value: "x"}
	if needsSpace(prev, cur) {
		t.Error("no space after ,")
	}
}

func TestNeedsSpaceBeforeCloseParen2(t *testing.T) {
	prev := Token{Type: TokenIdentifier, Value: "x"}
	cur := Token{Type: TokenPunctuation, Value: ")"}
	if needsSpace(prev, cur) {
		t.Error("no space before )")
	}
}

func TestNeedsSpaceBeforeComma(t *testing.T) {
	prev := Token{Type: TokenIdentifier, Value: "x"}
	cur := Token{Type: TokenPunctuation, Value: ","}
	if needsSpace(prev, cur) {
		t.Error("no space before ,")
	}
}

func TestNeedsSpaceBeforeSemicolon(t *testing.T) {
	prev := Token{Type: TokenIdentifier, Value: "x"}
	cur := Token{Type: TokenPunctuation, Value: ";"}
	if needsSpace(prev, cur) {
		t.Error("no space before ;")
	}
}

func TestNeedsSpacePrevDot(t *testing.T) {
	prev := Token{Type: TokenOperator, Value: "."}
	cur := Token{Type: TokenIdentifier, Value: "col"}
	if needsSpace(prev, cur) {
		t.Error("no space after .")
	}
}

func TestNeedsSpaceCurDot(t *testing.T) {
	prev := Token{Type: TokenIdentifier, Value: "tbl"}
	cur := Token{Type: TokenOperator, Value: "."}
	if needsSpace(prev, cur) {
		t.Error("no space before .")
	}
}

func TestNeedsSpaceNormal(t *testing.T) {
	prev := Token{Type: TokenKeyword, Value: "SELECT", Upper: "SELECT"}
	cur := Token{Type: TokenIdentifier, Value: "id"}
	if !needsSpace(prev, cur) {
		t.Error("space between SELECT and id")
	}
}
