package inspection

import "testing"

func TestIndexKeywordOutsideDoubleQuotes(t *testing.T) {
	upper := "SELECT * FROM \"ORDER_TABLE\" WHERE ID = 1 ORDER BY ID"
	idx := indexKeywordOutsideQuotes(upper, "ORDER BY")
	// Should find the real ORDER BY, not the one inside double quotes
	if idx < 40 {
		t.Errorf("idx = %d, should find ORDER BY after position 40", idx)
	}
}

func TestIndexKeywordOutsideBackticks(t *testing.T) {
	upper := "SELECT * FROM `LIMIT` WHERE ID = 1 LIMIT 10"
	idx := indexKeywordOutsideQuotes(upper, "LIMIT")
	// Should find the real LIMIT at the end, not inside backticks
	if idx < 30 {
		t.Errorf("idx = %d, should find LIMIT after position 30", idx)
	}
}

func TestIndexKeywordOutsideQuotesNotFound(t *testing.T) {
	upper := "SELECT * FROM USERS"
	idx := indexKeywordOutsideQuotes(upper, "ORDER BY")
	if idx != -1 {
		t.Errorf("idx = %d, want -1 (not found)", idx)
	}
}

func TestIndexKeywordAllInsideQuotes(t *testing.T) {
	upper := "SELECT * FROM T WHERE NAME = 'ORDER BY LIMIT'"
	idx := indexKeywordOutsideQuotes(upper, "ORDER BY")
	if idx != -1 {
		t.Errorf("idx = %d, want -1 (keyword only inside quotes)", idx)
	}
}

func TestHasKeywordWithBackticks(t *testing.T) {
	// hasKeyword uses indexKeywordOutsideQuotes internally
	if hasKeyword("SELECT * FROM `limit`", "LIMIT") {
		t.Error("should NOT find LIMIT inside backticks")
	}
	if !hasKeyword("SELECT * FROM t LIMIT 10", "LIMIT") {
		t.Error("should find LIMIT outside backticks")
	}
}
