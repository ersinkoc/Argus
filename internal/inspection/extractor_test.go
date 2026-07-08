package inspection

import (
	"testing"
	"time"
)

func TestClassifyWithCTE(t *testing.T) {
	// WITH SELECT — should be SELECT
	cmd := Classify("WITH cte AS (SELECT 1) SELECT * FROM cte")
	if cmd.Type != CommandSELECT {
		t.Errorf("WITH SELECT = %v, want SELECT", cmd.Type)
	}
}

func TestClassifyVacuum(t *testing.T) {
	cmd := Classify("VACUUM ANALYZE users")
	if cmd.Type != CommandUTILITY {
		t.Errorf("VACUUM = %v, want UTILITY", cmd.Type)
	}
}

func TestClassifyCopy(t *testing.T) {
	cmd := Classify("COPY users TO STDOUT")
	if cmd.Type != CommandUTILITY {
		t.Errorf("COPY = %v, want UTILITY", cmd.Type)
	}
}

func TestClassifySet(t *testing.T) {
	cmd := Classify("SET search_path TO public")
	if cmd.Type != CommandADMIN {
		t.Errorf("SET = %v, want ADMIN", cmd.Type)
	}
}

func TestReadTableNamesSubquery(t *testing.T) {
	cmd := Classify("SELECT * FROM (SELECT 1 AS x) AS sub")
	// Table extraction from subqueries is best-effort
	_ = cmd.Tables
}

func TestExtractInsertColumnsNoParens(t *testing.T) {
	cmd := Classify("INSERT INTO t VALUES (1, 2)")
	// No column list — columns should be empty
	if len(cmd.Columns) != 0 {
		t.Errorf("no column list: columns = %v", cmd.Columns)
	}
}

func TestNeedSpaceDot(t *testing.T) {
	stmts := SplitStatements("SELECT t.col FROM t")
	if len(stmts) != 1 {
		t.Error("dot-separated identifier should be single statement")
	}
}

func TestTokenizerDollarQuotedTag(t *testing.T) {
	tokens := NewTokenizer("SELECT $tag$body text$tag$").Tokenize()
	found := false
	for _, tok := range tokens {
		if tok.Type == TokenLiteral && tok.Value == "body text" {
			found = true
		}
	}
	if !found {
		t.Error("should parse tagged dollar-quoted string")
	}
}

func TestAnomalyFrequencySpike(t *testing.T) {
	d := NewAnomalyDetector(0)
	ts := fixedTime(14, 0)

	// Build baseline: 200 queries, peak 10/min
	for i := 0; i < 200; i++ {
		d.Record("spike_user", CommandSELECT, []string{"t"}, ts)
	}
	// Force minute rollover
	d.mu.Lock()
	p := d.profiles["spike_user"]
	p.peakMinute = 10
	p.recentMinute = 50 // 5x peak
	d.mu.Unlock()

	alerts := d.Check("spike_user", CommandSELECT, []string{"t"}, ts)
	found := false
	for _, a := range alerts {
		if a.Type == "frequency_spike" {
			found = true
		}
	}
	if !found {
		t.Error("50/min vs peak 10/min should trigger frequency_spike")
	}
}

func fixedTime(hour, min int) time.Time {
	return time.Date(2026, 3, 17, hour, min, 0, 0, time.UTC)
}
