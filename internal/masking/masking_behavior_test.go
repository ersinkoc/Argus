package masking

import (
	"testing"

	"github.com/ersinkoc/argus/internal/policy"
)

func TestPipelineMaskingRules(t *testing.T) {
	rules := []policy.MaskingRule{{Column: "email", Transformer: "redact"}}
	p := NewPipeline(rules, nil, 100)

	if len(p.MaskingRules()) != 1 {
		t.Errorf("MaskingRules = %d, want 1", len(p.MaskingRules()))
	}
	if p.MaxRowsLimit() != 100 {
		t.Errorf("MaxRowsLimit = %d, want 100", p.MaxRowsLimit())
	}
}

func TestPipelineRowCount(t *testing.T) {
	p := NewPipeline(nil, nil, 0)
	p.ProcessRow([]FieldValue{{Data: []byte("x")}})
	p.ProcessRow([]FieldValue{{Data: []byte("y")}})
	if p.RowCount() != 2 {
		t.Errorf("RowCount = %d, want 2", p.RowCount())
	}
}

func TestMatchColumnWildcard(t *testing.T) {
	if !matchColumn("*", "anything") {
		t.Error("* should match anything")
	}
	if !matchColumn("email", "EMAIL") {
		t.Error("should be case-insensitive")
	}
	if matchColumn("email", "phone") {
		t.Error("should not match different names")
	}
}

func TestRegisterTransformer(t *testing.T) {
	RegisterTransformer("custom_test", TransformerFunc(func(v []byte) []byte {
		return []byte("custom:" + string(v))
	}))
	tr := GetTransformer("custom_test")
	result := string(tr.Transform([]byte("hello")))
	if result != "custom:hello" {
		t.Errorf("custom transformer result = %q", result)
	}

	// Unknown transformer should default to redact
	tr2 := GetTransformer("nonexistent_transformer")
	if string(tr2.Transform([]byte("x"))) != "***" {
		t.Error("unknown should default to redact")
	}
}

func TestPartialIBANShort(t *testing.T) {
	result := string(partialIBAN([]byte("AB")))
	if result != "***" {
		t.Errorf("short IBAN = %q, want '***'", result)
	}
}

func TestPartialTCShort(t *testing.T) {
	result := string(partialTC([]byte("1")))
	if result != "***" {
		t.Errorf("short TC = %q, want '***'", result)
	}
}

func TestPIIDetectByValueLongString(t *testing.T) {
	detector := NewPIIDetector()
	cols := []ColumnInfo{{Name: "data", Index: 0}}
	// Very long value — should be skipped
	longVal := make([]byte, 100)
	for i := range longVal {
		longVal[i] = 'a'
	}
	row := []FieldValue{{Data: longVal}}
	matches := detector.DetectByValue(cols, row)
	if len(matches) != 0 {
		t.Error("very long values should be skipped")
	}
}

func TestTCKimlikValidNumber(t *testing.T) {
	// Test with a known valid TC: 10000000146
	if !tcKimlikCheck("10000000146") {
		t.Error("10000000146 should be valid")
	}
	// First digit 0
	if tcKimlikCheck("01234567890") {
		t.Error("TC starting with 0 should be invalid")
	}
}
