package masking

import (
	"testing"

	"github.com/ersinkoc/argus/internal/policy"
)

func TestTransformers(t *testing.T) {
	tests := []struct {
		name        string
		transformer string
		input       string
		want        string
	}{
		{"redact", "redact", "anything", "***"},
		{"redact empty", "redact", "", ""},
		{"partial_email", "partial_email", "john@example.com", "j***@example.com"},
		{"partial_email no @", "partial_email", "invalid", "***"},
		{"partial_phone", "partial_phone", "+905321234567", "***-***-4567"},
		{"partial_phone short", "partial_phone", "12", "***"},
		{"partial_card", "partial_card", "4532123456785678", "****-****-****-5678"},
		{"partial_card short", "partial_card", "12", "****-****-****-****"},
		{"partial_iban", "partial_iban", "TR330006100519786457841326", "TR**-****-****-****-**26"},
		{"partial_tc", "partial_tc", "12345678901", "*********01"},
		{"hash", "hash", "test", ""},     // just check non-empty
		{"null", "null", "anything", "NULL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer := GetTransformer(tt.transformer)
			result := string(transformer.Transform([]byte(tt.input)))
			if tt.name == "hash" {
				if len(result) == 0 {
					t.Error("hash should produce non-empty output")
				}
				return
			}
			if result != tt.want {
				t.Errorf("got %q, want %q", result, tt.want)
			}
		})
	}
}

func TestPipeline(t *testing.T) {
	rules := []policy.MaskingRule{
		{Column: "email", Transformer: "partial_email"},
		{Column: "salary", Transformer: "redact"},
	}

	columns := []ColumnInfo{
		{Name: "id", Index: 0},
		{Name: "name", Index: 1},
		{Name: "email", Index: 2},
		{Name: "salary", Index: 3},
	}

	pipeline := NewPipeline(rules, columns, 0)

	if !pipeline.HasMasking() {
		t.Error("pipeline should have masking")
	}

	masked := pipeline.MaskedColumns()
	if len(masked) != 2 {
		t.Errorf("masked columns = %v, want 2", masked)
	}

	// Process a row
	row := []FieldValue{
		{Data: []byte("1")},
		{Data: []byte("John")},
		{Data: []byte("john@example.com")},
		{Data: []byte("50000")},
	}

	result, include := pipeline.ProcessRow(row)
	if !include {
		t.Error("row should be included")
	}

	if string(result[0].Data) != "1" {
		t.Errorf("id should be unchanged, got %q", result[0].Data)
	}
	if string(result[1].Data) != "John" {
		t.Errorf("name should be unchanged, got %q", result[1].Data)
	}
	if string(result[2].Data) != "j***@example.com" {
		t.Errorf("email should be masked, got %q", result[2].Data)
	}
	if string(result[3].Data) != "***" {
		t.Errorf("salary should be redacted, got %q", result[3].Data)
	}
}

func TestPipelineRowLimit(t *testing.T) {
	pipeline := NewPipeline(nil, nil, 3)

	for i := 0; i < 3; i++ {
		_, include := pipeline.ProcessRow([]FieldValue{{Data: []byte("x")}})
		if !include {
			t.Errorf("row %d should be included", i+1)
		}
	}

	_, include := pipeline.ProcessRow([]FieldValue{{Data: []byte("x")}})
	if include {
		t.Error("row 4 should be excluded (limit=3)")
	}

	if !pipeline.IsTruncated() {
		t.Error("pipeline should be truncated")
	}
}

func TestPipelineNullValues(t *testing.T) {
	rules := []policy.MaskingRule{
		{Column: "email", Transformer: "partial_email"},
	}
	columns := []ColumnInfo{
		{Name: "email", Index: 0},
	}

	pipeline := NewPipeline(rules, columns, 0)

	row := []FieldValue{
		{Data: nil, IsNull: true},
	}
	result, include := pipeline.ProcessRow(row)
	if !include {
		t.Error("row should be included")
	}
	if !result[0].IsNull {
		t.Error("null value should remain null")
	}
}
