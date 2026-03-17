package masking

import "testing"

func TestPipelinePIIAutoDetect(t *testing.T) {
	detector := NewPIIDetector()

	// Create pipeline with no explicit rules but with PII detector
	pipeline := NewPipeline(nil, nil, 0)
	pipeline.SetPIIDetector(detector)

	// Simulate receiving RowDescription with PII columns
	columns := []ColumnInfo{
		{Name: "id", Index: 0},
		{Name: "name", Index: 1},
		{Name: "email", Index: 2},
		{Name: "phone_number", Index: 3},
		{Name: "salary", Index: 4},
	}

	pipeline.ApplyPIIDetection(columns)

	if !pipeline.HasMasking() {
		t.Error("pipeline should have masking after PII detection")
	}

	masked := pipeline.MaskedColumns()
	if len(masked) < 3 {
		t.Errorf("expected at least 3 masked columns (email, phone, salary), got %d: %v", len(masked), masked)
	}

	// Process a row
	row := []FieldValue{
		{Data: []byte("1")},
		{Data: []byte("John Doe")},
		{Data: []byte("john@example.com")},
		{Data: []byte("+905321234567")},
		{Data: []byte("75000")},
	}

	result, include := pipeline.ProcessRow(row)
	if !include {
		t.Error("row should be included")
	}

	// id and name should be unchanged
	if string(result[0].Data) != "1" {
		t.Errorf("id should be unchanged, got %q", result[0].Data)
	}
	if string(result[1].Data) != "John Doe" {
		t.Errorf("name should be unchanged, got %q", result[1].Data)
	}

	// email should be masked
	if string(result[2].Data) == "john@example.com" {
		t.Error("email should be masked")
	}

	// phone should be masked
	if string(result[3].Data) == "+905321234567" {
		t.Error("phone should be masked")
	}

	// salary should be masked
	if string(result[4].Data) == "75000" {
		t.Error("salary should be masked")
	}
}

func TestPipelinePIIDoesNotOverrideExplicit(t *testing.T) {
	detector := NewPIIDetector()

	// Explicit rule: redact email completely
	pipeline := NewPipeline(nil, nil, 0)
	pipeline.SetPIIDetector(detector)

	columns := []ColumnInfo{
		{Name: "email", Index: 0},
	}

	// Manually add explicit rule first
	pipeline.columnMap = map[int]Transformer{
		0: GetTransformer("redact"),
	}

	// PII detection should NOT override the explicit rule
	pipeline.ApplyPIIDetection(columns)

	row := []FieldValue{{Data: []byte("john@example.com")}}
	result, _ := pipeline.ProcessRow(row)

	// Should be redacted (***), not partial_email (j***@example.com)
	if string(result[0].Data) != "***" {
		t.Errorf("explicit rule should take precedence, got %q", result[0].Data)
	}
}

func TestPipelinePIINoDoubleDetect(t *testing.T) {
	detector := NewPIIDetector()
	pipeline := NewPipeline(nil, nil, 0)
	pipeline.SetPIIDetector(detector)

	columns := []ColumnInfo{{Name: "email", Index: 0}}

	pipeline.ApplyPIIDetection(columns)
	count1 := len(pipeline.MaskedColumns())

	// Second call should be a no-op
	pipeline.ApplyPIIDetection(columns)
	count2 := len(pipeline.MaskedColumns())

	if count1 != count2 {
		t.Errorf("double detection added duplicate columns: %d vs %d", count1, count2)
	}
}
