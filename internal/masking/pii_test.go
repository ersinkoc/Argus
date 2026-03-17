package masking

import "testing"

func TestPIIDetectByColumnName(t *testing.T) {
	detector := NewPIIDetector()

	columns := []ColumnInfo{
		{Name: "id", Index: 0},
		{Name: "user_email", Index: 1},
		{Name: "phone_number", Index: 2},
		{Name: "credit_card_no", Index: 3},
		{Name: "tc_kimlik_no", Index: 4},
		{Name: "iban", Index: 5},
		{Name: "salary", Index: 6},
		{Name: "password_hash", Index: 7},
		{Name: "first_name", Index: 8},
		{Name: "date_of_birth", Index: 9},
		{Name: "home_address", Index: 10},
	}

	matches := detector.DetectByColumnName(columns)

	expected := map[string]string{
		"user_email":     "email",
		"phone_number":   "phone",
		"credit_card_no": "credit_card",
		"tc_kimlik_no":   "national_id",
		"iban":           "iban",
		"salary":         "financial",
		"password_hash":  "credential",
		"date_of_birth":  "date_of_birth",
		"home_address":   "address",
	}

	found := make(map[string]string)
	for _, m := range matches {
		found[m.ColumnName] = m.Category
	}

	for col, cat := range expected {
		if found[col] != cat {
			t.Errorf("column %q: got category %q, want %q", col, found[col], cat)
		}
	}

	// "id" and "first_name" should NOT match
	if _, ok := found["id"]; ok {
		t.Error("id should not be detected as PII")
	}
	if _, ok := found["first_name"]; ok {
		t.Error("first_name should not be detected as PII")
	}
}

func TestPIIDetectByValue(t *testing.T) {
	detector := NewPIIDetector()

	columns := []ColumnInfo{
		{Name: "col1", Index: 0},
		{Name: "col2", Index: 1},
		{Name: "col3", Index: 2},
		{Name: "col4", Index: 3},
	}

	row := []FieldValue{
		{Data: []byte("john@example.com")},           // email
		{Data: []byte("+905321234567")},               // phone
		{Data: []byte("4532015112830366")},            // credit card (valid Luhn)
		{Data: []byte("just a normal string")},        // not PII
	}

	matches := detector.DetectByValue(columns, row)

	categories := make(map[int]string)
	for _, m := range matches {
		categories[m.ColumnIndex] = m.Category
	}

	if categories[0] != "email" {
		t.Errorf("col 0 should be email, got %q", categories[0])
	}
	if categories[1] != "phone" {
		t.Errorf("col 1 should be phone, got %q", categories[1])
	}
	if categories[2] != "credit_card" {
		t.Errorf("col 2 should be credit_card, got %q", categories[2])
	}
	if _, ok := categories[3]; ok {
		t.Error("col 3 should not be detected as PII")
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		{"4532015112830366", true},
		{"4111111111111111", true},
		{"1234567890123456", false},
		{"0000000000000000", true}, // technically valid Luhn
	}
	for _, tt := range tests {
		if got := luhnCheck(tt.number); got != tt.valid {
			t.Errorf("luhnCheck(%q) = %v, want %v", tt.number, got, tt.valid)
		}
	}
}

func TestTCKimlikCheck(t *testing.T) {
	tests := []struct {
		tc    string
		valid bool
	}{
		{"10000000146", true},
		{"12345678901", false},
		{"00000000000", false}, // starts with 0
		{"1234567890", false},  // wrong length
	}
	for _, tt := range tests {
		if got := tcKimlikCheck(tt.tc); got != tt.valid {
			t.Errorf("tcKimlikCheck(%q) = %v, want %v", tt.tc, got, tt.valid)
		}
	}
}

func TestPIIDetectNullValues(t *testing.T) {
	detector := NewPIIDetector()
	columns := []ColumnInfo{{Name: "email", Index: 0}}
	row := []FieldValue{{IsNull: true}}
	matches := detector.DetectByValue(columns, row)
	if len(matches) != 0 {
		t.Error("null values should not match PII patterns")
	}
}

func BenchmarkPIIDetectByColumnName(b *testing.B) {
	detector := NewPIIDetector()
	columns := []ColumnInfo{
		{Name: "id", Index: 0}, {Name: "email", Index: 1},
		{Name: "phone", Index: 2}, {Name: "name", Index: 3},
		{Name: "salary", Index: 4}, {Name: "address", Index: 5},
	}
	for b.Loop() {
		detector.DetectByColumnName(columns)
	}
}

func BenchmarkPIIDetectByValue(b *testing.B) {
	detector := NewPIIDetector()
	columns := []ColumnInfo{{Name: "c1", Index: 0}, {Name: "c2", Index: 1}}
	row := []FieldValue{
		{Data: []byte("john@example.com")},
		{Data: []byte("normal text")},
	}
	for b.Loop() {
		detector.DetectByValue(columns, row)
	}
}
