package masking

import "testing"

// --- DetectByValue: value too long (>50 chars) ---

func TestDetectByValueTooLong(t *testing.T) {
	d := NewPIIDetector()
	cols := []ColumnInfo{{Name: "data", Index: 0}}
	// 60-character string that looks like an email but too long
	longVal := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@bbbbbbbbbbbbbbbbbbbbbb.com"
	row := []FieldValue{{Data: []byte(longVal)}}
	matches := d.DetectByValue(cols, row)
	if len(matches) != 0 {
		t.Error("values longer than 50 chars should be skipped")
	}
}

// --- DetectByValue: more row values than columns ---

func TestDetectByValueMoreValuesThanColumns(t *testing.T) {
	d := NewPIIDetector()
	// Only 1 column but 2 values
	cols := []ColumnInfo{{Name: "email", Index: 0}}
	row := []FieldValue{
		{Data: []byte("john@example.com")},  // index 0, has column
		{Data: []byte("alice@example.com")},  // index 1, no column → colName = ""
	}
	matches := d.DetectByValue(cols, row)
	// Both should be detected
	if len(matches) < 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
	// Second match should have empty column name
	for _, m := range matches {
		if m.ColumnIndex == 1 && m.ColumnName != "" {
			t.Errorf("column index 1 should have empty name, got %q", m.ColumnName)
		}
	}
}

// --- DetectByValue: empty data (len==0) ---

func TestDetectByValueEmptyData(t *testing.T) {
	d := NewPIIDetector()
	cols := []ColumnInfo{{Name: "x", Index: 0}}
	row := []FieldValue{{Data: []byte{}}}
	matches := d.DetectByValue(cols, row)
	if len(matches) != 0 {
		t.Error("empty data should be skipped")
	}
}

// --- tcKimlikCheck: negative check10 (evenSum > oddSum*7) ---

func TestTCKimlikCheckNegativeCheck10(t *testing.T) {
	// 10000008098: oddSum*7 - evenSum = 1*7 - 8 = -1
	// In Go: -1 % 10 = -1, so check10 < 0 path is taken
	if !tcKimlikCheck("10000008098") {
		t.Error("10000008098 should be valid (exercises negative check10 path)")
	}
}

// --- tcKimlikCheck: valid check10 but wrong check11 (sum rule fails) ---

func TestTCKimlikCheckWrongCheck11(t *testing.T) {
	// 10000000146 is valid. Change last digit to make check11 fail.
	if tcKimlikCheck("10000000147") {
		t.Error("10000000147 should be invalid (wrong check11)")
	}
}

// --- DetectByValue: value matches credit_card regex but fails Luhn validation ---

func TestDetectByValueCreditCardRegexMatchLuhnFail(t *testing.T) {
	d := NewPIIDetector()
	cols := []ColumnInfo{{Name: "data", Index: 0}}
	// 16-digit number that matches credit_card regex (13-19 digits) but fails Luhn.
	// Must be >15 digits to avoid matching phone regex (10-15 digits) first.
	row := []FieldValue{{Data: []byte("1234567890123456")}} // 16 digits, fails Luhn
	matches := d.DetectByValue(cols, row)
	for _, m := range matches {
		if m.Category == "credit_card" {
			t.Error("invalid Luhn number should not be detected as credit card")
		}
	}
}
