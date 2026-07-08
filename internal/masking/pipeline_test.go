package masking

import "testing"

func TestPIIDetectByValueShortValues(t *testing.T) {
	d := NewPIIDetector()
	cols := []ColumnInfo{{Name: "x", Index: 0}}
	// Very short value — should skip
	row := []FieldValue{{Data: []byte("ab")}}
	if len(d.DetectByValue(cols, row)) != 0 {
		t.Error("short values should be skipped")
	}
}

func TestTCKimlikCheckAllPaths(t *testing.T) {
	// Valid
	if !tcKimlikCheck("10000000146") {
		t.Error("10000000146 should be valid")
	}
	// Wrong length
	if tcKimlikCheck("1234") {
		t.Error("short should be invalid")
	}
	// Starts with 0
	if tcKimlikCheck("00000000000") {
		t.Error("starts with 0 should be invalid")
	}
	// Wrong check digit 10
	if tcKimlikCheck("12345678999") {
		t.Error("wrong check10 should be invalid")
	}
}
