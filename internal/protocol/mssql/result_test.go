package mssql

import (
	"testing"
)

func TestParseColMetadata(t *testing.T) {
	// Build a simple COLMETADATA with 1 NVARCHAR column named "email"
	var data []byte
	data = append(data, TokenColMetadata) // token
	data = append(data, 1, 0)             // count = 1

	// user type (4 bytes) + flags (2 bytes)
	data = append(data, 0, 0, 0, 0, 0, 0)
	// Type ID: NVARCHAR = 0xE7
	data = append(data, 0xE7)
	// Max length (2 bytes)
	data = append(data, 0x00, 0x01) // 256
	// Collation (5 bytes)
	data = append(data, 0, 0, 0, 0, 0)
	// Column name: length=5, "email" in UTF-16LE
	data = append(data, 5) // name length
	data = append(data, 'e', 0, 'm', 0, 'a', 0, 'i', 0, 'l', 0)

	cols, consumed := ParseColMetadata(data)
	if consumed == 0 {
		t.Fatal("should consume bytes")
	}
	if len(cols) != 1 {
		t.Fatalf("got %d columns, want 1", len(cols))
	}
	if cols[0].Name != "email" {
		t.Errorf("name = %q, want %q", cols[0].Name, "email")
	}
	if !cols[0].IsText {
		t.Error("NVARCHAR should be text")
	}
}

func TestParseColMetadataEmpty(t *testing.T) {
	// Empty data
	cols, consumed := ParseColMetadata(nil)
	if cols != nil || consumed != 0 {
		t.Error("nil data should return nil, 0")
	}

	// No metadata marker (0xFFFF)
	data := []byte{TokenColMetadata, 0xFF, 0xFF}
	cols, consumed = ParseColMetadata(data)
	if len(cols) != 0 {
		t.Error("0xFFFF should return empty columns")
	}
	if consumed != 3 {
		t.Errorf("consumed = %d, want 3", consumed)
	}
}

func TestIsFixedLenType(t *testing.T) {
	if !isFixedLenType(0x38) { // INT
		t.Error("INT should be fixed length")
	}
	if !isFixedLenType(0x7F) { // BIGINT
		t.Error("BIGINT should be fixed length")
	}
	if isFixedLenType(0xE7) { // NVARCHAR
		t.Error("NVARCHAR should not be fixed length")
	}
}

func TestFixedTypeLen(t *testing.T) {
	tests := []struct {
		typeID byte
		want   int
	}{
		{0x30, 1}, // TINYINT
		{0x34, 2}, // SMALLINT
		{0x38, 4}, // INT
		{0x7F, 8}, // BIGINT
		{0x3E, 8}, // FLOAT
	}
	for _, tt := range tests {
		got := fixedTypeLen(tt.typeID)
		if got != tt.want {
			t.Errorf("fixedTypeLen(0x%02x) = %d, want %d", tt.typeID, got, tt.want)
		}
	}
}
