package mssql

import "testing"

func TestFixedTypeLenAll(t *testing.T) {
	tests := []struct {
		typeID byte
		want   int
	}{
		{0x30, 1}, {0x32, 1}, // TINYINT, BIT
		{0x34, 2},            // SMALLINT
		{0x38, 4}, {0x3B, 4}, // INT, REAL
		{0x3A, 4}, {0x3C, 4}, // SMALLDATETIME, SMALLMONEY
		{0x3D, 8}, {0x3E, 8}, {0x7F, 8}, {0x7A, 8}, // DATETIME, FLOAT, BIGINT, MONEY
		{0x99, 0}, // unknown
	}
	for _, tt := range tests {
		got := fixedTypeLen(tt.typeID)
		if got != tt.want {
			t.Errorf("fixedTypeLen(0x%02x) = %d, want %d", tt.typeID, got, tt.want)
		}
	}
}

func TestMaskTDSRowNilPipeline(t *testing.T) {
	data := []byte{TokenRow, 0x01, 0x02, 0x03}
	result := MaskTDSRow(data, nil, nil)
	if string(result) != string(data) {
		t.Error("nil pipeline should return data unchanged")
	}
}

func TestMaskTDSRowNonRowToken(t *testing.T) {
	data := []byte{TokenDone, 0x01, 0x02}
	result := MaskTDSRow(data, nil, nil)
	if string(result) != string(data) {
		t.Error("non-row token should return unchanged")
	}
}

func TestIsFixedLenTypeAll(t *testing.T) {
	fixed := []byte{0x30, 0x32, 0x34, 0x38, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x7A, 0x7F}
	for _, id := range fixed {
		if !isFixedLenType(id) {
			t.Errorf("0x%02x should be fixed length", id)
		}
	}
	notFixed := []byte{0xE7, 0xA5, 0xAD, 0x22, 0x23, 0x24, 0x00, 0xFF}
	for _, id := range notFixed {
		if isFixedLenType(id) {
			t.Errorf("0x%02x should NOT be fixed length", id)
		}
	}
}
