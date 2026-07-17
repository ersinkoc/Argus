package mssql

import (
	"encoding/binary"
	"testing"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

func nvarcharCol(name string) TDSColumnMeta {
	return TDSColumnMeta{Name: name, TypeID: 0xE7, IsText: true, MaxLen: 200}
}

func intCol(name string) TDSColumnMeta {
	return TDSColumnMeta{Name: name, TypeID: 0x38, MaxLen: 4}
}

func buildRow(fields ...any) []byte {
	out := []byte{TokenRow}
	for _, f := range fields {
		switch v := f.(type) {
		case int:
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(v))
			out = append(out, b...)
		case string:
			enc := toUTF16LE(v)
			out = append(out, byte(len(enc)), byte(len(enc)>>8))
			out = append(out, enc...)
		case nil:
			out = append(out, 0xFF, 0xFF)
		}
	}
	return out
}

func TestEncodeUTF16LE(t *testing.T) {
	got := EncodeUTF16LE("Hi")
	want := []byte{'H', 0, 'i', 0}
	if string(got) != string(want) {
		t.Fatalf("EncodeUTF16LE = % x, want % x", got, want)
	}
}

func TestTDSRowLen(t *testing.T) {
	cols := []TDSColumnMeta{intCol("id"), nvarcharCol("name")}
	row := buildRow(1, "Alice")
	if n := TDSRowLen(row, cols); n != len(row) {
		t.Fatalf("TDSRowLen = %d, want %d", n, len(row))
	}

	// Not a row token.
	if n := TDSRowLen([]byte{TokenDone}, cols); n != 0 {
		t.Fatalf("TDSRowLen(non-row) = %d, want 0", n)
	}

	// Truncated row (missing name bytes) → 0 (unknown boundary).
	trunc := buildRow(1, "Alice")
	if n := TDSRowLen(trunc[:len(trunc)-3], cols); n != 0 {
		t.Fatalf("TDSRowLen(truncated) = %d, want 0", n)
	}
}

func TestTDSTokenLen(t *testing.T) {
	// USHORT length-prefixed (INFO): token + len(2) + 5 bytes body.
	info := append([]byte{TokenInfo, 5, 0}, make([]byte, 5)...)
	if n := TDSTokenLen(info); n != 8 {
		t.Errorf("TDSTokenLen(info) = %d, want 8", n)
	}
	// DONE: fixed 13 bytes.
	if n := TDSTokenLen(append([]byte{TokenDone}, make([]byte, 12)...)); n != 13 {
		t.Errorf("TDSTokenLen(done) = %d, want 13", n)
	}
	// RETURNSTATUS: 5 bytes.
	if n := TDSTokenLen(append([]byte{0x79}, make([]byte, 4)...)); n != 5 {
		t.Errorf("TDSTokenLen(returnstatus) = %d, want 5", n)
	}
	// ROW is not sizeable without columns → 0.
	if n := TDSTokenLen([]byte{TokenRow, 1, 2}); n != 0 {
		t.Errorf("TDSTokenLen(row) = %d, want 0", n)
	}
	// Empty / short inputs.
	if n := TDSTokenLen(nil); n != 0 {
		t.Errorf("TDSTokenLen(nil) = %d, want 0", n)
	}
	if n := TDSTokenLen([]byte{TokenInfo, 5}); n != 0 {
		t.Errorf("TDSTokenLen(short header) = %d, want 0", n)
	}
	// Length claims more than available → 0.
	if n := TDSTokenLen([]byte{TokenInfo, 99, 0}); n != 0 {
		t.Errorf("TDSTokenLen(overrun) = %d, want 0", n)
	}
	// DONE with too few bytes returns what's there.
	if n := TDSTokenLen([]byte{TokenDone, 0}); n != 2 {
		t.Errorf("TDSTokenLen(short done) = %d, want 2", n)
	}
}

func TestParseErrorTokenMessage(t *testing.T) {
	tok := BuildErrorToken(208, 1, 16, "Invalid object name", "srv", "", 1)
	if msg := ParseErrorTokenMessage(tok); msg != "Invalid object name" {
		t.Fatalf("ParseErrorTokenMessage = %q, want %q", msg, "Invalid object name")
	}
	// Wrong token / too short.
	if msg := ParseErrorTokenMessage([]byte{TokenDone, 0}); msg != "" {
		t.Fatalf("ParseErrorTokenMessage(non-error) = %q, want empty", msg)
	}
}

func TestBuildErrorTokenMultibyteRoundTrip(t *testing.T) {
	// A multi-byte message must round-trip through the US_VARCHAR length field.
	msg := "Tablo yok: müşteri"
	tok := BuildErrorToken(208, 1, 16, msg, "sunucu", "", 1)
	if got := ParseErrorTokenMessage(tok); got != msg {
		t.Fatalf("round-trip = %q, want %q", got, msg)
	}
}

func TestToUTF16LEMultibyte(t *testing.T) {
	// 'ë' (U+00EB) encodes to a single UTF-16 code unit EB 00; the whole string
	// must be 3 code units with no stray trailing zero bytes.
	got := toUTF16LE("Zoë")
	want := []byte{'Z', 0, 'o', 0, 0xEB, 0x00}
	if string(got) != string(want) {
		t.Fatalf("toUTF16LE(Zoë) = % x, want % x", got, want)
	}
	// Astral-plane rune (U+1F600) must become a surrogate pair (4 bytes).
	if n := len(toUTF16LE("\U0001F600")); n != 4 {
		t.Fatalf("astral rune encoded to %d bytes, want 4 (surrogate pair)", n)
	}
}

func TestExtractTDSRowValues(t *testing.T) {
	cols := []TDSColumnMeta{intCol("id"), nvarcharCol("name")}
	// Includes a multi-byte rune to exercise correct UTF-16LE round-tripping.
	row := buildRow(42, "Zoë")
	vals := ExtractTDSRowValues(row, cols)
	if len(vals) != 2 {
		t.Fatalf("got %d values, want 2", len(vals))
	}
	if vals[1] != "Zoë" {
		t.Fatalf("name = %v, want Zoë", vals[1])
	}

	// NULL field.
	nullRow := buildRow(1, nil)
	if v := ExtractTDSRowValues(nullRow, cols); v[1] != nil {
		t.Fatalf("null field = %v, want nil", v[1])
	}

	// Non-row token.
	if v := ExtractTDSRowValues([]byte{TokenDone}, cols); v != nil {
		t.Fatalf("non-row = %v, want nil", v)
	}
}

func TestMaskTDSRowMasksCorrectColumnIndex(t *testing.T) {
	cols := []TDSColumnMeta{intCol("id"), nvarcharCol("email")}
	row := buildRow(1, "alice@example.com")

	rules := []policy.MaskingRule{{Column: "email", Transformer: "partial_email"}}
	colInfos := []masking.ColumnInfo{{Name: "id", Index: 0}, {Name: "email", Index: 1}}
	pipeline := masking.NewPipeline(rules, colInfos, 0)

	masked := MaskTDSRow(row, cols, pipeline)
	vals := ExtractTDSRowValues(masked, cols)
	if vals[1] != "a***@example.com" {
		t.Fatalf("masked email = %v, want a***@example.com", vals[1])
	}
	// The int column must be untouched.
	if vals[0] != string(func() []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, 1); return b }()) {
		t.Fatalf("id column altered: %v", vals[0])
	}
}
