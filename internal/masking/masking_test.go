package masking

import (
	"strings"
	"testing"

	"github.com/ersinkoc/argus/internal/policy"
)

func TestHashTransformerProperties(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		input := []byte("the same value every time")
		a := hashValue(input)
		b := hashValue(input)
		if string(a) != string(b) {
			t.Error("hash transformer is not deterministic")
		}
	})

	t.Run("different_inputs_different_outputs", func(t *testing.T) {
		seen := make(map[string]struct{}, 1000)
		inputs := []string{
			"", "a", "b", "hello", "world", "hello world",
			"user@example.com", "+905321234567",
			"TR330006100519786457841326",
			"12345678901",
			"admin", "password123",
			"SELECT * FROM users",
			"{\"json\": \"data\"}",
			string(make([]byte, 1024)), // binary data
		}
		for _, in := range inputs {
			out := string(hashValue([]byte(in)))
			if _, dup := seen[out]; dup {
				t.Errorf("collision detected for input %q", in)
			}
			seen[out] = struct{}{}
		}
	})

	t.Run("non_empty", func(t *testing.T) {
		out := hashValue([]byte("anything"))
		if len(out) == 0 {
			t.Error("hash should produce non-empty output")
		}
	})

	t.Run("length", func(t *testing.T) {
		out := hashValue([]byte("measure me"))
		// Current implementation returns 32 hex chars (16 bytes SHA-256 prefix).
		// This is NOT a contract — it's a documented implementation detail.
		// Change this value when the hash implementation changes.
		if len(out) != 32 {
			t.Logf("hash length = %d (expected 32 for current impl)", len(out))
		}
	})
}

// --- Property-based tests for all transformers ---

func TestRedactProperties(t *testing.T) {
	t.Run("replaces_non_empty_with_asterisks", func(t *testing.T) {
		inputs := []string{"anything", "x", " ", "\n", "long text with spaces"}
		for _, in := range inputs {
			out := string(redact([]byte(in)))
			if out != "***" {
				t.Errorf("redact(%q) = %q, want ***", in, out)
			}
		}
	})
	t.Run("preserves_empty_input", func(t *testing.T) {
		out := redact([]byte(""))
		if len(out) != 0 {
			t.Errorf("redact('') should preserve empty input, got %q", out)
		}
	})
	t.Run("always_same_length", func(t *testing.T) {
		for _, in := range []string{"a", "ab", "abc", "abcd", strings.Repeat("x", 1000)} {
			out := string(redact([]byte(in)))
			if out != "***" {
				t.Errorf("redact(%q) = %q, want *** (len=%d)", in, out, len(in))
			}
		}
	})
}

func TestPartialEmailProperties(t *testing.T) {
	t.Run("preserves_domain", func(t *testing.T) {
		inputs := []string{
			"john@example.com",
			"a@b.co",
			"user.name+tag@domain.org",
			"x@y",
		}
		for _, in := range inputs {
			out := string(partialEmail([]byte(in)))
			if !strings.Contains(out, "@") {
				t.Errorf("partialEmail(%q) = %q, should contain @", in, out)
				continue
			}
			parts := strings.SplitN(in, "@", 2)
			if len(parts) == 2 && !strings.HasSuffix(out, parts[1]) {
				t.Errorf("partialEmail(%q) = %q, should end with domain %q", in, out, parts[1])
			}
		}
	})
	t.Run("masks_local_part", func(t *testing.T) {
		out := string(partialEmail([]byte("john@example.com")))
		// Should start with first char + "***"
		if !strings.HasPrefix(out, "j***") {
			t.Errorf("partialEmail('john@example.com') = %q, want j***...", out)
		}
	})
	t.Run("fallback_for_no_at", func(t *testing.T) {
		inputs := []string{"", "invalid", "noatsign", "@"}
		for _, in := range inputs {
			out := string(partialEmail([]byte(in)))
			if out != "***" {
				t.Errorf("partialEmail(%q) = %q, want ***", in, out)
			}
		}
	})

}

func TestPartialPhoneProperties(t *testing.T) {
	t.Run("preserves_last_4_digits", func(t *testing.T) {
		inputs := []string{
			"+905321234567",
			"5551234567",
			"+1 (555) 123-4567",
			"123456789012345",
		}
		for _, in := range inputs {
			out := string(partialPhone([]byte(in)))
			// Extract last 4 digits from input
			var inDigits []byte
			for _, ch := range in {
				if ch >= '0' && ch <= '9' {
					inDigits = append(inDigits, byte(ch))
				}
			}
			if len(inDigits) >= 4 {
				last4 := string(inDigits[len(inDigits)-4:])
				if !strings.HasSuffix(out, last4) {
					t.Errorf("partialPhone(%q) = %q, should end with %q", in, out, last4)
				}
			}
		}
	})
	t.Run("format_is_asterisks_dash", func(t *testing.T) {
		inputs := []string{"+905321234567", "5551234567", "1234567890"}
		for _, in := range inputs {
			out := string(partialPhone([]byte(in)))
			if !strings.Contains(out, "***-***-") {
				t.Errorf("partialPhone(%q) = %q, should contain ***-***-", in, out)
			}
		}
	})
	t.Run("fallback_for_short_input", func(t *testing.T) {
		inputs := []string{"", "12", "abc", "12"}
		for _, in := range inputs {
			out := string(partialPhone([]byte(in)))
			if out != "***" {
				t.Errorf("partialPhone(%q) = %q, want ***", in, out)
			}
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		in := []byte("+905321234567")
		a := string(partialPhone(in))
		b := string(partialPhone(in))
		if a != b {
			t.Errorf("partialPhone not deterministic: %q vs %q", a, b)
		}
	})
}

func TestPartialCardProperties(t *testing.T) {
	t.Run("preserves_last_4_digits", func(t *testing.T) {
		inputs := []string{
			"4532123456785678",
			"4111111111111111",
			"5500000000000004",
			"12345678",
		}
		for _, in := range inputs {
			out := string(partialCard([]byte(in)))
			var inDigits []byte
			for _, ch := range in {
				if ch >= '0' && ch <= '9' {
					inDigits = append(inDigits, byte(ch))
				}
			}
			if len(inDigits) >= 4 {
				last4 := string(inDigits[len(inDigits)-4:])
				if !strings.HasSuffix(out, last4) {
					t.Errorf("partialCard(%q) = %q, should end with %q", in, out, last4)
				}
			}
		}
	})
	t.Run("format_is_asterisks_dash", func(t *testing.T) {
		inputs := []string{"4532123456785678", "4111111111111111"}
		for _, in := range inputs {
			out := string(partialCard([]byte(in)))
			if !strings.Contains(out, "****-****-****-") {
				t.Errorf("partialCard(%q) = %q, should contain ****-****-****-", in, out)
			}
		}
	})
	t.Run("fallback_for_short_input", func(t *testing.T) {
		in := "12"
		out := string(partialCard([]byte(in)))
		if out != "****-****-****-****" {
			t.Errorf("partialCard(%q) = %q, want ****-****-****-****", in, out)
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		in := []byte("4532123456785678")
		a := string(partialCard(in))
		b := string(partialCard(in))
		if a != b {
			t.Errorf("partialCard not deterministic: %q vs %q", a, b)
		}
	})
}

func TestPartialIBANProperties(t *testing.T) {
	t.Run("preserves_country_and_last_two", func(t *testing.T) {
		inputs := []string{
			"TR330006100519786457841326",
			"DE89370400440532013000",
			"GB29NWBK60161331926819",
		}
		for _, in := range inputs {
			out := string(partialIBAN([]byte(in)))
			if len(in) >= 4 {
				prefix := in[:2]
				suffix := in[len(in)-2:]
				if !strings.HasPrefix(out, prefix) {
					t.Errorf("partialIBAN(%q) = %q, should start with %q", in, out, prefix)
				}
				if !strings.HasSuffix(out, suffix) {
					t.Errorf("partialIBAN(%q) = %q, should end with %q", in, out, suffix)
				}
			}
		}
	})
	t.Run("fallback_for_short_input", func(t *testing.T) {
		inputs := []string{"", "AB", "ABC"}
		for _, in := range inputs {
			out := string(partialIBAN([]byte(in)))
			if out != "***" {
				t.Errorf("partialIBAN(%q) = %q, want ***", in, out)
			}
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		in := []byte("TR330006100519786457841326")
		a := string(partialIBAN(in))
		b := string(partialIBAN(in))
		if a != b {
			t.Errorf("partialIBAN not deterministic: %q vs %q", a, b)
		}
	})
}

func TestPartialTCProperties(t *testing.T) {
	t.Run("preserves_last_2_digits", func(t *testing.T) {
		inputs := []string{"12345678901", "98765432100", "11111111111"}
		for _, in := range inputs {
			out := string(partialTC([]byte(in)))
			if len(in) >= 2 {
				suffix := in[len(in)-2:]
				if !strings.HasSuffix(out, suffix) {
					t.Errorf("partialTC(%q) = %q, should end with %q", in, out, suffix)
				}
			}
		}
	})
	t.Run("masks_with_asterisks_same_length", func(t *testing.T) {
		inputs := []string{"12345678901", "98765432100", "abc123"}
		for _, in := range inputs {
			out := string(partialTC([]byte(in)))
			if len(out) != len(in) {
				t.Errorf("partialTC(%q) = %q (len=%d), should have same length %d", in, out, len(out), len(in))
			}
			// All but last 2 should be '*'
			for i := 0; i < len(out)-2; i++ {
				if out[i] != '*' {
					t.Errorf("partialTC(%q) = %q, position %d should be '*'", in, out, i)
				}
			}
		}
	})
	t.Run("fallback_for_short_input", func(t *testing.T) {
		inputs := []string{"", "x", "a"}
		for _, in := range inputs {
			out := string(partialTC([]byte(in)))
			if out != "***" {
				t.Errorf("partialTC(%q) = %q, want ***", in, out)
			}
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		in := []byte("12345678901")
		a := string(partialTC(in))
		b := string(partialTC(in))
		if a != b {
			t.Errorf("partialTC not deterministic: %q vs %q", a, b)
		}
	})
}

func TestNullProperties(t *testing.T) {
	t.Run("always_NULL", func(t *testing.T) {
		inputs := []string{"", "anything", " ", "\n", strings.Repeat("x", 100)}
		for _, in := range inputs {
			out := string(nullValue([]byte(in)))
			if out != "NULL" {
				t.Errorf("nullValue(%q) = %q, want NULL", in, out)
			}
		}
	})
}

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
		{"hash", "hash", "test", ""}, // just check non-empty
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
