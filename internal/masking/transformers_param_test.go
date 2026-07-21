package masking

import (
	"testing"

	"github.com/ersinkoc/argus/internal/policy"
)

func TestRegexReplaceTransformer(t *testing.T) {
	t.Run("replaces_all_matches", func(t *testing.T) {
		tr := TransformerFrom("regex_replace", map[string]string{
			"pattern":     `\d`,
			"replacement": "#",
		})
		got := string(tr.Transform([]byte("ab12cd34")))
		if got != "ab##cd##" {
			t.Fatalf("got %q, want %q", got, "ab##cd##")
		}
	})

	t.Run("group_reference", func(t *testing.T) {
		tr := TransformerFrom("regex_replace", map[string]string{
			"pattern":     `(\d{4})\d+(\d{4})`,
			"replacement": "$1********$2",
		})
		got := string(tr.Transform([]byte("1234567890123456")))
		if got != "1234********3456" {
			t.Fatalf("got %q, want %q", got, "1234********3456")
		}
	})

	t.Run("empty_pattern_redacts", func(t *testing.T) {
		tr := TransformerFrom("regex_replace", map[string]string{"replacement": "x"})
		if got := string(tr.Transform([]byte("secret"))); got != "***" {
			t.Fatalf("empty pattern should redact, got %q", got)
		}
	})

	t.Run("invalid_pattern_redacts", func(t *testing.T) {
		tr := TransformerFrom("regex_replace", map[string]string{"pattern": `([`})
		if got := string(tr.Transform([]byte("secret"))); got != "***" {
			t.Fatalf("invalid pattern should redact, got %q", got)
		}
	})

	t.Run("empty_value_passthrough", func(t *testing.T) {
		tr := TransformerFrom("regex_replace", map[string]string{"pattern": `.`, "replacement": "x"})
		if got := tr.Transform([]byte("")); len(got) != 0 {
			t.Fatalf("empty value should pass through, got %q", got)
		}
	})
}

func TestPartialTransformer(t *testing.T) {
	t.Run("keeps_first_and_last", func(t *testing.T) {
		tr := TransformerFrom("partial", map[string]string{"keep_first": "2", "keep_last": "2"})
		got := string(tr.Transform([]byte("abcdefgh")))
		if got != "ab****gh" {
			t.Fatalf("got %q, want %q", got, "ab****gh")
		}
	})

	t.Run("keep_last_only", func(t *testing.T) {
		tr := TransformerFrom("partial", map[string]string{"keep_last": "4"})
		got := string(tr.Transform([]byte("1234567890")))
		if got != "******7890" {
			t.Fatalf("got %q, want %q", got, "******7890")
		}
	})

	t.Run("custom_mask_char", func(t *testing.T) {
		tr := TransformerFrom("partial", map[string]string{"keep_last": "2", "mask_char": "#"})
		got := string(tr.Transform([]byte("abcdef")))
		if got != "####ef" {
			t.Fatalf("got %q, want %q", got, "####ef")
		}
	})

	t.Run("window_covers_all_redacts", func(t *testing.T) {
		tr := TransformerFrom("partial", map[string]string{"keep_first": "3", "keep_last": "3"})
		if got := string(tr.Transform([]byte("abcd"))); got != "***" {
			t.Fatalf("over-wide window should redact, got %q", got)
		}
	})

	t.Run("negative_values_treated_as_zero", func(t *testing.T) {
		tr := TransformerFrom("partial", map[string]string{"keep_first": "-5", "keep_last": "-2"})
		got := string(tr.Transform([]byte("abc")))
		if got != "***" {
			t.Fatalf("got %q, want %q", got, "***")
		}
	})

	t.Run("utf8_safe", func(t *testing.T) {
		tr := TransformerFrom("partial", map[string]string{"keep_first": "1", "keep_last": "1"})
		got := string(tr.Transform([]byte("çağrı")))
		if got != "ç***ı" {
			t.Fatalf("got %q, want %q", got, "ç***ı")
		}
	})

	t.Run("empty_value_passthrough", func(t *testing.T) {
		tr := TransformerFrom("partial", map[string]string{"keep_last": "2"})
		if got := tr.Transform([]byte("")); len(got) != 0 {
			t.Fatalf("empty value should pass through, got %q", got)
		}
	})
}

func TestTransformerFromFallsBackToBuiltin(t *testing.T) {
	// A non-parametric name must resolve to the fixed built-in registry.
	tr := TransformerFrom("hash", nil)
	if got := string(tr.Transform([]byte("x"))); got == "x" || got == "" {
		t.Fatalf("expected hashed output, got %q", got)
	}
	// Unknown name → redact (via GetTransformer), never a no-op leak.
	unknown := TransformerFrom("does_not_exist", nil)
	if got := string(unknown.Transform([]byte("secret"))); got != "***" {
		t.Fatalf("unknown transformer should redact, got %q", got)
	}
}

// TestPipelineHonorsParametricOptions proves options flow end-to-end through the pipeline.
func TestPipelineHonorsParametricOptions(t *testing.T) {
	rules := []policy.MaskingRule{{
		Column:      "card",
		Transformer: "partial",
		Options:     map[string]string{"keep_last": "4"},
	}}
	cols := []ColumnInfo{{Name: "card", Index: 0}}
	p := NewPipeline(rules, cols, 0)

	out, ok := p.ProcessRow([]FieldValue{{Data: []byte("1234567890123456")}})
	if !ok {
		t.Fatal("row unexpectedly dropped")
	}
	if got := string(out[0].Data); got != "************3456" {
		t.Fatalf("got %q, want %q", got, "************3456")
	}
}

// TestPipelineRowCapWithoutMasking proves max_rows is enforced even when no column is masked.
func TestPipelineRowCapWithoutMasking(t *testing.T) {
	cols := []ColumnInfo{{Name: "id", Index: 0}}
	p := NewPipeline(nil, cols, 2) // no masking rules, cap = 2

	if !p.Active() {
		t.Fatal("a row-limit-only pipeline must report Active()")
	}
	if p.HasMasking() {
		t.Fatal("a row-limit-only pipeline must not report masking")
	}

	kept := 0
	for i := 0; i < 5; i++ {
		if _, ok := p.ProcessRow([]FieldValue{{Data: []byte("x")}}); ok {
			kept++
		}
	}
	if kept != 2 {
		t.Fatalf("expected 2 rows kept under cap, got %d", kept)
	}
}
