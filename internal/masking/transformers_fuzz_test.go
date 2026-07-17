package masking

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzSeeds are shared starting points covering the shapes each transformer
// special-cases: empty, short, unicode, separators, and realistic values.
var fuzzSeeds = []string{
	"",
	"a",
	"@",
	"a@",
	"@example.com",
	"john.doe@example.com",
	"çağrı@örnek.com",
	"+90 532 123 45 67",
	"123",
	"4532-1234-5678-5678",
	"TR330006100519786457841326",
	"12345678901",
	"NULL",
	"***",
	"\x00\xff\xfe",
	strings.Repeat("9", 64),
}

func digitsOf(s string) string {
	var b strings.Builder
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// FuzzTransformerInvariants runs every registered built-in transformer over
// arbitrary input and asserts the masking guarantees each one advertises.
func FuzzTransformerInvariants(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		value := []byte(s)

		if got := redact(value); len(s) != 0 && string(got) != "***" {
			t.Errorf("redact(%q) = %q, want ***", s, got)
		}

		if got := nullValue(value); string(got) != "NULL" {
			t.Errorf("null(%q) = %q, want NULL", s, got)
		}

		hashed := hashValue(value)
		if len(hashed) != 32 {
			t.Errorf("hash(%q) length = %d, want 32 hex chars", s, len(hashed))
		}
		if !bytes.Equal(hashed, hashValue(value)) {
			t.Errorf("hash(%q) is not deterministic", s)
		}

		email := string(partialEmail(value))
		if at := strings.Index(s, "@"); at <= 0 {
			if email != "***" {
				t.Errorf("partial_email(%q) = %q, want ***", s, email)
			}
		} else {
			// The transformer's contract: keep the first rune and the domain,
			// replace the rest of the local part with a fixed mask.
			first, _ := utf8.DecodeRuneInString(s)
			if want := string(first) + "***" + s[at:]; email != want {
				t.Errorf("partial_email(%q) = %q, want %q", s, email, want)
			}
		}

		phone := string(partialPhone(value))
		if digits := digitsOf(s); len(digits) < 4 {
			if phone != "***" {
				t.Errorf("partial_phone(%q) = %q, want ***", s, phone)
			}
		} else if want := "***-***-" + digits[len(digits)-4:]; phone != want {
			t.Errorf("partial_phone(%q) = %q, want %q", s, phone, want)
		}

		card := string(partialCard(value))
		if digits := digitsOf(s); len(digits) < 4 {
			if card != "****-****-****-****" {
				t.Errorf("partial_card(%q) = %q, want fully masked", s, card)
			}
		} else if want := "****-****-****-" + digits[len(digits)-4:]; card != want {
			t.Errorf("partial_card(%q) = %q, want %q", s, card, want)
		}

		iban := string(partialIBAN(value))
		if len(s) < 4 {
			if iban != "***" {
				t.Errorf("partial_iban(%q) = %q, want ***", s, iban)
			}
		} else if want := s[:2] + "**-****-****-****-**" + s[len(s)-2:]; iban != want {
			t.Errorf("partial_iban(%q) = %q, want %q", s, iban, want)
		}

		tc := string(partialTC(value))
		if len(s) < 2 {
			if tc != "***" {
				t.Errorf("partial_tc(%q) = %q, want ***", s, tc)
			}
		} else {
			if len(tc) != len(s) {
				t.Errorf("partial_tc(%q) length = %d, want %d", s, len(tc), len(s))
			}
			if !strings.HasSuffix(tc, s[len(s)-2:]) {
				t.Errorf("partial_tc(%q) = %q, should keep last 2 bytes", s, tc)
			}
			if masked := tc[:len(tc)-2]; masked != strings.Repeat("*", len(masked)) {
				t.Errorf("partial_tc(%q) = %q, prefix should be all stars", s, tc)
			}
		}
	})
}

// FuzzRegistryTransformersDoNotEchoInput checks that no built-in transformer
// returns a plain alphanumeric value longer than 4 bytes unchanged — masking
// must mask. (Inputs that already look masked, e.g. "***45", legitimately
// survive partial_tc unchanged, so the property is restricted to values that
// actually carry information.)
func FuzzRegistryTransformersDoNotEchoInput(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) <= 4 || s == "NULL" {
			return
		}
		for _, ch := range []byte(s) {
			isDigit := ch >= '0' && ch <= '9'
			isLower := ch >= 'a' && ch <= 'z'
			isUpper := ch >= 'A' && ch <= 'Z'
			if !isDigit && !isLower && !isUpper {
				return
			}
		}
		for name, tr := range Registry {
			if got := tr.Transform([]byte(s)); string(got) == s {
				t.Errorf("%s(%q) returned the input unchanged", name, s)
			}
		}
	})
}
