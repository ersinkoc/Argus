package masking

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Transformer applies a masking transformation to a value.
type Transformer interface {
	Transform(value []byte) []byte
}

// TransformerFunc adapts a function to the Transformer interface.
type TransformerFunc func([]byte) []byte

func (f TransformerFunc) Transform(value []byte) []byte {
	return f(value)
}

// Registry holds all registered transformers.
var Registry = map[string]Transformer{
	"redact":        TransformerFunc(redact),
	"partial_email": TransformerFunc(partialEmail),
	"partial_phone": TransformerFunc(partialPhone),
	"partial_card":  TransformerFunc(partialCard),
	"partial_iban":  TransformerFunc(partialIBAN),
	"partial_tc":    TransformerFunc(partialTC),
	"hash":          TransformerFunc(hashValue),
	"null":          TransformerFunc(nullValue),
}

// GetTransformer returns a transformer by name.
func GetTransformer(name string) Transformer {
	if t, ok := Registry[name]; ok {
		return t
	}
	// Default to redact for unknown transformers
	return Registry["redact"]
}

// TransformerFrom builds a transformer for a masking rule, honoring parameters. The parametric
// transformers ("regex_replace", "partial") are constructed from options; every other name falls back
// to the fixed built-in registry via GetTransformer. Invalid or missing parameters degrade to redact
// (fail-safe) — never to a no-op that would leak the raw value.
func TransformerFrom(name string, options map[string]string) Transformer {
	switch name {
	case "regex_replace":
		return regexReplaceTransformer(options)
	case "partial":
		return partialTransformer(options)
	default:
		return GetTransformer(name)
	}
}

// regexReplaceTransformer replaces every match of options["pattern"] with options["replacement"]
// (Go regexp syntax; $1 group refs allowed). Empty or invalid pattern → redact.
func regexReplaceTransformer(options map[string]string) Transformer {
	pattern := options["pattern"]
	if pattern == "" {
		return TransformerFunc(redact)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return TransformerFunc(redact)
	}
	repl := []byte(options["replacement"])
	return TransformerFunc(func(value []byte) []byte {
		if len(value) == 0 {
			return value
		}
		return re.ReplaceAll(value, repl)
	})
}

// partialTransformer keeps the first options["keep_first"] and last options["keep_last"] characters
// visible and masks the middle with options["mask_char"] (default '*'). If the visible window would
// cover the whole value (or the value is shorter), it redacts instead — fail-safe on short values.
func partialTransformer(options map[string]string) Transformer {
	keepFirst := atoiOrZero(options["keep_first"])
	keepLast := atoiOrZero(options["keep_last"])
	if keepFirst < 0 {
		keepFirst = 0
	}
	if keepLast < 0 {
		keepLast = 0
	}
	maskChar := '*'
	if mc := options["mask_char"]; mc != "" {
		if r, _ := utf8.DecodeRuneInString(mc); r != utf8.RuneError {
			maskChar = r
		}
	}
	return TransformerFunc(func(value []byte) []byte {
		if len(value) == 0 {
			return value
		}
		runes := []rune(string(value))
		n := len(runes)
		if keepFirst+keepLast >= n {
			return []byte("***")
		}
		var b strings.Builder
		for i := 0; i < n; i++ {
			if i < keepFirst || i >= n-keepLast {
				b.WriteRune(runes[i])
			} else {
				b.WriteRune(maskChar)
			}
		}
		return []byte(b.String())
	})
}

// atoiOrZero parses s as an int, returning 0 on any error (including empty).
func atoiOrZero(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// RegisterTransformer registers a custom transformer.
func RegisterTransformer(name string, t Transformer) {
	Registry[name] = t
}

func redact(value []byte) []byte {
	if len(value) == 0 {
		return value
	}
	return []byte("***")
}

func partialEmail(value []byte) []byte {
	s := string(value)
	at := strings.Index(s, "@")
	if at <= 0 {
		return []byte("***")
	}
	// Keep first char + domain
	first, _ := utf8.DecodeRuneInString(s)
	return []byte(string(first) + "***" + s[at:])
}

func partialPhone(value []byte) []byte {
	s := string(value)
	// Extract only digits
	var digits []byte
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, byte(ch))
		}
	}
	if len(digits) < 4 {
		return []byte("***")
	}
	// Show last 4 digits
	last4 := string(digits[len(digits)-4:])
	return []byte("***-***-" + last4)
}

func partialCard(value []byte) []byte {
	s := string(value)
	var digits []byte
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, byte(ch))
		}
	}
	if len(digits) < 4 {
		return []byte("****-****-****-****")
	}
	last4 := string(digits[len(digits)-4:])
	return []byte("****-****-****-" + last4)
}

func partialIBAN(value []byte) []byte {
	s := string(value)
	if len(s) < 4 {
		return []byte("***")
	}
	// Keep first 2 chars (country) and last 2 digits
	prefix := s[:2]
	suffix := s[len(s)-2:]
	return []byte(prefix + "**-****-****-****-**" + suffix)
}

func partialTC(value []byte) []byte {
	s := string(value)
	if len(s) < 2 {
		return []byte("***")
	}
	// Show last 2 digits, mask rest
	last2 := s[len(s)-2:]
	masked := make([]byte, len(s))
	for i := 0; i < len(s)-2; i++ {
		masked[i] = '*'
	}
	copy(masked[len(s)-2:], last2)
	return masked
}

// hashValue returns a hex-encoded SHA-256 prefix (16 bytes = 32 hex chars).
// 128 bits provides a negligibly small collision probability
// (≈2⁻⁶⁴ at 64K values under the birthday bound).
// Downstream code must NOT depend on this length — it is an implementation detail.
func hashValue(value []byte) []byte {
	h := sha256.Sum256(value)
	return []byte(hex.EncodeToString(h[:16]))
}

func nullValue(value []byte) []byte {
	return []byte("NULL")
}
