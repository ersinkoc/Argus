package masking

import (
	"crypto/sha256"
	"encoding/hex"
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
	// Show last 2 digits
	last2 := s[len(s)-2:]
	masked := strings.Repeat("*", len(s)-2) + last2
	return []byte(masked)
}

func hashValue(value []byte) []byte {
	h := sha256.Sum256(value)
	return []byte(hex.EncodeToString(h[:4])) // first 8 hex chars
}

func nullValue(value []byte) []byte {
	return []byte("NULL")
}
