package inspection

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Fingerprint normalizes a SQL query into a canonical form for pattern matching.
// It replaces all literals with '?' and normalizes whitespace,
// producing a stable string that represents the query structure.
//
// Examples:
//
//	"SELECT * FROM users WHERE id = 42"     → "SELECT * FROM users WHERE id = ?"
//	"SELECT * FROM users WHERE name = 'Jo'" → "SELECT * FROM users WHERE name = ?"
//	"INSERT INTO t (a,b) VALUES (1, 'x')"  → "INSERT INTO t (a,b) VALUES (?, ?)"
func Fingerprint(sql string) string {
	tokenizer := NewTokenizer(sql)
	tokens := tokenizer.Tokenize()

	var parts []string
	for _, tok := range tokens {
		switch tok.Type {
		case TokenLiteral:
			parts = append(parts, "?")
		case TokenComment:
			// Strip comments from fingerprint
			continue
		case TokenKeyword:
			parts = append(parts, tok.Upper)
		case TokenIdentifier:
			parts = append(parts, tok.Value)
		default:
			parts = append(parts, tok.Value)
		}
	}

	return strings.Join(parts, " ")
}

// FingerprintHash returns a short hash of the fingerprint for use as a cache/grouping key.
func FingerprintHash(sql string) string {
	fp := Fingerprint(sql)
	h := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(h[:8])
}
