package inspection

import "testing"

func TestFingerprintHashFromCommand(t *testing.T) {
	cmd := Classify("SELECT * FROM users WHERE id = 42")
	hash := FingerprintHashFromCommand(cmd)
	if hash == "" {
		t.Fatal("hash should not be empty")
	}

	// Same SQL should produce same hash
	cmd2 := Classify("SELECT * FROM users WHERE id = 99")
	hash2 := FingerprintHashFromCommand(cmd2)
	if hash != hash2 {
		t.Error("different literal values should produce same fingerprint hash")
	}

	// Different structure should produce different hash
	cmd3 := Classify("SELECT name FROM orders WHERE total > 100")
	hash3 := FingerprintHashFromCommand(cmd3)
	if hash == hash3 {
		t.Error("different query structure should produce different hash")
	}

	// Command without tokens should fall back to Fingerprint()
	cmd4 := &Command{Raw: "SELECT 1"}
	cmd4.Tokens = nil
	hash4 := FingerprintHashFromCommand(cmd4)
	if hash4 == "" {
		t.Fatal("hash should work even without cached tokens")
	}
}

func TestFingerprintFromTokens(t *testing.T) {
	tokens := NewTokenizer("SELECT * FROM users WHERE id = 42").Tokenize()
	fp := fingerprintFromTokens(tokens)
	if fp == "" {
		t.Fatal("fingerprint should not be empty")
	}
	if fp != Fingerprint("SELECT * FROM users WHERE id = 42") {
		t.Error("fingerprintFromTokens should match Fingerprint")
	}
}
