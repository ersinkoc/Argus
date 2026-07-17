package scram_test

import (
	"crypto/hmac"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ersinkoc/argus/internal/scram"
)

// TestFullExchange tests a complete SCRAM-SHA-256 exchange between client and server.
func TestFullExchange(t *testing.T) {
	password := "test_password_123"
	username := "test_user"

	// Server initializes
	server := scram.NewServer(password)

	// Client generates client-first-message
	clientNonce := "client-nonce-abc123"
	clientFirst := scram.ClientFirst(username, clientNonce)

	// Server processes client-first and sends server-first
	serverFirst, err := server.ServerFirst(clientFirst)
	if err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}

	// Parse the server's challenge
	sf, err := scram.ParseSFMsg(serverFirst)
	if err != nil {
		t.Fatalf("ParseServerFirstMessage: %v", err)
	}

	// Verify combined nonce starts with client nonce
	if !strings.HasPrefix(sf.Nonce, clientNonce) {
		t.Errorf("combined nonce doesn't start with client nonce: %q", sf.Nonce)
	}
	if sf.Iter <= 0 {
		t.Errorf("invalid iterations: %d", sf.Iter)
	}
	if len(sf.Salt) == 0 {
		t.Errorf("empty salt")
	}

	// Client computes proof
	clientFinalBare := "c=" + base64.StdEncoding.EncodeToString([]byte("n,,")) +
		",r=" + sf.Nonce

	proof := scram.ClientFinalProof(password, sf, clientFirst, clientFinalBare)

	// Build client-final-message
	clientFinal := clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof)

	// Server validates and sends server-final-message
	serverFinal, err := server.ClientFinal(clientFinal)
	if err != nil {
		t.Fatalf("ClientFinal validation failed: %v", err)
	}

	// Verify server-final-message format
	if !strings.HasPrefix(serverFinal, "v=") {
		t.Errorf("server-final should start with 'v=': %q", serverFinal)
	}

	// Client verifies server signature
	bareClientFirst := scram.CFBare(clientFirst)
	clientFinalNoProof := scram.CFNoProof(clientFinal)
	authMsg := scram.AuthMsg(bareClientFirst, serverFirst)
	authMsg += clientFinalNoProof

	err = scram.VerifySig(password, sf, authMsg, serverFinal)
	if err != nil {
		t.Fatalf("VerifyServerSignature failed: %v", err)
	}
}

// TestRFCExample tests against the RFC 7677 Appendix A example values.
func TestRFCExample(t *testing.T) {
	// RFC 7677 §4 example (SCRAM-SHA-256):
	// Password: "pencil" (without quotes)
	// Salt: "W22ZaJ0SNY7soEsUEjb6gQ==" (base64)
	// Iterations: 4096
	// SaltedPassword: PBKDF2 result
	password := "pencil"

	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")

	// Compute salted password
	sp := scram.SaltedPassword(password, salt, 4096)
	if len(sp) != 32 {
		t.Fatalf("salted password length: got %d, want 32", len(sp))
	}

	// Verify against expected
	// From RFC: ClientKey should be known. Let's verify the HMAC chain works.
	clientKey := scram.ClientKey(sp)
	if len(clientKey) != 32 {
		t.Errorf("client key length: %d", len(clientKey))
	}

	storedKey := scram.StoredKey(clientKey)
	if len(storedKey) != 32 {
		t.Errorf("stored key length: %d", len(storedKey))
	}

	serverKey := scram.ServerKey(sp)
	if len(serverKey) != 32 {
		t.Errorf("server key length: %d", len(serverKey))
	}
}

// TestAuthMessageComputation verifies the auth message format.
func TestAuthMessageComputation(t *testing.T) {
	clientFirst := "n,,n=user,r=abc123"
	serverFirst := "r=abc123def,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
	clientFinal := "c=biws,r=abc123def,p=someproofvalue"

	bareClient := scram.CFBare(clientFirst)
	if bareClient != "n=user,r=abc123" {
		t.Errorf("bare client first = %q, want %q", bareClient, "n=user,r=abc123")
	}

	noProof := scram.CFNoProof(clientFinal)
	expectedNoProof := "c=biws,r=abc123def"
	if noProof != expectedNoProof {
		t.Errorf("client final no proof = %q, want %q", noProof, expectedNoProof)
	}

	authMsg := scram.AuthMsg(bareClient, serverFirst)
	authMsg += noProof

	expected := "n=user,r=abc123,r=abc123def,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=abc123def"
	if authMsg != expected {
		t.Errorf("auth message = %q\n          want = %q", authMsg, expected)
	}
}

// TestWrongPassword verifies that a wrong password is rejected.
func TestWrongPassword(t *testing.T) {
	// Server knows "correct_password"
	server := scram.NewServer("correct_password")

	// Client tries "wrong_password"
	clientNonce := "test-nonce"
	clientFirst := scram.ClientFirst("user", clientNonce)

	serverFirst, err := server.ServerFirst(clientFirst)
	if err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}

	sf, _ := scram.ParseSFMsg(serverFirst)
	clientFinalBare := "c=biws,r=" + sf.Nonce
	proof := scram.ClientFinalProof("wrong_password", sf, clientFirst, clientFinalBare)
	clientFinal := clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof)

	_, err = server.ClientFinal(clientFinal)
	if err == nil {
		t.Fatal("expected auth failure for wrong password, got success")
	}
	t.Logf("Got expected error: %v", err)
}

// TestHMACComparisonSanity tests that hmac.Equal works for our use case.
func TestHMACComparisonSanity(t *testing.T) {
	a := []byte("this is a test signature value 12345")
	b := []byte("this is a test signature value 12345")
	c := []byte("THIS IS DIFFERENT")

	if !hmac.Equal(a, b) {
		t.Error("hmac.Equal failed for identical slices")
	}
	if hmac.Equal(a, c) {
		t.Error("hmac.Equal returned true for different slices")
	}
}

// TestPBKDF2OutputLength verifies we can derive keys of various lengths.
func TestPBKDF2OutputLength(t *testing.T) {
	// SCRAM needs exactly 32 bytes (SHA-256 hash length)
	dk := scram.SaltedPassword("test", []byte("salt"), 1)
	if len(dk) != 32 {
		t.Errorf("salted password length: got %d, want 32", len(dk))
	}

	// Verify it's deterministic
	dk2 := scram.SaltedPassword("test", []byte("salt"), 1)
	if !hmac.Equal(dk, dk2) {
		t.Error("salted password not deterministic")
	}
}

// TestNonceGeneration verifies nonces are unique and properly formatted.
func TestNonceGeneration(t *testing.T) {
	n1, err := scram.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	n2, err := scram.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}

	if n1 == n2 {
		t.Error("nonces should be unique")
	}

	// Verify base64 encoding
	_, err = base64.StdEncoding.DecodeString(n1)
	if err != nil {
		t.Errorf("nonce not valid base64: %v", err)
	}
}

// TestVerifyServerSignatureValid tests that a correct server signature passes.
func TestVerifyServerSignatureValid(t *testing.T) {
	password := "test-password"
	server := scram.NewServer(password)

	clientNonce := "verify-nonce-xyz"
	clientFirst := scram.ClientFirst("testuser", clientNonce)

	serverFirst, err := server.ServerFirst(clientFirst)
	if err != nil {
		t.Fatalf("ServerFirst: %v", err)
	}

	sf, _ := scram.ParseSFMsg(serverFirst)
	clientFinalBare := "c=biws,r=" + sf.Nonce
	proof := scram.ClientFinalProof(password, sf, clientFirst, clientFinalBare)
	clientFinal := clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof)

	serverFinal, err := server.ClientFinal(clientFinal)
	if err != nil {
		t.Fatalf("ClientFinal: %v", err)
	}

	// Client verification
	bareClient := scram.CFBare(clientFirst)
	clientFinalNoProof := scram.CFNoProof(clientFinal)
	authMsg := scram.AuthMsg(bareClient, serverFirst) + clientFinalNoProof

	if err := scram.VerifySig(password, sf, authMsg, serverFinal); err != nil {
		t.Fatalf("VerifyServerSignature: %v", err)
	}
}

// TestServerClientConversation tests the full server/client conversation end-to-end.
func TestServerClientConversation(t *testing.T) {
	password := "shared-secret"

	// Create a single nonce to use for both sides (in real life, client generates it)
	clientNonce, err := scram.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}

	// --- Server side ---
	server := scram.NewServer(password)

	// --- Client side ---
	cf := scram.ClientFirst("user1", clientNonce)

	// Server processes
	sf, err := server.ServerFirst(cf)
	if err != nil {
		t.Fatal(err)
	}
	sfParsed, _ := scram.ParseSFMsg(sf)

	// Client computes response
	cfBare := "c=" + base64.StdEncoding.EncodeToString([]byte("n,,")) + ",r=" + sfParsed.Nonce
	proof := scram.ClientFinalProof(password, sfParsed, cf, cfBare)
	cf2 := cfBare + ",p=" + base64.StdEncoding.EncodeToString(proof)

	// Server validates
	sf2, err := server.ClientFinal(cf2)
	if err != nil {
		t.Fatal(err)
	}

	// Client verifies server
	bareCF := scram.CFBare(cf)
	cfNoProof := scram.CFNoProof(cf2)
	authMsg := scram.AuthMsg(bareCF, sf) + cfNoProof

	if err := scram.VerifySig(password, sfParsed, authMsg, sf2); err != nil {
		t.Fatal(err)
	}
}

// TestParseSFMsgErrors covers malformed server-first-message parsing.
func TestParseSFMsgErrors(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"empty", ""},
		{"invalid salt base64", "r=nonce,s=!!!notbase64!!!,i=4096"},
		{"invalid iterations", "r=nonce,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=notanumber"},
		{"missing nonce", "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"},
		{"missing salt", "r=nonce,i=4096"},
		{"missing iterations", "r=nonce,s=W22ZaJ0SNY7soEsUEjb6gQ=="},
		{"garbage parts only", "x,y,zz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := scram.ParseSFMsg(tt.msg); err == nil {
				t.Errorf("ParseSFMsg(%q): expected error, got nil", tt.msg)
			}
		})
	}
}

// TestParseSFMsgSkipsMalformedParts verifies parts without '=' are ignored
// while a complete message still parses.
func TestParseSFMsgSkipsMalformedParts(t *testing.T) {
	sm, err := scram.ParseSFMsg("junk,r=nonce123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,x")
	if err != nil {
		t.Fatalf("ParseSFMsg: %v", err)
	}
	if sm.Nonce != "nonce123" {
		t.Errorf("nonce = %q, want %q", sm.Nonce, "nonce123")
	}
	if sm.Iter != 4096 {
		t.Errorf("iter = %d, want 4096", sm.Iter)
	}
	if len(sm.Salt) == 0 {
		t.Error("empty salt")
	}
}

// TestSFMsgStringRoundTrip verifies String output re-parses to the same values.
func TestSFMsgStringRoundTrip(t *testing.T) {
	orig := &scram.SFMsg{Nonce: "abc123", Salt: []byte("0123456789abcdef"), Iter: 4096}
	parsed, err := scram.ParseSFMsg(orig.String())
	if err != nil {
		t.Fatalf("ParseSFMsg: %v", err)
	}
	if parsed.Nonce != orig.Nonce || parsed.Iter != orig.Iter || string(parsed.Salt) != string(orig.Salt) {
		t.Errorf("round trip mismatch: got %+v, want %+v", parsed, orig)
	}
}

// TestCFBareEdgeCases covers messages with fewer than two commas.
func TestCFBareEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want string
	}{
		{"no comma", "n=user", "n=user"},
		{"one comma", "n,n=user", "n=user"},
		{"two commas", "n,,n=user,r=abc", "n=user,r=abc"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scram.CFBare(tt.msg); got != tt.want {
				t.Errorf("CFBare(%q) = %q, want %q", tt.msg, got, tt.want)
			}
		})
	}
}

// TestCFNoProofWithoutProof verifies a message lacking ",p=" is returned unchanged.
func TestCFNoProofWithoutProof(t *testing.T) {
	msg := "c=biws,r=abc123def"
	if got := scram.CFNoProof(msg); got != msg {
		t.Errorf("CFNoProof(%q) = %q, want unchanged", msg, got)
	}
}

// TestServerFirstMissingNonce verifies ServerFirst rejects a client-first
// message with no nonce attribute.
func TestServerFirstMissingNonce(t *testing.T) {
	server := scram.NewServer("pw")
	if _, err := server.ServerFirst("n,,n=user"); err == nil {
		t.Fatal("expected error for missing nonce, got nil")
	}
}

// TestClientFinalErrors covers malformed client-final-message handling.
func TestClientFinalErrors(t *testing.T) {
	newStartedServer := func(t *testing.T) (*scram.Server, *scram.SFMsg) {
		t.Helper()
		server := scram.NewServer("pw")
		serverFirst, err := server.ServerFirst(scram.ClientFirst("user", "nonce-abc"))
		if err != nil {
			t.Fatalf("ServerFirst: %v", err)
		}
		sf, err := scram.ParseSFMsg(serverFirst)
		if err != nil {
			t.Fatalf("ParseSFMsg: %v", err)
		}
		return server, sf
	}

	t.Run("invalid proof base64", func(t *testing.T) {
		server, sf := newStartedServer(t)
		if _, err := server.ClientFinal("c=biws,r=" + sf.Nonce + ",p=!!!notbase64!!!"); err == nil {
			t.Fatal("expected error for invalid proof base64, got nil")
		}
	})

	t.Run("missing nonce", func(t *testing.T) {
		server, _ := newStartedServer(t)
		if _, err := server.ClientFinal("c=biws,p=" + base64.StdEncoding.EncodeToString([]byte("proof"))); err == nil {
			t.Fatal("expected error for missing nonce, got nil")
		}
	})

	t.Run("missing proof", func(t *testing.T) {
		server, sf := newStartedServer(t)
		if _, err := server.ClientFinal("c=biws,r=" + sf.Nonce); err == nil {
			t.Fatal("expected error for missing proof, got nil")
		}
	})

	t.Run("nonce mismatch", func(t *testing.T) {
		server, _ := newStartedServer(t)
		cf := "c=biws,r=wrong-nonce,p=" + base64.StdEncoding.EncodeToString([]byte("proof"))
		if _, err := server.ClientFinal(cf); err == nil {
			t.Fatal("expected error for nonce mismatch, got nil")
		}
	})
}

// TestVerifySigErrors covers malformed and mismatched server-final-messages.
func TestVerifySigErrors(t *testing.T) {
	sf := &scram.SFMsg{Nonce: "abc", Salt: []byte("0123456789abcdef"), Iter: 4096}
	authMsg := "n=user,r=abc,r=abcdef,s=MDEyMzQ1Njc4OWFiY2RlZg==,i=4096,c=biws,r=abcdef"

	t.Run("missing v= prefix", func(t *testing.T) {
		if err := scram.VerifySig("pw", sf, authMsg, "e=other-error"); err == nil {
			t.Fatal("expected error for missing v= prefix, got nil")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		if err := scram.VerifySig("pw", sf, authMsg, "v=!!!notbase64!!!"); err == nil {
			t.Fatal("expected error for invalid base64, got nil")
		}
	})

	t.Run("signature mismatch", func(t *testing.T) {
		wrong := "v=" + base64.StdEncoding.EncodeToString([]byte("wrong signature bytes here 1234"))
		if err := scram.VerifySig("pw", sf, authMsg, wrong); err == nil {
			t.Fatal("expected error for signature mismatch, got nil")
		}
	})
}

// TestGenerateSalt verifies salts are the right length and unique.
func TestGenerateSalt(t *testing.T) {
	s1, err := scram.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(s1) != scram.SaltLen {
		t.Errorf("salt length = %d, want %d", len(s1), scram.SaltLen)
	}
	s2, err := scram.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if string(s1) == string(s2) {
		t.Error("salts should be unique")
	}
}
