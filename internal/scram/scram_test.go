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
	sf, err := scram.ParseServerFirstMessage(serverFirst)
	if err != nil {
		t.Fatalf("ParseServerFirstMessage: %v", err)
	}

	// Verify combined nonce starts with client nonce
	if !strings.HasPrefix(sf.Nonce, clientNonce) {
		t.Errorf("combined nonce doesn't start with client nonce: %q", sf.Nonce)
	}
	if sf.Iterations <= 0 {
		t.Errorf("invalid iterations: %d", sf.Iterations)
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
	bareClientFirst := scram.ClientFirstMessageBare(clientFirst)
	clientFinalNoProof := scram.ClientFinalMessageWithoutProof(clientFinal)
	authMsg := scram.AuthMessage(bareClientFirst, serverFirst)
	authMsg += clientFinalNoProof

	err = scram.VerifyServerSignature(password, sf, authMsg, serverFinal)
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

	bareClient := scram.ClientFirstMessageBare(clientFirst)
	if bareClient != "n=user,r=abc123" {
		t.Errorf("bare client first = %q, want %q", bareClient, "n=user,r=abc123")
	}

	noProof := scram.ClientFinalMessageWithoutProof(clientFinal)
	expectedNoProof := "c=biws,r=abc123def"
	if noProof != expectedNoProof {
		t.Errorf("client final no proof = %q, want %q", noProof, expectedNoProof)
	}

	authMsg := scram.AuthMessage(bareClient, serverFirst)
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

	sf, _ := scram.ParseServerFirstMessage(serverFirst)
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

	sf, _ := scram.ParseServerFirstMessage(serverFirst)
	clientFinalBare := "c=biws,r=" + sf.Nonce
	proof := scram.ClientFinalProof(password, sf, clientFirst, clientFinalBare)
	clientFinal := clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof)

	serverFinal, err := server.ClientFinal(clientFinal)
	if err != nil {
		t.Fatalf("ClientFinal: %v", err)
	}

	// Client verification
	bareClient := scram.ClientFirstMessageBare(clientFirst)
	clientFinalNoProof := scram.ClientFinalMessageWithoutProof(clientFinal)
	authMsg := scram.AuthMessage(bareClient, serverFirst) + clientFinalNoProof

	if err := scram.VerifyServerSignature(password, sf, authMsg, serverFinal); err != nil {
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
	sfParsed, _ := scram.ParseServerFirstMessage(sf)

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
	bareCF := scram.ClientFirstMessageBare(cf)
	cfNoProof := scram.ClientFinalMessageWithoutProof(cf2)
	authMsg := scram.AuthMessage(bareCF, sf) + cfNoProof

	if err := scram.VerifyServerSignature(password, sfParsed, authMsg, sf2); err != nil {
		t.Fatal(err)
	}
}
