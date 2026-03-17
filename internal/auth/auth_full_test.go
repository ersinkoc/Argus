package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestSSOValidateExpiredToken(t *testing.T) {
	// Build a valid JWT with expired timestamp
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := JWTClaims{
		Subject: "user1",
		Issuer:  "test",
		Expiry:  time.Now().Add(-time.Hour).Unix(), // expired
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.URLEncoding.EncodeToString(claimsJSON)
	// No real signature needed since we're not validating sig here
	token := header + "." + payload + "." + base64.URLEncoding.EncodeToString([]byte("fake"))

	p := NewSSOProvider(SSOConfig{}) // no secret = skip sig check
	_, err := p.ValidateToken(token)
	if err == nil {
		t.Error("expired token should fail")
	}
}

func TestSSOValidateIssuerMismatch(t *testing.T) {
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	claims := JWTClaims{Subject: "u", Issuer: "wrong", Expiry: time.Now().Add(time.Hour).Unix()}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.URLEncoding.EncodeToString(claimsJSON)
	token := header + "." + payload + "." + base64.URLEncoding.EncodeToString([]byte("x"))

	p := NewSSOProvider(SSOConfig{Issuer: "expected"})
	_, err := p.ValidateToken(token)
	if err == nil {
		t.Error("issuer mismatch should fail")
	}
}

func TestSSOValidateValidToken(t *testing.T) {
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	claims := JWTClaims{
		Subject: "alice",
		Issuer:  "argus",
		Expiry:  time.Now().Add(time.Hour).Unix(),
		Email:   "alice@test.com",
		Groups:  []string{"admin", "dev"},
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.URLEncoding.EncodeToString(claimsJSON)

	// Sign with HMAC-SHA256
	secret := "my-secret"
	sig := hmacSHA256([]byte(secret), []byte(header+"."+payload))
	sigB64 := base64.URLEncoding.EncodeToString(sig)

	token := header + "." + payload + "." + sigB64

	p := NewSSOProvider(SSOConfig{Secret: secret, Issuer: "argus"})
	result, err := p.ValidateToken(token)
	if err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if result.Subject != "alice" {
		t.Errorf("subject = %q", result.Subject)
	}
	if len(result.Groups) != 2 {
		t.Errorf("groups = %d", len(result.Groups))
	}
}

func TestSSOValidateWrongSignature(t *testing.T) {
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	claims := JWTClaims{Subject: "u", Expiry: time.Now().Add(time.Hour).Unix()}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.URLEncoding.EncodeToString(claimsJSON)
	token := header + "." + payload + "." + base64.URLEncoding.EncodeToString([]byte("wrong-sig"))

	p := NewSSOProvider(SSOConfig{Secret: "correct-secret"})
	_, err := p.ValidateToken(token)
	if err == nil {
		t.Error("wrong signature should fail")
	}
}

func TestBase64URLDecode(t *testing.T) {
	// Standard padding
	result, err := base64URLDecode(base64.URLEncoding.EncodeToString([]byte("test")))
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "test" {
		t.Errorf("result = %q", result)
	}

	// No padding (needs auto-pad)
	noPad := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte("hello world"))
	result, err = base64URLDecode(noPad)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != "hello world" {
		t.Errorf("no-pad result = %q", result)
	}
}

func TestLDAPProviderCustomFilter(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{
		Host:       "ldap.test.com",
		BaseDN:     "dc=test,dc=com",
		UserFilter: "(sAMAccountName=%s)",
	})
	dn := p.buildUserDN("john")
	if dn != "sAMAccountName=john,dc=test,dc=com" {
		t.Errorf("AD dn = %q", dn)
	}
}

func TestBEREncodeLargeValue(t *testing.T) {
	// Test length encoding for values > 127 bytes
	large := make([]byte, 200)
	encoded := berEncodeTLV(0x04, large)
	if encoded[0] != 0x04 {
		t.Error("tag should be 0x04")
	}
	if encoded[1] != 0x81 {
		t.Error("length should use 2-byte form for 200 bytes")
	}
	if encoded[2] != 200 {
		t.Errorf("length value = %d", encoded[2])
	}
}

func TestBEREncodeVeryLargeValue(t *testing.T) {
	large := make([]byte, 300)
	encoded := berEncodeTLV(0x04, large)
	if encoded[1] != 0x82 {
		t.Error("length should use 3-byte form for 300 bytes")
	}
}

func TestChainProviderWithLDAP(t *testing.T) {
	// LDAP to unreachable server — chain should fail
	ldap := NewLDAPProvider(LDAPConfig{Host: "127.0.0.1", Port: 1})
	chain := NewChainProvider(ldap)

	_, err := chain.Authenticate("user", "pass")
	if err == nil {
		t.Error("unreachable LDAP should fail")
	}
}

func TestBuildLDAPBindRequest(t *testing.T) {
	req := buildLDAPBindRequest(1, "cn=admin,dc=test", "password")
	if len(req) < 10 {
		t.Error("bind request too short")
	}
	// First byte should be SEQUENCE tag (0x30)
	if req[0] != 0x30 {
		t.Errorf("first byte = 0x%02x, want 0x30 (SEQUENCE)", req[0])
	}
}
