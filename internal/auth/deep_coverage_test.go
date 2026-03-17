package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// --- SSO ExtractUsername all claims ---

func TestSSOExtractUsernameEmail(t *testing.T) {
	p := NewSSOProvider(SSOConfig{UsernameClaim: "email"})
	claims := &JWTClaims{Subject: "sub", Email: "alice@test.com"}
	if got := p.ExtractUsername(claims); got != "alice@test.com" {
		t.Errorf("got %q, want alice@test.com", got)
	}
}

func TestSSOExtractUsernamePreferred(t *testing.T) {
	p := NewSSOProvider(SSOConfig{UsernameClaim: "preferred_username"})
	claims := &JWTClaims{Subject: "sub", Username: "alice"}
	if got := p.ExtractUsername(claims); got != "alice" {
		t.Errorf("got %q, want alice", got)
	}
}

func TestSSOExtractUsernameSub(t *testing.T) {
	p := NewSSOProvider(SSOConfig{UsernameClaim: "sub"})
	claims := &JWTClaims{Subject: "user123"}
	if got := p.ExtractUsername(claims); got != "user123" {
		t.Errorf("got %q, want user123", got)
	}
}

// --- SSO ExtractGroups ---

func TestSSOExtractGroupsFromGroups(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})
	claims := &JWTClaims{Groups: []string{"admin", "dev"}}
	groups := p.ExtractGroups(claims)
	if len(groups) != 2 {
		t.Errorf("groups = %d", len(groups))
	}
}

func TestSSOExtractGroupsFromRoles(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})
	claims := &JWTClaims{Roles: []string{"reader"}}
	groups := p.ExtractGroups(claims)
	if len(groups) != 1 || groups[0] != "reader" {
		t.Errorf("groups = %v", groups)
	}
}

func TestSSOExtractGroupsEmpty(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})
	claims := &JWTClaims{}
	groups := p.ExtractGroups(claims)
	if len(groups) != 0 {
		t.Errorf("groups = %v", groups)
	}
}

// --- SSO ValidateToken edge cases ---

func TestSSOValidateTokenInvalidParts(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})
	_, err := p.ValidateToken("only.two")
	if err == nil {
		t.Error("2-part token should fail")
	}
	_, err = p.ValidateToken("single")
	if err == nil {
		t.Error("1-part token should fail")
	}
}

func TestSSOValidateTokenInvalidPayload(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})
	// Valid-ish header, garbage payload, garbage sig
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	token := header + ".!!!invalid!!!." + base64.URLEncoding.EncodeToString([]byte("x"))
	_, err := p.ValidateToken(token)
	if err == nil {
		t.Error("invalid payload encoding should fail")
	}
}

func TestSSOValidateTokenInvalidJSON(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.URLEncoding.EncodeToString([]byte(`not json`))
	token := header + "." + payload + "." + base64.URLEncoding.EncodeToString([]byte("x"))
	_, err := p.ValidateToken(token)
	if err == nil {
		t.Error("invalid JSON claims should fail")
	}
}

func TestSSOValidateTokenInvalidSignatureEncoding(t *testing.T) {
	p := NewSSOProvider(SSOConfig{Secret: "mysecret"})
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	claims := JWTClaims{Subject: "u", Expiry: time.Now().Add(time.Hour).Unix()}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.URLEncoding.EncodeToString(claimsJSON)
	// Invalid base64 in signature
	token := header + "." + payload + ".!!!invalid-base64!!!"
	_, err := p.ValidateToken(token)
	if err == nil {
		t.Error("invalid signature encoding should fail")
	}
}

func TestSSOValidateTokenNoExpiry(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})
	header := base64.URLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims := JWTClaims{Subject: "user1"} // no expiry
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.URLEncoding.EncodeToString(claimsJSON)
	token := header + "." + payload + "." + base64.URLEncoding.EncodeToString([]byte("x"))

	result, err := p.ValidateToken(token)
	if err != nil {
		t.Fatalf("no-expiry token: %v", err)
	}
	if result.Subject != "user1" {
		t.Errorf("subject = %q", result.Subject)
	}
}

// --- base64URLDecode padding variants ---

func TestBase64URLDecodePadding2(t *testing.T) {
	// len(s) % 4 == 2 → needs "=="
	raw := "ab"
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(raw))
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != raw {
		t.Errorf("decoded = %q", decoded)
	}
}

func TestBase64URLDecodePadding3(t *testing.T) {
	// len(s) % 4 == 3 → needs "="
	raw := "abc"
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(raw))
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != raw {
		t.Errorf("decoded = %q", decoded)
	}
}

func TestBase64URLDecodeNoPadNeeded(t *testing.T) {
	// len(s) % 4 == 0 → no padding
	raw := "test"
	encoded := base64.URLEncoding.EncodeToString([]byte(raw))
	decoded, err := base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != raw {
		t.Errorf("decoded = %q", decoded)
	}
}

// --- LDAP provider ---

func TestLDAPProviderPort(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{Host: "ldap.test.com", Port: 636, BaseDN: "dc=example,dc=com"})
	if p.cfg.Port != 636 {
		t.Errorf("port = %d", p.cfg.Port)
	}
}

func TestBuildUserDNDefault(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{BaseDN: "dc=test,dc=com"})
	dn := p.buildUserDN("alice")
	if dn != "uid=alice,dc=test,dc=com" {
		t.Errorf("dn = %q", dn)
	}
}

func TestBuildUserDNWithFilter(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{BaseDN: "dc=test,dc=com", UserFilter: "(cn=%s)"})
	dn := p.buildUserDN("bob")
	if dn != "cn=bob,dc=test,dc=com" {
		t.Errorf("dn = %q", dn)
	}
}

// --- parseLDAPResultCode edge cases ---

func TestParseLDAPResultCodeShort(t *testing.T) {
	code := parseLDAPResultCode([]byte{1, 2})
	if code != -1 {
		t.Errorf("short data should return -1, got %d", code)
	}
}

func TestParseLDAPResultCodeNil(t *testing.T) {
	code := parseLDAPResultCode(nil)
	if code != -1 {
		t.Errorf("nil should return -1, got %d", code)
	}
}

// --- NewChainProvider ---

func TestChainProviderEmpty(t *testing.T) {
	chain := NewChainProvider()
	result, err := chain.Authenticate("user", "pass")
	// Empty chain returns nil result and nil error
	if err != nil {
		t.Errorf("empty chain error: %v", err)
	}
	if result != nil {
		t.Error("empty chain should return nil result")
	}
}
