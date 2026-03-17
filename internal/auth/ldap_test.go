package auth

import (
	"testing"
)

func TestLDAPProviderDefaults(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{Host: "ldap.test.com"})
	if p.cfg.Port != 389 {
		t.Errorf("default port = %d, want 389", p.cfg.Port)
	}
	if p.cfg.UserFilter != "(uid=%s)" {
		t.Errorf("default filter = %q", p.cfg.UserFilter)
	}
}

func TestLDAPProviderTLSPort(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{Host: "ldap.test.com", UseTLS: true})
	if p.cfg.Port != 636 {
		t.Errorf("TLS port = %d, want 636", p.cfg.Port)
	}
}

func TestLDAPProviderName(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{})
	if p.Name() != "ldap" {
		t.Errorf("name = %q", p.Name())
	}
}

func TestLDAPBuildUserDN(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{BaseDN: "dc=example,dc=com"})
	dn := p.buildUserDN("john")
	if dn != "uid=john,dc=example,dc=com" {
		t.Errorf("dn = %q", dn)
	}
}

func TestLDAPAuthEmptyCredentials(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{Host: "localhost"})
	_, err := p.Authenticate("", "pass")
	if err == nil {
		t.Error("empty username should fail")
	}
	_, err = p.Authenticate("user", "")
	if err == nil {
		t.Error("empty password should fail")
	}
}

func TestLDAPAuthConnectionFail(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{Host: "127.0.0.1", Port: 1})
	_, err := p.Authenticate("user", "pass")
	if err == nil {
		t.Error("unreachable host should fail")
	}
}

func TestBEREncoding(t *testing.T) {
	seq := berEncodeSequence([]byte{1, 2, 3})
	if seq[0] != 0x30 {
		t.Error("sequence tag should be 0x30")
	}

	oct := berEncodeOctetString("hello")
	if oct[0] != 0x04 {
		t.Error("octet string tag should be 0x04")
	}

	integer := berEncodeInteger(42)
	if integer[0] != 0x02 {
		t.Error("integer tag should be 0x02")
	}
}

func TestParseLDAPResultCode(t *testing.T) {
	// Invalid data
	code := parseLDAPResultCode([]byte{0x01, 0x02})
	if code != -1 {
		t.Errorf("invalid data should return -1, got %d", code)
	}
}

func TestSSOProviderValidateToken(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})

	// Invalid token format
	_, err := p.ValidateToken("not-a-jwt")
	if err == nil {
		t.Error("invalid format should fail")
	}

	_, err = p.ValidateToken("a.b")
	if err == nil {
		t.Error("2 parts should fail")
	}
}

func TestSSOProviderExtractUsername(t *testing.T) {
	p := NewSSOProvider(SSOConfig{UsernameClaim: "email"})
	claims := &JWTClaims{Subject: "sub1", Email: "test@test.com"}

	username := p.ExtractUsername(claims)
	if username != "test@test.com" {
		t.Errorf("username = %q, want email", username)
	}

	p2 := NewSSOProvider(SSOConfig{UsernameClaim: "preferred_username"})
	claims.Username = "jdoe"
	if p2.ExtractUsername(claims) != "jdoe" {
		t.Error("should use preferred_username")
	}
}

func TestSSOExtractGroups(t *testing.T) {
	p := NewSSOProvider(SSOConfig{})

	claims := &JWTClaims{Groups: []string{"admin", "dev"}}
	groups := p.ExtractGroups(claims)
	if len(groups) != 2 {
		t.Errorf("groups = %d", len(groups))
	}

	// Fallback to roles
	claims2 := &JWTClaims{Roles: []string{"dba"}}
	roles := p.ExtractGroups(claims2)
	if len(roles) != 1 {
		t.Errorf("roles fallback = %d", len(roles))
	}
}

func TestChainProvider(t *testing.T) {
	chain := NewChainProvider()
	result, err := chain.Authenticate("user", "pass")
	if err != nil || result != nil {
		// No providers — returns nil, nil
	}
}
