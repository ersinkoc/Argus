package auth

import (
	"net"
	"testing"
	"time"
)

func TestLdapSimpleBindTimeout(t *testing.T) {
	// Server that accepts but never responds
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { time.Sleep(10 * time.Second); c.Close() } }()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	err := ldapSimpleBind(conn, "cn=admin", "pass")
	if err == nil {
		t.Error("timeout should fail")
	}
}

func TestLdapSimpleBindShortResponse(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Read(make([]byte, 1024)) // read bind req
			c.Write([]byte{1, 2, 3})   // short response
			c.Close()
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	err := ldapSimpleBind(conn, "cn=test", "pass")
	if err == nil {
		t.Error("short response should fail")
	}
}

func TestLdapSimpleBindSuccess(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Read(make([]byte, 1024)) // read bind req
			// Build minimal LDAP BindResponse: SEQUENCE { msgID, Application[1] { ENUM(0=success), "", "" } }
			bindResp := berEncodeSequence(append(
				berEncodeInteger(1),
				berEncodeApplication(1, append(
					berEncodeTLV(0x0A, []byte{0}),
					berEncodeOctetString("")...,
				))...,
			))
			c.Write(bindResp)
			c.Close()
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	err := ldapSimpleBind(conn, "cn=admin,dc=test", "password")
	if err != nil {
		t.Errorf("bind should succeed: %v", err)
	}
}

func TestLdapSimpleBindFailed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Read(make([]byte, 1024))
			// resultCode = 49 (invalidCredentials)
			bindResp := berEncodeSequence(append(
				berEncodeInteger(1),
				berEncodeApplication(1, append(
					berEncodeTLV(0x0A, []byte{49}),
					berEncodeOctetString("")...,
				))...,
			))
			c.Write(bindResp)
			c.Close()
		}
	}()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	err := ldapSimpleBind(conn, "cn=bad", "wrong")
	if err == nil {
		t.Error("invalid credentials should fail")
	}
}

func TestParseLDAPResultCodeSuccess(t *testing.T) {
	// Build response with resultCode=0 inside Application[1]
	inner := append(berEncodeTLV(0x0A, []byte{0}), berEncodeOctetString("")...)
	resp := berEncodeSequence(append(berEncodeInteger(1), berEncodeApplication(1, inner)...))

	code := parseLDAPResultCode(resp)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestParseLDAPResultCodeFail(t *testing.T) {
	inner := append(berEncodeTLV(0x0A, []byte{49}), berEncodeOctetString("")...)
	resp := berEncodeSequence(append(berEncodeInteger(1), berEncodeApplication(1, inner)...))

	code := parseLDAPResultCode(resp)
	if code != 49 {
		t.Errorf("code = %d, want 49", code)
	}
}

func TestResolveGroups(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{})
	groups := p.resolveGroups("user")
	if groups != nil {
		t.Error("placeholder should return nil")
	}
}

func TestSSOExtractUsernameDefault(t *testing.T) {
	p := NewSSOProvider(SSOConfig{UsernameClaim: "unknown_claim"})
	claims := &JWTClaims{Subject: "fallback"}
	if p.ExtractUsername(claims) != "fallback" {
		t.Error("unknown claim should fallback to subject")
	}
}
