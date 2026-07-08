package auth

import (
	"net"
	"testing"
	"time"
)

// --- LDAP Authenticate full flow ---

func TestLDAPAuthenticateSuccess(t *testing.T) {
	// Start a fake LDAP server that accepts bind
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c == nil {
			return
		}
		defer c.Close()
		c.Read(make([]byte, 1024)) // read bind request
		// Build successful LDAP BindResponse
		bindResp := berEncodeSequence(append(
			berEncodeInteger(1),
			berEncodeApplication(1, append(
				berEncodeTLV(0x0A, []byte{0}), // resultCode=0 (success)
				berEncodeOctetString("")...,
			))...,
		))
		c.Write(bindResp)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	p := NewLDAPProvider(LDAPConfig{
		Host:    host,
		Port:    port,
		BaseDN:  "dc=test,dc=com",
		Timeout: 2 * time.Second,
	})

	groups, err := p.Authenticate("testuser", "password")
	if err != nil {
		t.Errorf("Authenticate should succeed: %v", err)
	}
	// resolveGroups returns nil (placeholder)
	if groups != nil {
		t.Errorf("groups = %v", groups)
	}
}

func TestLDAPAuthenticateEmptyCredentials(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{Host: "127.0.0.1", Port: 389})
	_, err := p.Authenticate("", "pass")
	if err == nil {
		t.Error("empty username should fail")
	}
	_, err = p.Authenticate("user", "")
	if err == nil {
		t.Error("empty password should fail")
	}
}

func TestLDAPAuthenticateConnectFailed(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{
		Host:    "127.0.0.1",
		Port:    1, // unreachable
		Timeout: 100 * time.Millisecond,
	})
	_, err := p.Authenticate("user", "pass")
	if err == nil {
		t.Error("unreachable server should fail")
	}
}

func TestLDAPAuthenticateBindFailed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c == nil {
			return
		}
		defer c.Close()
		c.Read(make([]byte, 1024))
		// resultCode=49 (invalidCredentials)
		bindResp := berEncodeSequence(append(
			berEncodeInteger(1),
			berEncodeApplication(1, append(
				berEncodeTLV(0x0A, []byte{49}),
				berEncodeOctetString("")...,
			))...,
		))
		c.Write(bindResp)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	p := NewLDAPProvider(LDAPConfig{
		Host:    host,
		Port:    port,
		BaseDN:  "dc=test,dc=com",
		Timeout: 2 * time.Second,
	})

	_, err := p.Authenticate("user", "wrongpass")
	if err == nil {
		t.Error("bad credentials should fail")
	}
}

func TestLDAPAuthenticateTLSConnectFailed(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{
		Host:       "127.0.0.1",
		Port:       1,
		UseTLS:     true,
		SkipVerify: true,
		Timeout:    100 * time.Millisecond,
	})
	_, err := p.Authenticate("user", "pass")
	if err == nil {
		t.Error("unreachable TLS server should fail")
	}
}

// --- ChainProvider with multiple providers ---

func TestChainProviderFirstSucceeds(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c == nil {
			return
		}
		defer c.Close()
		c.Read(make([]byte, 1024))
		bindResp := berEncodeSequence(append(
			berEncodeInteger(1),
			berEncodeApplication(1, append(
				berEncodeTLV(0x0A, []byte{0}),
				berEncodeOctetString("")...,
			))...,
		))
		c.Write(bindResp)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	ldap1 := NewLDAPProvider(LDAPConfig{Host: host, Port: port, BaseDN: "dc=test", Timeout: time.Second})
	ldap2 := NewLDAPProvider(LDAPConfig{Host: "127.0.0.1", Port: 1, BaseDN: "dc=test", Timeout: 100 * time.Millisecond})

	chain := NewChainProvider(ldap1, ldap2)
	result, err := chain.Authenticate("user", "pass")
	if err != nil {
		t.Fatalf("chain should succeed: %v", err)
	}
	if result.Provider != "ldap" {
		t.Errorf("provider = %q", result.Provider)
	}
}
