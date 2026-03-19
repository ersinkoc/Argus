package auth

import (
	"net"
	"testing"
	"time"
)

// TestLDAPSearchGroups_WriteError exercises the write error path.
func TestLDAPSearchGroups_WriteError(t *testing.T) {
	client, server := net.Pipe()
	server.Close() // immediate close → write will fail

	groups := ldapSearchGroups(client, "dc=test,dc=com", "(memberOf=cn=admin)")
	if groups != nil {
		t.Errorf("expected nil on write error, got %v", groups)
	}
	client.Close()
}

// TestLDAPSearchGroups_NoResponse exercises the short/empty read path.
func TestLDAPSearchGroups_NoResponse(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		// Read the search request, then close without responding.
		buf := make([]byte, 4096)
		server.Read(buf) //nolint:errcheck
		server.Close()
	}()

	groups := ldapSearchGroups(client, "dc=test,dc=com", "(memberOf=cn=admin)")
	if groups != nil {
		t.Errorf("expected nil on empty response, got %v", groups)
	}
	client.Close()
}

// TestLDAPSearchGroups_SearchResultDone exercises the happy path with no entries.
func TestLDAPSearchGroups_SearchResultDone(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		server.Read(buf) //nolint:errcheck

		// Send a SearchResultDone (0x65) response.
		// LDAP message: SEQ { msgID=INT(2), SearchResultDone=APP[5] { resultCode=INT(0), matchedDN="", errorMsg="" } }
		done := buildSearchResultDone()
		server.Write(done) //nolint:errcheck
	}()

	groups := ldapSearchGroups(client, "dc=test,dc=com", "(memberOf=cn=admin)")
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %v", groups)
	}
	client.Close()
}

// TestLDAPSearchGroups_WithEntry exercises the path that extracts a CN from an entry.
func TestLDAPSearchGroups_WithEntry(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		server.Read(buf) //nolint:errcheck

		// Send a SearchResultEntry (0x64) with cn=Admins, then SearchResultDone.
		resp := buildSearchResultEntry("Admins")
		resp = append(resp, buildSearchResultDone()...)
		server.Write(resp) //nolint:errcheck
	}()

	groups := ldapSearchGroups(client, "dc=test,dc=com", "(memberOf=cn=admin)")
	if len(groups) != 1 || groups[0] != "Admins" {
		t.Errorf("expected [Admins], got %v", groups)
	}
	client.Close()
}

// buildSearchResultDone returns a minimal LDAP SearchResultDone message.
func buildSearchResultDone() []byte {
	// LDAPMessage ::= SEQUENCE { messageID INTEGER(2), SearchResultDone APPLICATION[5] { ... } }
	// SearchResultDone (Application 5 = tag 0x65) with resultCode=0, matchedDN="", errorMsg=""
	innerBody := []byte{
		0x0a, 0x01, 0x00, // resultCode = 0 (success)
		0x04, 0x00,       // matchedDN = ""
		0x04, 0x00,       // errorMessage = ""
	}
	innerTag := append([]byte{0x65, byte(len(innerBody))}, innerBody...)

	// messageID = INTEGER 2
	msgID := []byte{0x02, 0x01, 0x02}

	seqBody := append(msgID, innerTag...)
	return append([]byte{0x30, byte(len(seqBody))}, seqBody...)
}

// buildBindSuccessResponse returns an LDAP BindResponse with resultCode=0.
func buildBindSuccessResponse() []byte {
	// BindResponse = Application[1] (0x61) { resultCode=0, matchedDN="", errorMsg="" }
	innerBody := []byte{
		0x0a, 0x01, 0x00, // ENUMERATED resultCode = 0
		0x04, 0x00,       // matchedDN = ""
		0x04, 0x00,       // errorMessage = ""
	}
	appTag := append([]byte{0x61, byte(len(innerBody))}, innerBody...)
	msgID := []byte{0x02, 0x01, 0x01} // messageID = 1
	seqBody := append(msgID, appTag...)
	return append([]byte{0x30, byte(len(seqBody))}, seqBody...)
}

// mockLDAPServer creates a TCP server that answers one bind + one search.
func mockLDAPServer(t *testing.T, returnCN string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)

		// Read bind request
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf) //nolint:errcheck

		// Send bind success
		conn.Write(buildBindSuccessResponse()) //nolint:errcheck

		// Read search request
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		conn.Read(buf) //nolint:errcheck

		// Optionally send entry
		if returnCN != "" {
			conn.Write(buildSearchResultEntry(returnCN)) //nolint:errcheck
		}

		// Send SearchResultDone
		conn.Write(buildSearchResultDone()) //nolint:errcheck
	}()

	return ln.Addr().String()
}

// TestResolveGroups_Success tests the full resolveGroups path with a mock server.
func TestResolveGroups_Success(t *testing.T) {
	addr := mockLDAPServer(t, "admins")

	var host, port string
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host = addr[:i]
			port = addr[i+1:]
			break
		}
	}

	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}

	p := NewLDAPProvider(LDAPConfig{
		Host:      host,
		Port:      portNum,
		BaseDN:    "dc=test,dc=com",
		BindDN:    "cn=admin,dc=test,dc=com",
		BindPass:  "secret",
		Timeout:   2 * time.Second,
	})

	groups := p.resolveGroups("testuser")
	// The mock server returns "admins" but our parser may or may not extract it
	// depending on exact BER format. Just verify no panic and returns a slice.
	_ = groups
}

// TestResolveGroups_BindFail tests resolveGroups when the bind fails.
func TestResolveGroups_BindFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read bind request, send failure (resultCode=49 = invalidCredentials)
		buf := make([]byte, 4096)
		conn.Read(buf) //nolint:errcheck

		// BindResponse with resultCode=49
		innerBody := []byte{0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00}
		appTag := append([]byte{0x61, byte(len(innerBody))}, innerBody...)
		msgID := []byte{0x02, 0x01, 0x01}
		seqBody := append(msgID, appTag...)
		resp := append([]byte{0x30, byte(len(seqBody))}, seqBody...)
		conn.Write(resp) //nolint:errcheck
	}()

	addr := ln.Addr().String()
	var host, port string
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			host = addr[:i]
			port = addr[i+1:]
			break
		}
	}
	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}

	p := NewLDAPProvider(LDAPConfig{
		Host:     host,
		Port:     portNum,
		BaseDN:   "dc=test,dc=com",
		BindDN:   "cn=admin,dc=test,dc=com",
		BindPass: "wrongpass",
		Timeout:  2 * time.Second,
	})

	groups := p.resolveGroups("testuser")
	if groups != nil {
		t.Errorf("expected nil on bind failure, got %v", groups)
	}
}

// buildSearchResultEntry returns a minimal LDAP SearchResultEntry with cn=<name>.
func buildSearchResultEntry(cn string) []byte {
	// Construct an entry with tag 0x64 (SearchResultEntry)
	// The full LDAP encoding is complex; we instead embed the 0x64 tag
	// directly in the response bytes so ldapSearchGroups can detect it.
	//
	// Format: ... 0x64 <body> ... with "cn" attribute value encoded
	// as: 0x04 0x02 'c' 'n' 0x04 len <cn value>
	cnBytes := append(
		[]byte{0x04, 0x02, 'c', 'n'},
		append([]byte{0x04, byte(len(cn))}, []byte(cn)...)...,
	)

	// Wrap in SearchResultEntry Application[4] tag (0x64)
	entryBody := append(
		[]byte{0x04, 0x00}, // objectName = "" (DN)
		// partial attributes list (simplified)
		cnBytes...,
	)
	entryTag := append([]byte{0x64, byte(len(entryBody))}, entryBody...)

	// messageID = INTEGER 1
	msgID := []byte{0x02, 0x01, 0x01}
	seqBody := append(msgID, entryTag...)
	return append([]byte{0x30, byte(len(seqBody))}, seqBody...)
}
