package auth

import (
	"net"
	"testing"
	"time"
)

// --- resolveGroups: TLS connect failure path ---

func TestResolveGroupsTLSConnectFail(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{
		Host:       "127.0.0.1",
		Port:       1, // unreachable
		BaseDN:     "dc=test,dc=com",
		BindDN:     "cn=admin,dc=test,dc=com",
		BindPass:   "secret",
		UseTLS:     true,
		SkipVerify: true,
		Timeout:    100 * time.Millisecond,
	})
	groups := p.resolveGroups("testuser")
	if groups != nil {
		t.Errorf("TLS connect failure should return nil, got %v", groups)
	}
}

// --- resolveGroups: empty GroupDN falls back to BaseDN ---

func TestResolveGroupsEmptyGroupDN(t *testing.T) {
	addr := mockLDAPServer(t, "developers")

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
		BindPass: "secret",
		GroupDN:  "", // empty → should fallback to BaseDN
		Timeout:  2 * time.Second,
	})

	groups := p.resolveGroups("testuser")
	// Just verify no panic; the mock server sends an entry
	_ = groups
}

// --- extractCNFromEntry: truncated value (valStart+2+vlen > len(data)) ---

func TestExtractCNFromEntryTruncatedValue(t *testing.T) {
	// Build entry with cn attribute but truncated value
	// 0x04, 0x02, 'c', 'n' → then 0x04 with length exceeding remaining data
	entry := []byte{
		0x04, 0x02, 'c', 'n', // OCTET STRING "cn"
		0x04, 0xFF, // value octet string with length 255 (but data ends here)
	}
	cn := extractCNFromEntry(entry)
	if cn != "" {
		t.Errorf("truncated value should return empty, got %q", cn)
	}
}

// --- extractCNFromEntry: CN attribute found but no following OCTET STRING ---

func TestExtractCNFromEntryNoValueOctet(t *testing.T) {
	// cn attribute followed by non-0x04 bytes until end
	entry := []byte{
		0x04, 0x02, 'c', 'n', // OCTET STRING "cn"
		0x01, 0x01, 0x00, // BOOLEAN FALSE (not an OCTET STRING)
	}
	cn := extractCNFromEntry(entry)
	if cn != "" {
		t.Errorf("no octet string after cn should return empty, got %q", cn)
	}
}

// --- ldapSimpleBind: write error ---

func TestLDAPSimpleBindWriteError(t *testing.T) {
	client, server := net.Pipe()
	server.Close() // close immediately → write will fail

	err := ldapSimpleBind(client, "cn=admin", "password")
	if err == nil {
		t.Error("write to closed conn should fail")
	}
	client.Close()
}

// --- ldapSimpleBind: read error ---

func TestLDAPSimpleBindReadError(t *testing.T) {
	client, server := net.Pipe()

	go func() {
		// Read the bind request then close without responding
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Close()
	}()

	err := ldapSimpleBind(client, "cn=admin", "password")
	if err == nil {
		t.Error("read from closed conn should fail")
	}
	client.Close()
}

// --- ldapSimpleBind: response too short ---

func TestLDAPSimpleBindShortResponse(t *testing.T) {
	client, server := net.Pipe()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		// Send very short response (< 10 bytes)
		server.Write([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
		server.Close()
	}()

	err := ldapSimpleBind(client, "cn=admin", "password")
	if err == nil {
		t.Error("short response should fail")
	}
	client.Close()
}

// --- parseLDAPResultCode: multi-byte length in Application[1] ---

func TestParseLDAPResultCodeMultiByteLength(t *testing.T) {
	// Build a response with Application[1] tag (0x61) with multi-byte length
	// 0x61, 0x81, 0x07 = Application[1] with length 7 (0x81 means 1 byte of length follows)
	// After that: ENUMERATED resultCode=5
	data := []byte{
		0x30, 0x0C,       // SEQUENCE
		0x02, 0x01, 0x01, // INTEGER (messageID=1)
		0x61, 0x81, 0x05, // Application[1] with multi-byte length = 5
		0x0A, 0x01, 0x05, // ENUMERATED resultCode=5
		0x04, 0x00,       // matchedDN = ""
	}

	code := parseLDAPResultCode(data)
	if code != 5 {
		t.Errorf("expected resultCode=5, got %d", code)
	}
}

// --- parseLDAPResultCode: Application[1] found but no ENUMERATED follows ---

func TestParseLDAPResultCodeNoEnumerated(t *testing.T) {
	// Application[1] with unexpected content (not starting with 0x0A)
	data := []byte{
		0x30, 0x08,
		0x02, 0x01, 0x01,
		0x61, 0x03,       // Application[1], length 3
		0x04, 0x01, 0x00, // OCTET STRING (not ENUMERATED)
	}
	code := parseLDAPResultCode(data)
	if code != -1 {
		t.Errorf("no ENUMERATED should return -1, got %d", code)
	}
}

// --- parseLDAPResultCode: Application[1] with ENUMERATED but value truncated ---

func TestParseLDAPResultCodeEnumTruncated(t *testing.T) {
	// 0x61, length, then 0x0A but not enough data for value
	data := []byte{
		0x30, 0x05,
		0x02, 0x01, 0x01,
		0x61, 0x02,       // Application[1], length 2
		0x0A, 0x01,       // ENUMERATED tag + length, but no value byte
	}
	code := parseLDAPResultCode(data)
	if code != -1 {
		t.Errorf("truncated ENUMERATED should return -1, got %d", code)
	}
}
