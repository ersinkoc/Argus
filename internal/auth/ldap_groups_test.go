package auth

import (
	"testing"
)

func TestBerEncodeEnumerated(t *testing.T) {
	got := berEncodeEnumerated(2)
	// Tag=0x0A, Len=1, Val=2
	if len(got) != 3 || got[0] != 0x0A || got[1] != 1 || got[2] != 2 {
		t.Errorf("berEncodeEnumerated(2) = %x", got)
	}
}

func TestBerEncodeFilterEquality(t *testing.T) {
	got := berEncodeFilter("(memberOf=cn=admin,dc=test)")
	// Should be context [3] (EqualityMatch) containing attr + value
	if len(got) == 0 || got[0] != 0xA3 {
		t.Errorf("expected EqualityMatch tag 0xA3, got %x", got)
	}
}

func TestBerEncodeFilterNoEquals(t *testing.T) {
	got := berEncodeFilter("(objectClass)")
	// Should fallback to present filter (context [7])
	if len(got) == 0 || got[0] != 0x87 {
		t.Errorf("expected present tag 0x87, got %x", got)
	}
}

func TestExtractCNFromEntry(t *testing.T) {
	// Build a minimal entry with cn=Admins
	var entry []byte
	// OCTET STRING "cn" (tag 0x04, len 2, 'c', 'n')
	entry = append(entry, 0x04, 0x02, 'c', 'n')
	// OCTET STRING "Admins" (tag 0x04, len 6)
	entry = append(entry, 0x04, 0x06, 'A', 'd', 'm', 'i', 'n', 's')

	cn := extractCNFromEntry(entry)
	if cn != "Admins" {
		t.Errorf("extractCN = %q, want Admins", cn)
	}
}

func TestExtractCNFromEntryNoCN(t *testing.T) {
	// Entry without "cn" attribute
	entry := []byte{0x04, 0x02, 'o', 'u', 0x04, 0x05, 'G', 'r', 'o', 'u', 'p'}
	cn := extractCNFromEntry(entry)
	if cn != "" {
		t.Errorf("expected empty, got %q", cn)
	}
}

func TestExtractCNFromEntryEmpty(t *testing.T) {
	cn := extractCNFromEntry(nil)
	if cn != "" {
		t.Errorf("expected empty, got %q", cn)
	}
}

func TestBuildLDAPSearchRequest(t *testing.T) {
	req := buildLDAPSearchRequest(2, "dc=test,dc=com", "(memberOf=cn=admin)", "cn")
	if len(req) == 0 {
		t.Fatal("empty search request")
	}
	// Should start with SEQUENCE tag 0x30
	if req[0] != 0x30 {
		t.Errorf("expected SEQUENCE tag 0x30, got 0x%02x", req[0])
	}
}

func TestResolveGroupsNoBindDN(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{
		Host:   "127.0.0.1",
		Port:   389,
		BaseDN: "dc=test,dc=com",
		// No BindDN/BindPass — should return nil immediately
	})
	groups := p.resolveGroups("testuser")
	if groups != nil {
		t.Errorf("expected nil without BindDN, got %v", groups)
	}
}

func TestResolveGroupsConnectFail(t *testing.T) {
	p := NewLDAPProvider(LDAPConfig{
		Host:     "127.0.0.1",
		Port:     1, // unreachable
		BaseDN:   "dc=test,dc=com",
		BindDN:   "cn=admin,dc=test,dc=com",
		BindPass: "adminpass",
		Timeout:  100 * 1e6, // 100ms
	})
	groups := p.resolveGroups("testuser")
	if groups != nil {
		t.Errorf("expected nil on connect fail, got %v", groups)
	}
}
