package auth

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// LDAPConfig configures LDAP/AD authentication.
type LDAPConfig struct {
	Host       string `json:"host"`       // ldap.example.com
	Port       int    `json:"port"`       // 389 or 636 (LDAPS)
	BaseDN     string `json:"base_dn"`    // dc=example,dc=com
	BindDN     string `json:"bind_dn"`    // cn=admin,dc=example,dc=com
	BindPass   string `json:"bind_pass"`  // bind password
	UserFilter string `json:"user_filter"` // (uid=%s) or (sAMAccountName=%s)
	GroupDN    string `json:"group_dn"`    // ou=groups,dc=example,dc=com
	GroupAttr  string `json:"group_attr"`  // memberOf
	UseTLS     bool   `json:"use_tls"`
	SkipVerify bool   `json:"skip_verify"`
	Timeout    time.Duration `json:"timeout"`
}

// LDAPProvider authenticates users against LDAP/Active Directory.
type LDAPProvider struct {
	cfg LDAPConfig
}

// NewLDAPProvider creates an LDAP auth provider.
func NewLDAPProvider(cfg LDAPConfig) *LDAPProvider {
	if cfg.Port == 0 {
		if cfg.UseTLS {
			cfg.Port = 636
		} else {
			cfg.Port = 389
		}
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(uid=%s)"
	}
	if cfg.GroupAttr == "" {
		cfg.GroupAttr = "memberOf"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &LDAPProvider{cfg: cfg}
}

// Authenticate verifies username/password against LDAP.
// Returns the user's groups (for role mapping) on success.
func (p *LDAPProvider) Authenticate(username, password string) ([]string, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("empty username or password")
	}

	addr := fmt.Sprintf("%s:%d", p.cfg.Host, p.cfg.Port)

	// Connect
	var conn net.Conn
	var err error

	if p.cfg.UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: p.cfg.SkipVerify,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: p.cfg.Timeout}, "tcp", addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", addr, p.cfg.Timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP connect to %s: %w", addr, err)
	}
	defer conn.Close()

	// Simple LDAP bind — in production use a proper LDAP library
	// For Argus, we implement minimal LDAP bind request/response
	userDN := p.buildUserDN(username)
	if err := ldapSimpleBind(conn, userDN, password); err != nil {
		return nil, fmt.Errorf("LDAP auth failed for %s: %w", username, err)
	}

	// Resolve groups (simplified — would need LDAP search in full implementation)
	groups := p.resolveGroups(username)

	return groups, nil
}

// buildUserDN constructs the user's distinguished name.
func (p *LDAPProvider) buildUserDN(username string) string {
	filter := strings.Replace(p.cfg.UserFilter, "%s", username, 1)
	// Extract attribute name from filter: (uid=%s) → uid
	attr := "uid"
	if idx := strings.Index(filter, "="); idx > 0 {
		attr = filter[1:idx]
	}
	return fmt.Sprintf("%s=%s,%s", attr, username, p.cfg.BaseDN)
}

// resolveGroups returns groups for a user by performing an LDAP search.
// Connects with the service account (BindDN/BindPass) and searches
// for entries matching the user filter under GroupDN (or BaseDN).
func (p *LDAPProvider) resolveGroups(username string) []string {
	if p.cfg.BindDN == "" || p.cfg.BindPass == "" {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", p.cfg.Host, p.cfg.Port)
	var conn net.Conn
	var err error

	if p.cfg.UseTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: p.cfg.SkipVerify}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: p.cfg.Timeout}, "tcp", addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", addr, p.cfg.Timeout)
	}
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Bind as service account
	if err := ldapSimpleBind(conn, p.cfg.BindDN, p.cfg.BindPass); err != nil {
		return nil
	}

	// Search for user's group memberships
	searchBase := p.cfg.GroupDN
	if searchBase == "" {
		searchBase = p.cfg.BaseDN
	}

	userDN := p.buildUserDN(username)
	filter := fmt.Sprintf("(%s=%s)", p.cfg.GroupAttr, userDN)
	groups := ldapSearchGroups(conn, searchBase, filter)

	return groups
}

// ldapSearchGroups performs an LDAP search and extracts CN values from results.
func ldapSearchGroups(conn net.Conn, baseDN, filter string) []string {
	// Build LDAP SearchRequest (msgID=2)
	searchReq := buildLDAPSearchRequest(2, baseDN, filter, "cn")

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(searchReq); err != nil {
		return nil
	}

	// Read search result entries
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var groups []string

	for {
		resp := make([]byte, 4096)
		n, err := conn.Read(resp)
		if err != nil || n < 10 {
			break
		}

		// Parse entries — extract CN values from SearchResultEntry (0x64)
		// and stop at SearchResultDone (0x65)
		data := resp[:n]
		for i := 0; i < len(data)-2; i++ {
			if data[i] == 0x65 { // SearchResultDone
				return groups
			}
			if data[i] == 0x64 { // SearchResultEntry
				cn := extractCNFromEntry(data[i:])
				if cn != "" {
					groups = append(groups, cn)
				}
			}
		}
	}
	return groups
}

// extractCNFromEntry extracts the CN (common name) from an LDAP SearchResultEntry.
func extractCNFromEntry(data []byte) string {
	// Look for "cn" or "CN" attribute followed by its value
	for i := 0; i < len(data)-4; i++ {
		// OCTET STRING containing "cn"
		if data[i] == 0x04 && i+1 < len(data) && data[i+1] == 2 {
			if i+4 < len(data) && (data[i+2] == 'c' || data[i+2] == 'C') && (data[i+3] == 'n' || data[i+3] == 'N') {
				// Next OCTET STRING is the value
				valStart := i + 4
				for valStart < len(data)-2 {
					if data[valStart] == 0x04 {
						vlen := int(data[valStart+1])
						if valStart+2+vlen <= len(data) {
							return string(data[valStart+2 : valStart+2+vlen])
						}
					}
					valStart++
				}
			}
		}
	}
	return ""
}

// buildLDAPSearchRequest creates a minimal LDAP SearchRequest message.
func buildLDAPSearchRequest(msgID int, baseDN, filter, attr string) []byte {
	// SearchRequest components:
	// baseObject: baseDN
	// scope: wholeSubtree (2)
	// derefAliases: neverDerefAliases (0)
	// sizeLimit: 100
	// timeLimit: 10
	// typesOnly: false
	// filter: (attr=value)
	// attributes: [attr]

	base := berEncodeOctetString(baseDN)
	scope := berEncodeEnumerated(2)       // wholeSubtree
	deref := berEncodeEnumerated(0)       // neverDerefAliases
	sizeLimit := berEncodeInteger(100)
	timeLimit := berEncodeInteger(10)
	typesOnly := []byte{0x01, 0x01, 0x00} // BOOLEAN FALSE

	// Encode filter as substring — simplified equality match
	filterBytes := berEncodeFilter(filter)

	// Attributes: SEQUENCE of OCTET STRING
	attrBytes := berEncodeSequence(berEncodeOctetString(attr))

	searchBody := append(base, scope...)
	searchBody = append(searchBody, deref...)
	searchBody = append(searchBody, sizeLimit...)
	searchBody = append(searchBody, timeLimit...)
	searchBody = append(searchBody, typesOnly...)
	searchBody = append(searchBody, filterBytes...)
	searchBody = append(searchBody, attrBytes...)

	searchReq := berEncodeApplication(3, searchBody) // SearchRequest is Application[3]

	msgIDBytes := berEncodeInteger(msgID)
	msgBody := append(msgIDBytes, searchReq...)

	return berEncodeSequence(msgBody)
}

// berEncodeEnumerated encodes an ENUMERATED BER value.
func berEncodeEnumerated(val int) []byte {
	return berEncodeTLV(0x0A, []byte{byte(val)})
}

// berEncodeFilter encodes an LDAP filter string like "(memberOf=cn=admin,dc=example,dc=com)".
func berEncodeFilter(filter string) []byte {
	// Strip outer parens
	f := strings.TrimPrefix(strings.TrimSuffix(filter, ")"), "(")
	parts := strings.SplitN(f, "=", 2)
	if len(parts) != 2 {
		// Fallback: present filter
		return berEncodeTLV(0x87, []byte(f)) // context [7] = present
	}
	// EqualityMatch: context [3] { attr, value }
	attr := berEncodeOctetString(parts[0])
	val := berEncodeOctetString(parts[1])
	return berEncodeTLV(0xA3, append(attr, val...))
}

// ldapSimpleBind performs a minimal LDAP simple bind.
// This is a simplified implementation — production should use a proper LDAP library.
func ldapSimpleBind(conn net.Conn, dn, password string) error {
	// LDAP Bind Request (simplified BER encoding)
	// MessageID: 1, BindRequest: version=3, name=dn, auth=simple(password)
	bindReq := buildLDAPBindRequest(1, dn, password)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(bindReq); err != nil {
		return fmt.Errorf("sending bind request: %w", err)
	}

	// Read Bind Response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return fmt.Errorf("reading bind response: %w", err)
	}

	// Parse result code from response
	if n < 10 {
		return fmt.Errorf("LDAP response too short")
	}

	// Very simplified BER parsing — find resultCode
	// In a real LDAP response, resultCode=0 means success
	resultCode := parseLDAPResultCode(resp[:n])
	if resultCode != 0 {
		return fmt.Errorf("LDAP bind failed: result code %d", resultCode)
	}

	return nil
}

// buildLDAPBindRequest creates a minimal LDAP BindRequest.
func buildLDAPBindRequest(msgID int, dn, password string) []byte {
	// BER encode: SEQUENCE { MessageID, BindRequest { version, name, SimpleAuth } }

	// SimpleAuth: context-specific [0] password
	simpleAuth := berEncodeContextString(0, password)

	// BindRequest: SEQUENCE of version(3) + name(dn) + auth
	version := berEncodeInteger(3)
	name := berEncodeOctetString(dn)

	bindBody := append(version, name...)
	bindBody = append(bindBody, simpleAuth...)
	bindReq := berEncodeApplication(0, bindBody) // BindRequest is Application[0]

	// Message: SEQUENCE of MessageID + BindRequest
	msgIDBytes := berEncodeInteger(msgID)
	msgBody := append(msgIDBytes, bindReq...)

	return berEncodeSequence(msgBody)
}

func parseLDAPResultCode(data []byte) int {
	// Walk through BER to find resultCode in BindResponse
	// BindResponse is Application[1] containing: resultCode, matchedDN, diagnosticMessage
	for i := 0; i < len(data)-2; i++ {
		// Look for Application[1] tag (0x61)
		if data[i] == 0x61 {
			// Skip length
			offset := i + 2
			if data[i+1] > 0x80 {
				offset = i + 2 + int(data[i+1]&0x7F)
			}
			// First element should be ENUMERATED (resultCode)
			if offset < len(data) && data[offset] == 0x0A {
				// ENUMERATED tag, length, value
				if offset+2 < len(data) {
					return int(data[offset+2])
				}
			}
		}
	}
	return -1 // couldn't parse
}

// BER encoding helpers
func berEncodeSequence(content []byte) []byte {
	return berEncodeTLV(0x30, content)
}

func berEncodeApplication(tag int, content []byte) []byte {
	return berEncodeTLV(byte(0x60|tag), content)
}

func berEncodeInteger(val int) []byte {
	return berEncodeTLV(0x02, []byte{byte(val)})
}

func berEncodeOctetString(s string) []byte {
	return berEncodeTLV(0x04, []byte(s))
}

func berEncodeContextString(tag int, s string) []byte {
	return berEncodeTLV(byte(0x80|tag), []byte(s))
}

func berEncodeTLV(tag byte, value []byte) []byte {
	length := len(value)
	var result []byte
	result = append(result, tag)

	if length < 128 {
		result = append(result, byte(length))
	} else if length < 256 {
		result = append(result, 0x81, byte(length))
	} else {
		result = append(result, 0x82, byte(length>>8), byte(length))
	}

	return append(result, value...)
}
