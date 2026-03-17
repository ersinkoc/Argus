package policy

import (
	"net"
	"testing"

	"github.com/ersinkoc/argus/internal/inspection"
)

func TestMatchDatabases(t *testing.T) {
	if !matchDatabases("prod", []string{"prod", "staging"}) {
		t.Error("should match exact")
	}
	if !matchDatabases("prod_app", []string{"prod_*"}) {
		t.Error("should match wildcard")
	}
	if matchDatabases("dev_app", []string{"prod_*"}) {
		t.Error("should not match")
	}
	if !matchDatabases("anything", nil) {
		t.Error("empty list should match all")
	}
}

func TestMatchTables(t *testing.T) {
	if !matchTables([]string{"users", "orders"}, []string{"users"}) {
		t.Error("should match users")
	}
	if matchTables([]string{"logs"}, []string{"users", "orders"}) {
		t.Error("should not match logs")
	}
	if !matchTables([]string{"anything"}, nil) {
		t.Error("empty policy tables should match all")
	}
	if !matchTables([]string{"audit_log"}, []string{"*_log"}) {
		t.Error("should match suffix wildcard")
	}
}

func TestMatchIPInSingleIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.100")
	if !matchIPIn(ip, []string{"192.168.1.100"}) {
		t.Error("should match exact IP")
	}
	if matchIPIn(ip, []string{"10.0.0.1"}) {
		t.Error("should not match different IP")
	}
}

func TestMatchIPInNilIP(t *testing.T) {
	if matchIPIn(nil, []string{"10.0.0.0/8"}) {
		t.Error("nil IP should not match")
	}
}

func TestMatchIPInInvalidCIDR(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	if matchIPIn(ip, []string{"invalid-cidr"}) {
		t.Error("invalid CIDR should not match")
	}
}

func TestMatchCommands(t *testing.T) {
	if !matchCommands(inspection.CommandSELECT, []string{"SELECT"}) {
		t.Error("should match SELECT")
	}
	if !matchCommands(inspection.CommandDDL, []string{"DDL", "DCL"}) {
		t.Error("should match DDL in list")
	}
	if matchCommands(inspection.CommandINSERT, []string{"SELECT"}) {
		t.Error("INSERT should not match SELECT")
	}
	if !matchCommands(inspection.CommandSELECT, nil) {
		t.Error("empty commands should match all")
	}
}

func TestMatchRoleNegation(t *testing.T) {
	roles := map[string]Role{
		"dba":     {Users: []string{"admin"}},
		"support": {Users: []string{"support_*"}},
	}

	ctx := &Context{Username: "admin"}
	// admin IS dba, so "!dba" should NOT match
	if matchRole(ctx, []string{"!dba"}, roles) {
		t.Error("admin has dba role, !dba should not match")
	}

	ctx2 := &Context{Username: "dev_john"}
	// dev_john is NOT dba, so "!dba" should match
	if !matchRole(ctx2, []string{"!dba"}, roles) {
		t.Error("dev_john is not dba, !dba should match")
	}
}

func TestMatchRoleEmpty(t *testing.T) {
	if !matchRole(&Context{Username: "anyone"}, nil, nil) {
		t.Error("empty roles should match all")
	}
}
