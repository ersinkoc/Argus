package core

import (
	"testing"

	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/session"
)

// combineRoles is the proxy-auth per-user policy binding: the wire username may be an opaque handle
// (Monopam's mp_<...>), so the roles the identity resolver returns must reach the session in addition
// to any roles the policy file maps to the username.

func TestCombineRolesCarriesResolverRoles(t *testing.T) {
	ps := &policy.PolicySet{Roles: map[string]policy.Role{
		"dba": {Users: []string{"admin"}},
	}}
	// Username "admin" maps to "dba" via the policy file; the resolver adds "analyst".
	assertRoles(t, combineRoles(ps, &session.Info{Username: "admin", Roles: []string{"analyst"}}),
		[]string{"dba", "analyst"})
}

func TestCombineRolesOpaqueHandleUsesResolverRoles(t *testing.T) {
	ps := &policy.PolicySet{Roles: map[string]policy.Role{
		"dba": {Users: []string{"admin"}},
	}}
	// An opaque handle matches no policy user, so only the resolver-provided roles apply.
	assertRoles(t, combineRoles(ps, &session.Info{Username: "mp_abc123", Roles: []string{"analyst", "reader"}}),
		[]string{"analyst", "reader"})
}

func TestCombineRolesDedupesAndSkipsEmpty(t *testing.T) {
	ps := &policy.PolicySet{Roles: map[string]policy.Role{
		"analyst": {Users: []string{"mp_x"}},
	}}
	// "analyst" already comes from the username; the duplicate and empty resolver entries are ignored.
	assertRoles(t, combineRoles(ps, &session.Info{Username: "mp_x", Roles: []string{"analyst", "", "extra"}}),
		[]string{"analyst", "extra"})
}

func TestCombineRolesNilPolicySet(t *testing.T) {
	assertRoles(t, combineRoles(nil, &session.Info{Username: "mp_x", Roles: []string{"analyst"}}),
		[]string{"analyst"})
}

func TestCombineRolesNoResolverRolesUnchanged(t *testing.T) {
	ps := &policy.PolicySet{Roles: map[string]policy.Role{
		"dba": {Users: []string{"admin"}},
	}}
	assertRoles(t, combineRoles(ps, &session.Info{Username: "admin"}), []string{"dba"})
}

func assertRoles(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("roles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roles = %v, want %v", got, want)
		}
	}
}
