package core

import (
	"testing"

	"github.com/ersinkoc/argus/internal/session"
)

func TestRateLimitBucketKey(t *testing.T) {
	sess := &session.Session{ID: "sid1", Username: "mp_handle", Database: "sales", Principal: "user-42"}

	cases := map[string]string{
		"user":       "u:user-42",
		"connection": "c:sid1",
		"database":   "d:sales",
		"rule":       "rule",
		"":           "rule",
	}
	for scope, want := range cases {
		if got := rateLimitBucketKey(scope, sess); got != want {
			t.Errorf("scope %q: got %q, want %q", scope, got, want)
		}
	}

	// No principal → per-user degrades to the wire username (per-session).
	noPrincipal := &session.Session{ID: "sid2", Username: "mp_h2"}
	if got := rateLimitBucketKey("user", noPrincipal); got != "u:mp_h2" {
		t.Errorf("user without principal: got %q", got)
	}
}
