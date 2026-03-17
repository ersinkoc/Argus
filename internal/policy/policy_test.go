package policy

import (
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"dev_*", "dev_john", true},
		{"dev_*", "admin", false},
		{"*_log", "audit_log", true},
		{"*_log", "users", false},
		{"users", "users", true},
		{"users", "Users", true}, // case insensitive
		{"users", "orders", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := matchWildcard(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("matchWildcard(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestResolveRoles(t *testing.T) {
	roles := map[string]Role{
		"dba":       {Users: []string{"admin", "postgres_admin"}},
		"developer": {Users: []string{"dev_*"}},
		"support":   {Users: []string{"support_*"}},
	}

	tests := []struct {
		username string
		want     []string
	}{
		{"admin", []string{"dba"}},
		{"dev_john", []string{"developer"}},
		{"support_jane", []string{"support"}},
		{"random_user", nil},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			got := ResolveUserRoles(tt.username, roles)
			if len(got) != len(tt.want) {
				t.Errorf("roles for %q = %v, want %v", tt.username, got, tt.want)
			}
		})
	}
}

func TestMatchIPIn(t *testing.T) {
	tests := []struct {
		ip    string
		cidrs []string
		want  bool
	}{
		{"10.0.1.5", []string{"10.0.0.0/8"}, true},
		{"192.168.1.1", []string{"10.0.0.0/8"}, false},
		{"172.16.5.10", []string{"172.16.0.0/12"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := matchIPIn(net.ParseIP(tt.ip), tt.cidrs)
			if got != tt.want {
				t.Errorf("matchIPIn(%s, %v) = %v, want %v", tt.ip, tt.cidrs, got, tt.want)
			}
		})
	}
}

func TestPolicyEngine(t *testing.T) {
	ps := &PolicySet{
		Version: "1",
		Defaults: DefaultsConfig{
			Action:   "audit",
			LogLevel: "standard",
			MaxRows:  100000,
		},
		Roles: map[string]Role{
			"dba":       {Users: []string{"admin"}},
			"developer": {Users: []string{"dev_*"}},
			"support":   {Users: []string{"support_*"}},
		},
		Policies: []PolicyRule{
			{
				Name: "block-destructive-ddl",
				Match: MatchConfig{
					Roles:    []string{"!dba"},
					Commands: []string{"DDL"},
				},
				Condition: &ConditionConfig{
					SQLContains: []string{"DROP"},
				},
				Action: "block",
				Reason: "DBA only",
			},
			{
				Name: "mask-pii-support",
				Match: MatchConfig{
					Roles:    []string{"support"},
					Commands: []string{"SELECT"},
				},
				Masking: []MaskingRule{
					{Column: "email", Transformer: "partial_email"},
				},
			},
			{
				Name:   "allow-read",
				Match:  MatchConfig{Commands: []string{"SELECT"}},
				Action: "allow",
			},
		},
	}

	loader := NewLoader(nil, 0)
	loader.mu.Lock()
	loader.current = ps
	loader.mu.Unlock()

	engine := NewEngine(loader)

	t.Run("block destructive DDL for non-DBA", func(t *testing.T) {
		ctx := &Context{
			Username:    "dev_john",
			CommandType: inspection.CommandDDL,
			RawSQL:      "DROP TABLE users",
			Timestamp:   time.Now(),
		}
		d := engine.Evaluate(ctx)
		if d.Action != ActionBlock {
			t.Errorf("action = %v, want block", d.Action)
		}
	})

	t.Run("allow DDL for DBA", func(t *testing.T) {
		ctx := &Context{
			Username:    "admin",
			CommandType: inspection.CommandDDL,
			RawSQL:      "DROP TABLE users",
			Timestamp:   time.Now(),
		}
		d := engine.Evaluate(ctx)
		if d.Action == ActionBlock {
			t.Errorf("DBA should not be blocked, action = %v", d.Action)
		}
	})

	t.Run("mask for support", func(t *testing.T) {
		ctx := &Context{
			Username:    "support_jane",
			CommandType: inspection.CommandSELECT,
			RawSQL:      "SELECT * FROM users",
			Tables:      []string{"users"},
			Timestamp:   time.Now(),
		}
		d := engine.Evaluate(ctx)
		if d.Action != ActionMask {
			t.Errorf("action = %v, want mask", d.Action)
		}
		if len(d.MaskingRules) == 0 {
			t.Error("should have masking rules")
		}
	})

	t.Run("allow read for developer", func(t *testing.T) {
		ctx := &Context{
			Username:    "dev_john",
			CommandType: inspection.CommandSELECT,
			RawSQL:      "SELECT * FROM users",
			Timestamp:   time.Now(),
		}
		d := engine.Evaluate(ctx)
		if d.Action != ActionAllow {
			t.Errorf("action = %v, want allow", d.Action)
		}
	})
}
