package policy

import "testing"

func TestMergePolicySets(t *testing.T) {
	base := &PolicySet{
		Version:  "1",
		Defaults: DefaultsConfig{Action: "allow", LogLevel: "standard"},
		Roles: map[string]Role{
			"dba":       {Users: []string{"admin"}},
			"developer": {Users: []string{"dev_*"}},
		},
		Policies: []PolicyRule{
			{Name: "base-allow-read", Match: MatchConfig{Commands: []string{"SELECT"}}, Action: "allow"},
		},
	}

	overlay := &PolicySet{
		Version: "2",
		Roles: map[string]Role{
			"developer": {Users: []string{"dev_*", "eng_*"}}, // extended
			"support":   {Users: []string{"support_*"}},       // new role
		},
		Policies: []PolicyRule{
			{Name: "overlay-block-ddl", Match: MatchConfig{Commands: []string{"DDL"}}, Action: "block"},
		},
	}

	merged := MergePolicySets(base, overlay)

	// Version from overlay
	if merged.Version != "2" {
		t.Errorf("version = %q, want 2", merged.Version)
	}

	// Roles: developer overwritten, dba from base, support from overlay
	if len(merged.Roles) != 3 {
		t.Errorf("roles count = %d, want 3", len(merged.Roles))
	}
	if _, ok := merged.Roles["dba"]; !ok {
		t.Error("dba role should exist from base")
	}
	if _, ok := merged.Roles["support"]; !ok {
		t.Error("support role should exist from overlay")
	}
	devRole := merged.Roles["developer"]
	if len(devRole.Users) != 2 {
		t.Errorf("developer users = %v, want 2 entries", devRole.Users)
	}

	// Policies: overlay first (higher priority), then base
	if len(merged.Policies) != 2 {
		t.Fatalf("policies count = %d, want 2", len(merged.Policies))
	}
	if merged.Policies[0].Name != "overlay-block-ddl" {
		t.Errorf("first policy = %q, want overlay-block-ddl (higher priority)", merged.Policies[0].Name)
	}
	if merged.Policies[1].Name != "base-allow-read" {
		t.Errorf("second policy = %q, want base-allow-read", merged.Policies[1].Name)
	}
}

func TestMergePolicySetsNil(t *testing.T) {
	ps := &PolicySet{Version: "1"}

	if MergePolicySets(nil, ps) != ps {
		t.Error("nil base should return overlay")
	}
	if MergePolicySets(ps, nil) != ps {
		t.Error("nil overlay should return base")
	}
}
