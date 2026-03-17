package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateCrossReference(t *testing.T) {
	t.Run("invalid default target", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Targets = []Target{{Name: "pg", Host: "localhost", Port: 5432}}
		cfg.Routing.DefaultTarget = "nonexistent"
		err := Validate(cfg)
		if err == nil {
			t.Error("should fail: default_target references nonexistent target")
		}
	})

	t.Run("valid default target", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Targets = []Target{{Name: "pg", Host: "localhost", Port: 5432, Protocol: "postgresql"}}
		cfg.Routing.DefaultTarget = "pg"
		err := Validate(cfg)
		if err != nil {
			t.Errorf("should pass: %v", err)
		}
	})

	t.Run("invalid routing rule target", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Targets = []Target{{Name: "pg", Host: "localhost", Port: 5432}}
		cfg.Routing.Rules = []RoutingRule{{Database: "test", Target: "nonexistent"}}
		err := Validate(cfg)
		if err == nil {
			t.Error("should fail: routing rule references nonexistent target")
		}
	})

	t.Run("missing policy file", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Policy.Files = []string{"/nonexistent/policy.json"}
		err := Validate(cfg)
		if err == nil {
			t.Error("should fail: policy file does not exist")
		}
	})

	t.Run("existing policy file", func(t *testing.T) {
		dir := t.TempDir()
		policyPath := filepath.Join(dir, "test.json")
		os.WriteFile(policyPath, []byte("{}"), 0644)

		cfg := DefaultConfig()
		cfg.Policy.Files = []string{policyPath}
		err := Validate(cfg)
		if err != nil {
			t.Errorf("should pass: %v", err)
		}
	})
}

func TestTargetAddress(t *testing.T) {
	target := Target{Host: "db.example.com", Port: 5432}
	addr := target.Address()
	if addr != "db.example.com:5432" {
		t.Errorf("Address() = %q, want %q", addr, "db.example.com:5432")
	}
}

func TestConfigString(t *testing.T) {
	cfg := DefaultConfig()
	s := cfg.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
}

func TestConfigFindTarget(t *testing.T) {
	cfg := &Config{
		Targets: []Target{
			{Name: "pg1", Host: "host1", Port: 5432},
			{Name: "pg2", Host: "host2", Port: 5432},
		},
	}

	t1 := cfg.FindTarget("pg1")
	if t1 == nil || t1.Host != "host1" {
		t.Error("should find pg1")
	}

	if cfg.FindTarget("nonexistent") != nil {
		t.Error("should return nil for nonexistent")
	}
}

func TestResolveTargetWithRules(t *testing.T) {
	cfg := &Config{
		Targets: []Target{
			{Name: "prod", Host: "prod-host", Port: 5432},
			{Name: "staging", Host: "staging-host", Port: 5432},
		},
		Routing: RoutingConfig{
			DefaultTarget: "prod",
			Rules: []RoutingRule{
				{Database: "staging_*", Target: "staging"},
				{Database: "*_test", Target: "staging"},
			},
		},
	}

	// Matching rule
	target := cfg.ResolveTarget("staging_app")
	if target == nil || target.Name != "staging" {
		t.Error("staging_app should route to staging")
	}

	// Suffix match
	target = cfg.ResolveTarget("myapp_test")
	if target == nil || target.Name != "staging" {
		t.Error("myapp_test should route to staging")
	}

	// Default
	target = cfg.ResolveTarget("production")
	if target == nil || target.Name != "prod" {
		t.Error("production should route to prod (default)")
	}

	// No match, no default
	cfg2 := &Config{Targets: []Target{{Name: "x", Host: "h", Port: 1}}}
	if cfg2.ResolveTarget("anything") != nil {
		t.Error("no default should return nil")
	}
}
