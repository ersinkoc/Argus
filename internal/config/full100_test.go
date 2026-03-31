package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// --- UnmarshalJSON error paths for invalid base JSON ---

func TestPolicyConfigUnmarshalInvalidJSON(t *testing.T) {
	// Line 112-114: json.Unmarshal returns error - type mismatch triggers error inside UnmarshalJSON
	var pc PolicyConfig
	// "files" expects []string but gets a number - triggers unmarshal error inside the method
	err := json.Unmarshal([]byte(`{"files": 12345}`), &pc)
	if err == nil {
		t.Error("expected error for type mismatch in PolicyConfig.UnmarshalJSON")
	}
}

func TestPoolConfigUnmarshalInvalidJSON(t *testing.T) {
	// Line 149-151: json.Unmarshal returns error - type mismatch triggers error inside UnmarshalJSON
	var pc PoolConfig
	// "max_connections_per_target" expects int but gets an array - triggers unmarshal error inside the method
	err := json.Unmarshal([]byte(`{"max_connections_per_target": "not-int"}`), &pc)
	if err == nil {
		t.Error("expected error for type mismatch in PoolConfig.UnmarshalJSON")
	}
}

func TestSessionConfigUnmarshalInvalidJSON(t *testing.T) {
	// Line 211-213: json.Unmarshal returns error - type mismatch triggers error inside UnmarshalJSON
	var sc SessionConfig
	// "max_per_user" expects int but gets a string - triggers unmarshal error inside the method
	err := json.Unmarshal([]byte(`{"max_per_user": "not-int"}`), &sc)
	if err == nil {
		t.Error("expected error for type mismatch in SessionConfig.UnmarshalJSON")
	}
}

// --- PoolConfig.UnmarshalJSON: CircuitBreakerResetTimeout ---

func TestPoolConfigUnmarshalCircuitBreakerResetTimeout(t *testing.T) {
	// Line 174-178: cover both the valid and invalid circuit_breaker_reset_timeout paths
	t.Run("valid duration", func(t *testing.T) {
		data := []byte(`{"max_connections_per_target":10,"circuit_breaker_reset_timeout":"30s"}`)
		var pc PoolConfig
		if err := json.Unmarshal(data, &pc); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pc.CircuitBreakerResetTimeout.Seconds() != 30 {
			t.Errorf("got %v, want 30s", pc.CircuitBreakerResetTimeout)
		}
	})

	t.Run("invalid duration", func(t *testing.T) {
		data := []byte(`{"max_connections_per_target":10,"circuit_breaker_reset_timeout":"not-a-duration"}`)
		var pc PoolConfig
		err := json.Unmarshal(data, &pc)
		if err == nil {
			t.Error("expected error for invalid circuit_breaker_reset_timeout")
		}
	})
}

// --- Load: validation failure after successful parse ---

func TestLoadValidationFailure(t *testing.T) {
	// Line 317-319: config parses OK but fails validation
	// No listeners = validation error
	content := `{
		"server": {"listeners": []},
		"pool": {"max_connections_per_target": 10}
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "bad_valid.json")
	os.WriteFile(path, []byte(content), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected validation error from Load")
	}
}

// --- expandEnvInConfig: routing rules and gateway API keys ---

func TestExpandEnvInConfigRoutingRules(t *testing.T) {
	// Line 418-421: routing rules env expansion
	t.Setenv("TEST_RULE_DB", "my_database")
	t.Setenv("TEST_RULE_TARGET", "my_target")

	cfg := &Config{
		Server: ServerConfig{
			Listeners: []ListenerConfig{{Address: ":5432"}},
		},
		Routing: RoutingConfig{
			Rules: []RoutingRule{
				{Database: "$ENV{TEST_RULE_DB}", Target: "$ENV{TEST_RULE_TARGET}"},
			},
		},
	}

	expandEnvInConfig(cfg)

	if cfg.Routing.Rules[0].Database != "my_database" {
		t.Errorf("database = %q, want 'my_database'", cfg.Routing.Rules[0].Database)
	}
	if cfg.Routing.Rules[0].Target != "my_target" {
		t.Errorf("target = %q, want 'my_target'", cfg.Routing.Rules[0].Target)
	}
}

func TestExpandEnvInConfigGatewayAPIKeys(t *testing.T) {
	// Line 438-440: gateway API keys env expansion
	t.Setenv("TEST_API_KEY", "secret-key-123")

	cfg := &Config{
		Server: ServerConfig{
			Listeners: []ListenerConfig{{Address: ":5432"}},
		},
		Gateway: GatewayConfig{
			APIKeys: []APIKeyConfig{
				{Key: "$ENV{TEST_API_KEY}", Username: "user1"},
			},
		},
	}

	expandEnvInConfig(cfg)

	if cfg.Gateway.APIKeys[0].Key != "secret-key-123" {
		t.Errorf("key = %q, want 'secret-key-123'", cfg.Gateway.APIKeys[0].Key)
	}
}

// --- Validate: gateway validation block ---

func TestValidateGatewayEnabledNoTargets(t *testing.T) {
	// Line 549-552: gateway enabled but no targets
	cfg := DefaultConfig()
	cfg.Server.Listeners[0].Protocol = "" // avoid protocol mismatch check
	cfg.Gateway.Enabled = true
	cfg.Targets = nil

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error: gateway enabled but no targets")
	}
}

func TestValidateGatewayAPIKeyEmpty(t *testing.T) {
	// Line 554-557: API key with empty key field
	cfg := DefaultConfig()
	cfg.Gateway.Enabled = true
	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 5432, Protocol: "postgresql"}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Gateway.APIKeys = []APIKeyConfig{
		{Key: "", Username: "user1", Enabled: true},
	}

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error: API key is empty")
	}
}

func TestValidateGatewayAPIKeyEmptyUsername(t *testing.T) {
	// Line 558-560: API key with empty username
	cfg := DefaultConfig()
	cfg.Gateway.Enabled = true
	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 5432, Protocol: "postgresql"}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Gateway.APIKeys = []APIKeyConfig{
		{Key: "some-key", Username: "", Enabled: true},
	}

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error: API key username is empty")
	}
}

func TestValidateGatewayDuplicateAPIKey(t *testing.T) {
	// Line 561-563: duplicate API keys
	cfg := DefaultConfig()
	cfg.Gateway.Enabled = true
	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 5432, Protocol: "postgresql"}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Gateway.APIKeys = []APIKeyConfig{
		{Key: "same-key", Username: "user1", Enabled: true},
		{Key: "same-key", Username: "user2", Enabled: true},
	}

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error: duplicate API keys")
	}
}

func TestValidateGatewayValidAPIKeys(t *testing.T) {
	// Line 564: seenKeys[key.Key] = i (success path through entire gateway block)
	cfg := DefaultConfig()
	cfg.Gateway.Enabled = true
	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 5432, Protocol: "postgresql"}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Gateway.APIKeys = []APIKeyConfig{
		{Key: "key1", Username: "user1", Enabled: true},
		{Key: "key2", Username: "user2", Enabled: true},
	}

	err := Validate(cfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateGatewayEnabledNoAPIKeys(t *testing.T) {
	// Gateway enabled with targets but no API keys (valid, just no keys)
	cfg := DefaultConfig()
	cfg.Gateway.Enabled = true
	cfg.Targets = []Target{{Name: "t", Host: "h", Port: 5432, Protocol: "postgresql"}}
	cfg.Routing.DefaultTarget = "t"

	err := Validate(cfg)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Load end-to-end with gateway config to cover expandEnvInConfig gateway path ---

func TestLoadWithGatewayConfig(t *testing.T) {
	t.Setenv("GW_KEY", "loaded-key")

	content := `{
		"server": {"listeners": [{"address": ":5432", "protocol": "postgresql"}]},
		"targets": [{"name": "t", "host": "h", "port": 5432, "protocol": "postgresql"}],
		"routing": {
			"default_target": "t",
			"rules": [{"database": "test_db", "target": "t"}]
		},
		"pool": {"max_connections_per_target": 10, "connection_max_lifetime": "1h", "connection_timeout": "5s", "health_check_interval": "30s"},
		"gateway": {
			"enabled": true,
			"api_keys": [{"key": "$ENV{GW_KEY}", "username": "gw_user", "enabled": true}]
		},
		"metrics": {"enabled": false}
	}`

	dir := t.TempDir()
	path := filepath.Join(dir, "gw.json")
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Gateway.APIKeys[0].Key != "loaded-key" {
		t.Errorf("gateway API key = %q, want 'loaded-key'", cfg.Gateway.APIKeys[0].Key)
	}
}
