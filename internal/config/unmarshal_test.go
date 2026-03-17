package config

import (
	"encoding/json"
	"testing"
)

func TestPoolConfigUnmarshalErrors(t *testing.T) {
	// Invalid duration
	data := []byte(`{"max_connections_per_target":10,"connection_max_lifetime":"invalid"}`)
	var pc PoolConfig
	err := json.Unmarshal(data, &pc)
	if err == nil {
		t.Error("invalid duration should error")
	}

	data = []byte(`{"max_connections_per_target":10,"connection_timeout":"bad"}`)
	err = json.Unmarshal(data, &pc)
	if err == nil {
		t.Error("invalid connection_timeout should error")
	}

	data = []byte(`{"max_connections_per_target":10,"health_check_interval":"nope"}`)
	err = json.Unmarshal(data, &pc)
	if err == nil {
		t.Error("invalid health_check_interval should error")
	}
}

func TestSessionConfigUnmarshalErrors(t *testing.T) {
	data := []byte(`{"idle_timeout":"invalid"}`)
	var sc SessionConfig
	err := json.Unmarshal(data, &sc)
	if err == nil {
		t.Error("invalid idle_timeout should error")
	}

	data = []byte(`{"max_duration":"bad"}`)
	err = json.Unmarshal(data, &sc)
	if err == nil {
		t.Error("invalid max_duration should error")
	}
}

func TestPolicyConfigUnmarshalError(t *testing.T) {
	data := []byte(`{"reload_interval":"bad"}`)
	var pc PolicyConfig
	err := json.Unmarshal(data, &pc)
	if err == nil {
		t.Error("invalid reload_interval should error")
	}
}

func TestPolicyConfigUnmarshalDefault(t *testing.T) {
	data := []byte(`{"files":["a.json"]}`)
	var pc PolicyConfig
	err := json.Unmarshal(data, &pc)
	if err != nil {
		t.Fatal(err)
	}
	if pc.ReloadInterval.Seconds() != 5 {
		t.Errorf("default reload = %v, want 5s", pc.ReloadInterval)
	}
}
