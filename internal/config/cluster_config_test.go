package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClusterConfigUnmarshal(t *testing.T) {
	var c ClusterConfig
	data := `{"enabled": true, "node_id": "argus-1", "session_ttl": "2m"}`
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !c.Enabled || c.NodeID != "argus-1" || c.SessionTTL != 2*time.Minute {
		t.Fatalf("config = %+v, want enabled/argus-1/2m", c)
	}
}

func TestClusterConfigUnmarshalDefaults(t *testing.T) {
	var c ClusterConfig
	if err := json.Unmarshal([]byte(`{}`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Enabled || c.NodeID != "" || c.SessionTTL != 0 {
		t.Fatalf("config = %+v, want zero values", c)
	}
}

func TestClusterConfigUnmarshalInvalidTTL(t *testing.T) {
	var c ClusterConfig
	err := json.Unmarshal([]byte(`{"session_ttl": "not-a-duration"}`), &c)
	if err == nil || !strings.Contains(err.Error(), "invalid session_ttl") {
		t.Fatalf("err = %v, want invalid session_ttl", err)
	}
}

func TestClusterConfigUnmarshalNegativeTTL(t *testing.T) {
	var c ClusterConfig
	err := json.Unmarshal([]byte(`{"session_ttl": "-5s"}`), &c)
	if err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("err = %v, want negative duration error", err)
	}
}

func TestClusterConfigUnmarshalBadJSON(t *testing.T) {
	var c ClusterConfig
	if err := json.Unmarshal([]byte(`{"enabled": "yes"}`), &c); err == nil {
		t.Fatal("expected type error for enabled")
	}
}
