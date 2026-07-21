package config

import (
	"os"
	"testing"
)

// Load("-") reads the config JSON from stdin (in-memory delivery, no file on disk).
func TestLoadFromStdin(t *testing.T) {
	content := `{
		"server": {"listeners": [{"address": ":30100", "protocol": "postgresql"}]},
		"targets": [{"name": "t", "host": "127.0.0.1", "port": 5432, "protocol": "postgresql"}],
		"routing": {"default_target": "t"},
		"pool": {"max_connections_per_target": 20, "min_idle_connections": 1, "connection_max_lifetime": "30m", "connection_timeout": "5s", "health_check_interval": "10s"},
		"session": {"idle_timeout": "10m", "max_duration": "1h"},
		"audit": {"level": "verbose", "outputs": [{"type": "stdout"}], "buffer_size": 1000, "sql_max_length": 2048}
	}`

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	go func() {
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()

	cfg, err := Load("-")
	if err != nil {
		t.Fatalf("Load(-): %v", err)
	}
	if len(cfg.Server.Listeners) != 1 || cfg.Server.Listeners[0].Address != ":30100" {
		t.Fatalf("listeners = %+v", cfg.Server.Listeners)
	}
	if cfg.Server.Listeners[0].Protocol != "postgresql" {
		t.Fatalf("protocol = %q", cfg.Server.Listeners[0].Protocol)
	}
}
