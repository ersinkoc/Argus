package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoaderLoad(t *testing.T) {
	dir := t.TempDir()
	policyFile := filepath.Join(dir, "test.json")

	ps := PolicySet{
		Version:  "1",
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{"admin": {Users: []string{"root"}}},
		Policies: []PolicyRule{
			{Name: "allow-all", Match: MatchConfig{}, Action: "allow"},
		},
	}
	data, _ := json.MarshalIndent(ps, "", "  ")
	os.WriteFile(policyFile, data, 0644)

	loader := NewLoader([]string{policyFile}, 5*time.Second)
	err := loader.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	current := loader.Current()
	if current == nil {
		t.Fatal("current should not be nil")
	}
	if current.Version != "1" {
		t.Errorf("version = %q", current.Version)
	}
	if len(current.Policies) != 1 {
		t.Errorf("policies = %d", len(current.Policies))
	}
}

func TestLoaderLoadInvalidFile(t *testing.T) {
	loader := NewLoader([]string{"/nonexistent/file.json"}, 0)
	err := loader.Load()
	if err == nil {
		t.Error("should fail on nonexistent file")
	}
}

func TestLoaderLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid json"), 0644)

	loader := NewLoader([]string{path}, 0)
	err := loader.Load()
	if err == nil {
		t.Error("should fail on invalid JSON")
	}
}

func TestLoaderMultipleFiles(t *testing.T) {
	dir := t.TempDir()

	// File 1: base policies
	f1 := filepath.Join(dir, "base.json")
	base := PolicySet{
		Roles: map[string]Role{"dba": {Users: []string{"admin"}}},
		Policies: []PolicyRule{
			{Name: "base-rule", Action: "allow"},
		},
	}
	d1, _ := json.Marshal(base)
	os.WriteFile(f1, d1, 0644)

	// File 2: overlay
	f2 := filepath.Join(dir, "overlay.json")
	overlay := PolicySet{
		Roles: map[string]Role{"dev": {Users: []string{"dev_*"}}},
		Policies: []PolicyRule{
			{Name: "overlay-rule", Action: "block"},
		},
	}
	d2, _ := json.Marshal(overlay)
	os.WriteFile(f2, d2, 0644)

	loader := NewLoader([]string{f1, f2}, 0)
	err := loader.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	current := loader.Current()
	if len(current.Roles) != 2 {
		t.Errorf("merged roles = %d, want 2", len(current.Roles))
	}
	if len(current.Policies) != 2 {
		t.Errorf("merged policies = %d, want 2", len(current.Policies))
	}
}

func TestLoaderOnReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(`{"version":"1","policies":[]}`), 0644)

	reloaded := false
	loader := NewLoader([]string{path}, 100*time.Millisecond)
	loader.OnReload(func() { reloaded = true })
	loader.Load()

	// Modify file
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, []byte(`{"version":"2","policies":[]}`), 0644)

	loader.Start()
	time.Sleep(300 * time.Millisecond)
	loader.Stop()

	if !reloaded {
		t.Error("should have triggered reload callback")
	}
}

func TestLoaderFilesChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(`{}`), 0644)

	loader := NewLoader([]string{path}, 0)
	loader.Load() // records initial mtime

	if loader.filesChanged() {
		t.Error("should not detect change immediately")
	}

	// Wait and modify
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, []byte(`{"changed":true}`), 0644)

	if !loader.filesChanged() {
		t.Error("should detect file change")
	}
}

func TestEngineLoader(t *testing.T) {
	loader := NewLoader(nil, 0)
	ps := &PolicySet{Defaults: DefaultsConfig{Action: "allow"}}
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	if engine.Loader() != loader {
		t.Error("Loader() should return the loader")
	}
}
