package policy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
)

// ConditionPlugin is a custom, pluggable policy condition.
// Implementations are registered with the global ConditionRegistry and
// can be referenced in policy JSON via the "custom" condition map:
//
//	{
//	  "condition": {
//	    "custom": {
//	      "my_plugin": { "param1": "value1" }
//	    }
//	  }
//	}
type ConditionPlugin interface {
	// Name returns a unique identifier used as the key in the "custom" map.
	Name() string

	// Eval evaluates this condition against the policy context.
	// config is the JSON object from the policy rule's "custom" map.
	// Return true if the condition matches (rule should apply), false otherwise.
	Eval(ctx *Context, config json.RawMessage) (bool, error)
}

// ConditionRegistry manages registered condition plugins.
type ConditionRegistry struct {
	mu      sync.RWMutex
	plugins map[string]ConditionPlugin
}

// GlobalCondRegistry is the default condition plugin registry.
var GlobalCondRegistry = NewConditionRegistry()

// NewConditionRegistry creates a new condition registry.
func NewConditionRegistry() *ConditionRegistry {
	return &ConditionRegistry{
		plugins: make(map[string]ConditionPlugin),
	}
}

// Register adds a condition plugin to the registry.
// Returns an error if a plugin with the same name already exists.
func (r *ConditionRegistry) Register(p ConditionPlugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("condition plugin %q already registered", name)
	}

	r.plugins[name] = p
	slog.Info("condition plugin registered", "name", name)
	return nil
}

// Get returns a condition plugin by name, or nil if not found.
func (r *ConditionRegistry) Get(name string) ConditionPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugins[name]
}

// List returns all registered condition plugin names.
func (r *ConditionRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// Count returns the number of registered condition plugins.
func (r *ConditionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins)
}
