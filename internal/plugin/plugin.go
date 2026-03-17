package plugin

import (
	"fmt"
	"log"
	"sync"
)

// Type identifies the kind of plugin.
type Type string

const (
	TypeTransformer    Type = "transformer"    // custom masking transformer
	TypePolicyProvider Type = "policy_provider" // external policy source
	TypeAuditWriter    Type = "audit_writer"    // custom audit output
	TypeAuthProvider   Type = "auth_provider"   // custom identity provider
)

// Plugin is the interface all plugins must implement.
type Plugin interface {
	Name() string
	Type() Type
	Init(config map[string]any) error
	Close() error
}

// TransformerPlugin extends masking with custom transformers.
type TransformerPlugin interface {
	Plugin
	Transform(value []byte, columnName string) []byte
}

// AuditWriterPlugin sends audit events to custom destinations.
type AuditWriterPlugin interface {
	Plugin
	WriteEvent(event map[string]any) error
}

// Registry manages loaded plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// NewRegistry creates a plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds a plugin to the registry.
func (r *Registry) Register(p Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %q already registered", name)
	}

	r.plugins[name] = p
	log.Printf("[argus] plugin registered: %s (type: %s)", name, p.Type())
	return nil
}

// Get returns a plugin by name.
func (r *Registry) Get(name string) Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugins[name]
}

// GetTransformers returns all transformer plugins.
func (r *Registry) GetTransformers() []TransformerPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []TransformerPlugin
	for _, p := range r.plugins {
		if tp, ok := p.(TransformerPlugin); ok {
			result = append(result, tp)
		}
	}
	return result
}

// GetAuditWriters returns all audit writer plugins.
func (r *Registry) GetAuditWriters() []AuditWriterPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []AuditWriterPlugin
	for _, p := range r.plugins {
		if aw, ok := p.(AuditWriterPlugin); ok {
			result = append(result, aw)
		}
	}
	return result
}

// List returns all registered plugin names and types.
func (r *Registry) List() map[string]Type {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]Type, len(r.plugins))
	for name, p := range r.plugins {
		result[name] = p.Type()
	}
	return result
}

// Count returns the number of registered plugins.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins)
}

// CloseAll closes all registered plugins.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for name, p := range r.plugins {
		if err := p.Close(); err != nil {
			log.Printf("[argus] plugin %s close error: %v", name, err)
		}
	}
}
