package policy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

// ── Mock condition plugin ──────────────────────────────────────────────

type mockConditionPlugin struct {
	name      string
	evalFn    func(ctx *Context, config json.RawMessage) (bool, error)
	evalCalls int
}

func (m *mockConditionPlugin) Name() string { return m.name }

func (m *mockConditionPlugin) Eval(ctx *Context, config json.RawMessage) (bool, error) {
	m.evalCalls++
	if m.evalFn != nil {
		return m.evalFn(ctx, config)
	}
	return true, nil
}

// ── ConditionRegistry tests ────────────────────────────────────────────

func TestConditionRegistryRegisterAndGet(t *testing.T) {
	r := NewConditionRegistry()
	p := &mockConditionPlugin{name: "test_plugin"}

	if err := r.Register(p); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	got := r.Get("test_plugin")
	if got == nil {
		t.Fatal("Get returned nil for registered plugin")
	}
	if got.Name() != "test_plugin" {
		t.Errorf("got name %q, want %q", got.Name(), "test_plugin")
	}
}

func TestConditionRegistryDuplicate(t *testing.T) {
	r := NewConditionRegistry()
	r.Register(&mockConditionPlugin{name: "dup"})

	err := r.Register(&mockConditionPlugin{name: "dup"})
	if err == nil {
		t.Fatal("expected error for duplicate registration")
	}
}

func TestConditionRegistryGetUnknown(t *testing.T) {
	r := NewConditionRegistry()
	if p := r.Get("nonexistent"); p != nil {
		t.Error("Get for unknown plugin should return nil")
	}
}

func TestConditionRegistryListAndCount(t *testing.T) {
	r := NewConditionRegistry()
	r.Register(&mockConditionPlugin{name: "a"})
	r.Register(&mockConditionPlugin{name: "b"})

	if n := r.Count(); n != 2 {
		t.Errorf("Count = %d, want 2", n)
	}

	names := r.List()
	if len(names) != 2 {
		t.Fatalf("List len = %d, want 2", len(names))
	}
}

// ── Custom condition evaluation via matchCondition ─────────────────────

func TestMatchConditionCustomPluginMatch(t *testing.T) {
	// Register a test plugin that matches when username is "allowed_user"
	p := &mockConditionPlugin{
		name: "test_user_check",
		evalFn: func(ctx *Context, config json.RawMessage) (bool, error) {
			var cfg struct {
				AllowedUser string `json:"allowed_user"`
			}
			json.Unmarshal(config, &cfg)
			return ctx.Username == cfg.AllowedUser, nil
		},
	}

	// Use a fresh registry to avoid conflicts with init()-registered plugins
	orig := GlobalCondRegistry
	GlobalCondRegistry = NewConditionRegistry()
	defer func() { GlobalCondRegistry = orig }()

	GlobalCondRegistry.Register(p)

	raw := json.RawMessage(`{"allowed_user": "alice"}`)
	cond := &ConditionConfig{Custom: map[string]json.RawMessage{
		"test_user_check": raw,
	}}

	ctx := &Context{
		Username:    "alice",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}

	if !matchCondition(ctx, cond) {
		t.Error("expected match for alice")
	}

	ctx.Username = "bob"
	if matchCondition(ctx, cond) {
		t.Error("expected no match for bob")
	}
}

func TestMatchConditionCustomPluginUnknown(t *testing.T) {
	// Unknown plugin should fail match (safety: fail-closed)
	raw := json.RawMessage(`{}`)
	cond := &ConditionConfig{Custom: map[string]json.RawMessage{
		"nonexistent_plugin": raw,
	}}

	ctx := &Context{Username: "u", Timestamp: time.Now()}
	if matchCondition(ctx, cond) {
		t.Error("unknown plugin should not match")
	}
}

func TestMatchConditionCustomPluginError(t *testing.T) {
	p := &mockConditionPlugin{
		name: "err_plugin",
		evalFn: func(ctx *Context, config json.RawMessage) (bool, error) {
			return false, nil // always returns no-match, no error
		},
	}

	orig := GlobalCondRegistry
	GlobalCondRegistry = NewConditionRegistry()
	defer func() { GlobalCondRegistry = orig }()

	GlobalCondRegistry.Register(p)

	raw := json.RawMessage(`{}`)
	cond := &ConditionConfig{Custom: map[string]json.RawMessage{
		"err_plugin": raw,
	}}

	ctx := &Context{Username: "u", Timestamp: time.Now()}
	if matchCondition(ctx, cond) {
		t.Error("plugin returning false should not match")
	}
}

// ── Integration: custom condition through Engine.Evaluate ──────────────

func TestEngineEvaluateWithCustomCondition(t *testing.T) {
	p := &mockConditionPlugin{
		name: "block_if_admin",
		evalFn: func(ctx *Context, config json.RawMessage) (bool, error) {
			for _, role := range ctx.Roles {
				if role == "admin" {
					return true, nil // matches → block
				}
			}
			return false, nil
		},
	}

	orig := GlobalCondRegistry
	GlobalCondRegistry = NewConditionRegistry()
	defer func() { GlobalCondRegistry = orig }()

	GlobalCondRegistry.Register(p)

	// The engine resolves roles from the PolicySet's Roles map, so we must
	// define the role-to-user mapping there rather than passing ctx.Roles directly.
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles: map[string]Role{
			"admin": {Users: []string{"superuser"}},
			"user":  {Users: []string{"regular"}},
		},
		Policies: []PolicyRule{{
			Name:   "block-admin",
			Match:  MatchConfig{},
			Action: "block",
			Condition: &ConditionConfig{
				Custom: map[string]json.RawMessage{
					"block_if_admin": json.RawMessage(`{}`),
				},
			},
		}},
	}

	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	// Admin user should be blocked (plugin matches admin role → rule applies)
	ctx := &Context{
		Username:    "superuser",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionBlock {
		t.Errorf("admin user: expected block, got %s", d.Action)
	}

	// Regular user should be allowed by default (plugin doesn't match → default allow)
	ctx2 := &Context{
		Username:    "regular",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d2 := engine.Evaluate(ctx2)
	if d2.Action != ActionAllow {
		t.Errorf("regular user: expected allow, got %s", d2.Action)
	}
}
