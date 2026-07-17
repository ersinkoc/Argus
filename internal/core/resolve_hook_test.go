package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeResolver implements IdentityResolver for tests.
type fakeResolver struct {
	resolved *ResolvedIdentity
	err      error
	got      *ResolveIdentity
}

func (f *fakeResolver) Resolve(_ context.Context, id *ResolveIdentity) (*ResolvedIdentity, error) {
	f.got = id
	return f.resolved, f.err
}

func testHookContext() *HookContext {
	return &HookContext{
		Stage: HookPostAuth,
		Session: &SessionSnapshot{
			ID:       "sess-1",
			Username: "alice",
			Database: "orders",
			ClientIP: "10.1.2.3",
			Roles:    []string{"dev"},
		},
	}
}

func TestIdentityResolverHookName(t *testing.T) {
	hook := NewIdentityResolverHook(&fakeResolver{})
	if hook.Name() != "identity-resolver" {
		t.Fatalf("Name() = %q, want identity-resolver", hook.Name())
	}
	if hook.timeout != 10*time.Second {
		t.Fatalf("default timeout = %v, want 10s", hook.timeout)
	}
}

func TestIdentityResolverHookPostAuthNilResolver(t *testing.T) {
	hook := NewIdentityResolverHook(nil)
	if err := hook.PostAuth(testHookContext()); err != nil {
		t.Fatalf("PostAuth with nil resolver returned error: %v", err)
	}
}

func TestIdentityResolverHookPostAuthSuccess(t *testing.T) {
	resolver := &fakeResolver{
		resolved: &ResolvedIdentity{
			Host: "db.internal", Port: 5432,
			Username: "svc_alice", Password: "pw",
			Roles: []string{"reader"},
		},
	}
	hook := NewIdentityResolverHook(resolver)

	if err := hook.PostAuth(testHookContext()); err != nil {
		t.Fatalf("PostAuth returned error: %v", err)
	}
	if resolver.got == nil {
		t.Fatal("resolver was not called")
	}
	if resolver.got.Username != "alice" {
		t.Fatalf("resolver identity username = %q, want alice", resolver.got.Username)
	}
	if resolver.got.Database != "orders" {
		t.Fatalf("resolver identity database = %q, want orders", resolver.got.Database)
	}
	if resolver.got.ClientIP != "10.1.2.3" {
		t.Fatalf("resolver identity client IP = %q, want 10.1.2.3", resolver.got.ClientIP)
	}
}

func TestIdentityResolverHookPostAuthNilResolved(t *testing.T) {
	// A resolver may return (nil, nil); the hook must treat this as success.
	hook := NewIdentityResolverHook(&fakeResolver{})
	if err := hook.PostAuth(testHookContext()); err != nil {
		t.Fatalf("PostAuth with nil resolved identity returned error: %v", err)
	}
}

func TestIdentityResolverHookPostAuthError(t *testing.T) {
	hook := NewIdentityResolverHook(&fakeResolver{err: errors.New("upstream down")})
	err := hook.PostAuth(testHookContext())
	if err == nil {
		t.Fatal("expected error from PostAuth")
	}
	if !strings.Contains(err.Error(), "identity resolution failed") {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), "identity resolution failed")
	}
	if !strings.Contains(err.Error(), "upstream down") {
		t.Fatalf("error = %q, want it to wrap the resolver error", err.Error())
	}
}

func TestIdentityResolverHookNoOpStages(t *testing.T) {
	hook := NewIdentityResolverHook(&fakeResolver{err: errors.New("never called")})
	if err := hook.PreEval(nil); err != nil {
		t.Fatalf("PreEval returned error: %v", err)
	}
	if err := hook.PostEval(nil); err != nil {
		t.Fatalf("PostEval returned error: %v", err)
	}
	if err := hook.PostExec(nil); err != nil {
		t.Fatalf("PostExec returned error: %v", err)
	}
}

func TestSetPipelineHooks(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	hook := NewIdentityResolverHook(&fakeResolver{})
	proxy.SetPipelineHooks(hook)
	if got := proxy.hookChain.Count(); got != 1 {
		t.Fatalf("hook count = %d, want 1", got)
	}

	// Each call replaces the previous chain entirely.
	proxy.SetPipelineHooks(hook, NewIdentityResolverHook(&fakeResolver{}))
	if got := proxy.hookChain.Count(); got != 2 {
		t.Fatalf("hook count after replace = %d, want 2", got)
	}

	proxy.SetPipelineHooks()
	if got := proxy.hookChain.Count(); got != 0 {
		t.Fatalf("hook count after empty replace = %d, want 0", got)
	}
}

func TestSetIdentityResolver(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	if proxy.identityResolver != nil {
		t.Fatal("identity resolver should be nil by default")
	}
	resolver := &fakeResolver{}
	proxy.SetIdentityResolver(resolver)
	if proxy.identityResolver != IdentityResolver(resolver) {
		t.Fatal("SetIdentityResolver did not store the resolver")
	}
}
