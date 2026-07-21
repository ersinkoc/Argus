package core

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// IdentityResolver resolves session identity to a backend target and credential.
// Implementations call an external /api/db/resolve endpoint, a Vault plugin,
// or any other identity provider.
//
// This is the bridge between Argus (Go) and Monopam (.NET) or any credential
// injection provider. Currently in development — the actual credential injection
// requires per-protocol auth server support (SCRAM-SHA-256, caching_sha2, etc.)
// and is wired through the PipelineHook.PostAuth extension point.
type IdentityResolver interface {
	// Resolve takes session identity and returns the target database and credential.
	// Returning an error causes the connection to be rejected.
	Resolve(ctx context.Context, identity *ResolveIdentity) (*ResolvedIdentity, error)
}

// ResolveIdentity carries the session identity known after the protocol handshake.
type ResolveIdentity struct {
	Username string
	Database string
	ClientIP string
	Protocol string
}

// ResolvedIdentity is the result of identity resolution.
type ResolvedIdentity struct {
	// Host is the backend hostname or IP (e.g. "db-primary.internal").
	Host string
	// Port is the backend port (e.g. 5432).
	Port int
	// Username is the database user to authenticate as.
	Username string
	// Password is the backend database password fetched from the credential store.
	Password string
	// ClientSecret authenticates the client to Argus; it is never sent upstream.
	ClientSecret string
	// AuthMethod is the protocol-specific auth method hint.
	AuthMethod string
	// Roles to assign in addition to policy-resolved roles.
	Roles []string
	// Principal is a stable acting identity (e.g. Monopam userId / access-key id) for per-user rate
	// limiting; the wire username is an opaque per-session handle.
	Principal string
}

// IdentityResolverHook is a PipelineHook that calls an IdentityResolver after
// the protocol handshake to perform identity resolution and credential injection.
//
// When registered via Proxy.SetPipelineHooks(), this hook runs after every
// successful database handshake, before the command loop begins.
// If the resolver returns an error, the connection is terminated.
type IdentityResolverHook struct {
	resolver IdentityResolver
	timeout  time.Duration
}

// NewIdentityResolverHook creates a new PostAuth hook using the given resolver.
// Default timeout is 10 seconds.
func NewIdentityResolverHook(resolver IdentityResolver) *IdentityResolverHook {
	return &IdentityResolverHook{
		resolver: resolver,
		timeout:  10 * time.Second,
	}
}

// Name returns the hook identifier.
func (h *IdentityResolverHook) Name() string { return "identity-resolver" }

// PostAuth implements PipelineHook.PostAuth.
func (h *IdentityResolverHook) PostAuth(hctx *HookContext) error {
	if h.resolver == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	identity := &ResolveIdentity{
		Username: hctx.Session.Username,
		Database: hctx.Session.Database,
		ClientIP: hctx.Session.ClientIP,
	}

	resolved, err := h.resolver.Resolve(ctx, identity)
	if err != nil {
		return fmt.Errorf("identity resolution failed: %w", err)
	}

	if resolved != nil {
		slog.Info("identity resolved",
			"username", hctx.Session.Username,
			"target", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port),
			"db_user", resolved.Username,
			"roles", resolved.Roles,
		)
	}

	return nil
}

// PreEval implements PipelineHook.PreEval (no-op).
func (h *IdentityResolverHook) PreEval(_ *HookContext) error { return nil }

// PostEval implements PipelineHook.PostEval (no-op).
func (h *IdentityResolverHook) PostEval(_ *HookContext) error { return nil }

// PostExec implements PipelineHook.PostExec (no-op).
func (h *IdentityResolverHook) PostExec(_ *HookContext) error { return nil }
