package core

import (
	"log/slog"
	"sync"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/policy"
)

// HookStage identifies the pipeline stage at which a hook is invoked.
type HookStage int

const (
	// HookPreEval runs after the policy context is built but before policy evaluation.
	// Use cases: request enrichment, geo-IP resolution, tenant extraction, custom logging.
	HookPreEval HookStage = iota

	// HookPostEval runs after the policy decision and rate-limit check,
	// but before the action switch (block/allow/mask).
	// Use cases: custom actions (webhook notify, redirect), decision override,
	// approval triggers, metrics export.
	HookPostEval

	// HookPostExec runs after the result is forwarded to the client,
	// audited, and broadcast. The last thing before the next command.
	// Use cases: result transformation audit, custom metrics, external notifications.
	HookPostExec
)

// HookContext carries pipeline state at each hook stage.
// Not all fields are populated at every stage — check HookStage for what's available.
type HookContext struct {
	Stage    HookStage
	Session  *SessionSnapshot
	Command  *inspection.Command
	Decision *policy.Decision
	PolicyCtx *policy.Context
	Error    string // set if the hook itself or a previous stage failed
}

// SessionSnapshot is a read-only snapshot of session state at hook time.
type SessionSnapshot struct {
	ID       string
	Username string
	Database string
	ClientIP string
	Roles    []string
}

// PipelineHook is an extension point in the proxy command pipeline.
// Implementations are registered via Proxy.SetPipelineHooks().
//
// Hook lifecycle:
//
//	ReadCommand → PreEval → PolicyEval → RateLimit → PostEval → ActionSwitch → PostExec
type PipelineHook interface {
	// Name returns a unique identifier for this hook.
	Name() string

	// PreEval is called after the policy context is built, before policy evaluation.
	PreEval(hctx *HookContext) error

	// PostEval is called after the policy decision, before the action switch.
	PostEval(hctx *HookContext) error

	// PostExec is called after the result is forwarded, audited, and broadcast.
	PostExec(hctx *HookContext) error
}

// PipelineHookChain manages an ordered list of pipeline hooks.
type PipelineHookChain struct {
	mu    sync.RWMutex
	hooks []PipelineHook
}

// NewPipelineHookChain creates an empty hook chain.
func NewPipelineHookChain() *PipelineHookChain {
	return &PipelineHookChain{}
}

// Add appends a hook to the chain.
func (c *PipelineHookChain) Add(hook PipelineHook) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hooks = append(c.hooks, hook)
	slog.Info("pipeline hook registered", "name", hook.Name())
}

// RunPreEval invokes all registered PreEval hooks in order.
// If any hook returns an error, remaining hooks are skipped.
func (c *PipelineHookChain) RunPreEval(hctx *HookContext) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, h := range c.hooks {
		if err := h.PreEval(hctx); err != nil {
			slog.Warn("pipeline hook PreEval failed", "name", h.Name(), "error", err)
			return err
		}
	}
	return nil
}

// RunPostEval invokes all registered PostEval hooks in order.
func (c *PipelineHookChain) RunPostEval(hctx *HookContext) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, h := range c.hooks {
		if err := h.PostEval(hctx); err != nil {
			slog.Warn("pipeline hook PostEval failed", "name", h.Name(), "error", err)
			return err
		}
	}
	return nil
}

// RunPostExec invokes all registered PostExec hooks in order.
func (c *PipelineHookChain) RunPostExec(hctx *HookContext) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, h := range c.hooks {
		if err := h.PostExec(hctx); err != nil {
			slog.Warn("pipeline hook PostExec failed", "name", h.Name(), "error", err)
		}
	}
}

// Count returns the number of registered hooks.
func (c *PipelineHookChain) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.hooks)
}
