package core

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/ersinkoc/argus/internal/policy"
)

// ── Mock pipeline hook ─────────────────────────────────────────────────

type mockHook struct {
	name        string
	preEvalFn   func(hctx *HookContext) error
	postEvalFn  func(hctx *HookContext) error
	postExecFn  func(hctx *HookContext) error
	callCount   atomic.Int64
}

func (m *mockHook) Name() string { return m.name }

func (m *mockHook) PreEval(hctx *HookContext) error {
	m.callCount.Add(1)
	if m.preEvalFn != nil {
		return m.preEvalFn(hctx)
	}
	return nil
}

func (m *mockHook) PostEval(hctx *HookContext) error {
	m.callCount.Add(1)
	if m.postEvalFn != nil {
		return m.postEvalFn(hctx)
	}
	return nil
}

func (m *mockHook) PostExec(hctx *HookContext) error {
	m.callCount.Add(1)
	if m.postExecFn != nil {
		return m.postExecFn(hctx)
	}
	return nil
}

// ── PipelineHookChain tests ────────────────────────────────────────────

func TestPipelineHookChainAddAndCount(t *testing.T) {
	chain := NewPipelineHookChain()
	if chain.Count() != 0 {
		t.Errorf("empty chain: Count = %d, want 0", chain.Count())
	}

	chain.Add(&mockHook{name: "h1"})
	chain.Add(&mockHook{name: "h2"})

	if chain.Count() != 2 {
		t.Errorf("expected 2 hooks, got %d", chain.Count())
	}
}

func TestPipelineHookChainRunPreEval(t *testing.T) {
	chain := NewPipelineHookChain()
	var callOrder []string
	var mu mockMutex

	h1 := &mockHook{
		name: "hook_a",
		preEvalFn: func(hctx *HookContext) error {
			mu.Lock()
			callOrder = append(callOrder, "a")
			mu.Unlock()
			return nil
		},
	}
	h2 := &mockHook{
		name: "hook_b",
		preEvalFn: func(hctx *HookContext) error {
			mu.Lock()
			callOrder = append(callOrder, "b")
			mu.Unlock()
			return nil
		},
	}

	chain.Add(h1)
	chain.Add(h2)

	hctx := &HookContext{Stage: HookPreEval}
	if err := chain.RunPreEval(hctx); err != nil {
		t.Fatalf("RunPreEval failed: %v", err)
	}

	if len(callOrder) != 2 || callOrder[0] != "a" || callOrder[1] != "b" {
		t.Errorf("call order = %v, want [a b]", callOrder)
	}
}

func TestPipelineHookChainPreEvalErrorStopsChain(t *testing.T) {
	chain := NewPipelineHookChain()
	var hookBCalled bool

	chain.Add(&mockHook{
		name: "failing",
		preEvalFn: func(hctx *HookContext) error {
			return errors.New("fail")
		},
	})
	chain.Add(&mockHook{
		name: "after_fail",
		preEvalFn: func(hctx *HookContext) error {
			hookBCalled = true
			return nil
		},
	})

	hctx := &HookContext{Stage: HookPreEval}
	if err := chain.RunPreEval(hctx); err == nil {
		t.Error("expected error from failing hook")
	}

	if hookBCalled {
		t.Error("second hook should not be called after first fails")
	}
}

func TestPipelineHookChainPostEvalErrorStopsChain(t *testing.T) {
	chain := NewPipelineHookChain()
	var hookBCalled bool

	chain.Add(&mockHook{
		name: "failing",
		postEvalFn: func(hctx *HookContext) error {
			return errors.New("fail")
		},
	})
	chain.Add(&mockHook{
		postEvalFn: func(hctx *HookContext) error {
			hookBCalled = true
			return nil
		},
	})

	hctx := &HookContext{Stage: HookPostEval}
	if err := chain.RunPostEval(hctx); err == nil {
		t.Error("expected error from failing hook")
	}

	if hookBCalled {
		t.Error("second hook should not be called after first fails")
	}
}

func TestPipelineHookChainPostExecDoesNotStopOnError(t *testing.T) {
	chain := NewPipelineHookChain()
	var hookBCalled bool

	chain.Add(&mockHook{
		name: "failing",
		postExecFn: func(hctx *HookContext) error {
			return errors.New("fail")
		},
	})
	chain.Add(&mockHook{
		postExecFn: func(hctx *HookContext) error {
			hookBCalled = true
			return nil
		},
	})

	hctx := &HookContext{Stage: HookPostExec}
	chain.RunPostExec(hctx)

	if !hookBCalled {
		t.Error("second hook should still run after first fails in PostExec")
	}
}

func TestPipelineHookContextStage(t *testing.T) {
	chain := NewPipelineHookChain()
	stages := make(map[string]HookStage)

	chain.Add(&mockHook{
		name: "stage_check",
		preEvalFn: func(hctx *HookContext) error {
			stages["pre"] = hctx.Stage
			if hctx.Session == nil {
				t.Error("PreEval: Session should not be nil")
			}
			return nil
		},
		postEvalFn: func(hctx *HookContext) error {
			stages["posteval"] = hctx.Stage
			if hctx.Decision == nil {
				t.Error("PostEval: Decision should not be nil")
			}
			return nil
		},
		postExecFn: func(hctx *HookContext) error {
			stages["postexec"] = hctx.Stage
			return nil
		},
	})

	chain.RunPreEval(&HookContext{
		Stage:   HookPreEval,
		Session: &SessionSnapshot{ID: "s1"},
	})
	chain.RunPostEval(&HookContext{
		Stage:    HookPostEval,
		Decision: &policy.Decision{},
		Session:  &SessionSnapshot{ID: "s1"},
	})
	chain.RunPostExec(&HookContext{
		Stage:    HookPostExec,
		Decision: &policy.Decision{},
		Session:  &SessionSnapshot{ID: "s1"},
	})

	if stages["pre"] != HookPreEval {
		t.Errorf("pre stage = %v, want %v", stages["pre"], HookPreEval)
	}
	if stages["posteval"] != HookPostEval {
		t.Errorf("posteval stage = %v, want %v", stages["posteval"], HookPostEval)
	}
	if stages["postexec"] != HookPostExec {
		t.Errorf("postexec stage = %v, want %v", stages["postexec"], HookPostExec)
	}
}

func TestPipelineHookChainEmpty(t *testing.T) {
	chain := NewPipelineHookChain()

	// Should not panic
	if err := chain.RunPreEval(&HookContext{}); err != nil {
		t.Errorf("empty chain RunPreEval: %v", err)
	}
	if err := chain.RunPostEval(&HookContext{}); err != nil {
		t.Errorf("empty chain RunPostEval: %v", err)
	}
	chain.RunPostExec(&HookContext{})
}

// ── Helper for concurrent test safety ──────────────────────────────────

type mockMutex struct {
	ch chan struct{}
}

func (m *mockMutex) Lock() {
	if m.ch == nil {
		m.ch = make(chan struct{}, 1)
	}
	m.ch <- struct{}{}
}

func (m *mockMutex) Unlock() {
	<-m.ch
}
