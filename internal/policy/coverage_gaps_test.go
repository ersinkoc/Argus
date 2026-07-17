package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ── engine.go: decisionCache.set — update existing key ─────────────────

func TestDecisionCacheSetUpdatesExistingKey(t *testing.T) {
	c := newDecisionCache(10, time.Minute)

	d1 := &Decision{Action: ActionAllow, PolicyName: "first"}
	d2 := &Decision{Action: ActionBlock, PolicyName: "second"}

	c.set("k", d1)
	c.set("k", d2)

	got, ok := c.get("k")
	if !ok {
		t.Fatal("expected cache hit after update")
	}
	if got.PolicyName != "second" {
		t.Errorf("PolicyName = %q, want %q", got.PolicyName, "second")
	}
	if c.order.Len() != 1 {
		t.Errorf("order.Len() = %d, want 1 (update must not add a new entry)", c.order.Len())
	}
	if len(c.entries) != 1 {
		t.Errorf("len(entries) = %d, want 1", len(c.entries))
	}
}

// ── engine.go: decisionCache.evictLRU — empty cache ────────────────────

func TestDecisionCacheEvictLRUEmpty(t *testing.T) {
	c := newDecisionCache(10, time.Minute)
	// Must not panic when there is nothing to evict.
	c.evictLRU()
	if c.order.Len() != 0 || len(c.entries) != 0 {
		t.Errorf("empty cache changed: order=%d entries=%d", c.order.Len(), len(c.entries))
	}
}

// ── engine.go: decisionCache.set — LRU eviction when full ──────────────

func TestDecisionCacheLRUEviction(t *testing.T) {
	c := newDecisionCache(2, time.Minute)

	c.set("a", &Decision{PolicyName: "a"})
	c.set("b", &Decision{PolicyName: "b"})

	// Touch "a" so "b" becomes the least recently used entry.
	if _, ok := c.get("a"); !ok {
		t.Fatal("expected hit for a")
	}

	c.set("c", &Decision{PolicyName: "c"})

	if _, ok := c.get("b"); ok {
		t.Error("LRU entry b should have been evicted")
	}
	if _, ok := c.get("a"); !ok {
		t.Error("recently used entry a should survive eviction")
	}
	if _, ok := c.get("c"); !ok {
		t.Error("newly inserted entry c should be present")
	}
}

// ── engine.go: decisionCache.set — periodic cleanup + purgeExpired ─────

func TestDecisionCachePurgeExpired(t *testing.T) {
	c := newDecisionCache(10, time.Minute)

	c.set("a", &Decision{PolicyName: "a"})
	c.set("b", &Decision{PolicyName: "b"})
	c.set("c", &Decision{PolicyName: "c"})

	// Expire "a" and "c" directly (no sleeping) so purgeExpired hits both
	// the remove branch and the keep branch while walking the list.
	past := time.Now().Add(-time.Second)
	c.entries["a"].Value.(*cacheEntry).expiry = past
	c.entries["c"].Value.(*cacheEntry).expiry = past

	// Force the periodic cleanup path in set().
	c.lastCleanup = time.Now().Add(-2 * time.Minute)

	c.set("d", &Decision{PolicyName: "d"})

	if _, ok := c.entries["a"]; ok {
		t.Error("expired entry a should have been purged")
	}
	if _, ok := c.entries["c"]; ok {
		t.Error("expired entry c should have been purged")
	}
	if _, ok := c.get("b"); !ok {
		t.Error("unexpired entry b should survive purge")
	}
	if _, ok := c.get("d"); !ok {
		t.Error("newly inserted entry d should be present")
	}
	if c.order.Len() != 2 {
		t.Errorf("order.Len() = %d, want 2", c.order.Len())
	}
}

// ── matcher.go: matchCondition — custom plugin returning an error ──────

func TestMatchConditionCustomPluginEvalError(t *testing.T) {
	p := &mockConditionPlugin{
		name: "boom_plugin",
		evalFn: func(ctx *Context, config json.RawMessage) (bool, error) {
			return true, errTestBoom
		},
	}

	orig := GlobalCondRegistry
	GlobalCondRegistry = NewConditionRegistry()
	defer func() { GlobalCondRegistry = orig }()

	GlobalCondRegistry.Register(p)

	cond := &ConditionConfig{Custom: map[string]json.RawMessage{
		"boom_plugin": json.RawMessage(`{}`),
	}}

	ctx := &Context{Username: "u", Timestamp: time.Now()}
	if matchCondition(ctx, cond) {
		t.Error("plugin error should fail the condition (fail-closed)")
	}
	if p.evalCalls != 1 {
		t.Errorf("evalCalls = %d, want 1", p.evalCalls)
	}
}

type testBoomError struct{}

func (testBoomError) Error() string { return "boom" }

var errTestBoom = testBoomError{}

// ── plugins_example.go: timeWindowPlugin.Eval ──────────────────────────

func TestTimeWindowPluginInvalidConfig(t *testing.T) {
	p := &timeWindowPlugin{}
	ctx := &Context{Timestamp: time.Now()}

	if _, err := p.Eval(ctx, json.RawMessage(`{bad json`)); err == nil {
		t.Error("invalid JSON config should return error")
	}
}

func TestTimeWindowPluginNoWindows(t *testing.T) {
	p := &timeWindowPlugin{}
	ctx := &Context{Timestamp: time.Now()}

	if _, err := p.Eval(ctx, json.RawMessage(`{"windows":[]}`)); err == nil {
		t.Error("empty windows should return error")
	}
}

func TestTimeWindowPluginInvalidTimezone(t *testing.T) {
	p := &timeWindowPlugin{}
	ctx := &Context{Timestamp: time.Now()}

	raw := json.RawMessage(`{"windows":["09:00-12:00"],"timezone":"Not/AZone"}`)
	if _, err := p.Eval(ctx, raw); err == nil {
		t.Error("invalid timezone should return error")
	}
}

func TestTimeWindowPluginInvalidWindowFormat(t *testing.T) {
	p := &timeWindowPlugin{}
	ctx := &Context{Timestamp: time.Now()}

	raw := json.RawMessage(`{"windows":["garbage"],"timezone":"UTC"}`)
	if _, err := p.Eval(ctx, raw); err == nil {
		t.Error("malformed window should return error")
	}
}

func TestTimeWindowPluginInsideWindow(t *testing.T) {
	p := &timeWindowPlugin{}
	// 10:30 UTC is inside 09:00-12:00.
	ctx := &Context{Timestamp: time.Date(2026, 1, 5, 10, 30, 0, 0, time.UTC)}

	raw := json.RawMessage(`{"windows":["09:00-12:00","14:00-18:00"],"timezone":"UTC"}`)
	match, err := p.Eval(ctx, raw)
	if err != nil {
		t.Fatalf("Eval failed: %v", err)
	}
	if match {
		t.Error("inside a window: condition must NOT trigger")
	}
}

func TestTimeWindowPluginOutsideAllWindows(t *testing.T) {
	p := &timeWindowPlugin{}
	// 13:00 UTC is outside both 09:00-12:00 and 14:00-18:00.
	ctx := &Context{Timestamp: time.Date(2026, 1, 5, 13, 0, 0, 0, time.UTC)}

	raw := json.RawMessage(`{"windows":["09:00-12:00","14:00-18:00"],"timezone":"UTC"}`)
	match, err := p.Eval(ctx, raw)
	if err != nil {
		t.Fatalf("Eval failed: %v", err)
	}
	if !match {
		t.Error("outside all windows: condition must trigger")
	}
}

func TestTimeWindowPluginDefaultTimezone(t *testing.T) {
	p := &timeWindowPlugin{}
	// No timezone → time.Local. A full-day window keeps the test deterministic.
	ctx := &Context{Timestamp: time.Now()}

	raw := json.RawMessage(`{"windows":["00:00-23:59"]}`)
	match, err := p.Eval(ctx, raw)
	if err != nil {
		t.Fatalf("Eval failed: %v", err)
	}
	if match {
		t.Error("full-day window: condition must never trigger")
	}
}

func TestTimeWindowPluginName(t *testing.T) {
	p := &timeWindowPlugin{}
	if p.Name() != "time_window" {
		t.Errorf("Name() = %q, want %q", p.Name(), "time_window")
	}
}

// Integration: the init()-registered time_window plugin returning an error
// through matchCondition must fail closed.
func TestMatchConditionTimeWindowBadConfig(t *testing.T) {
	cond := &ConditionConfig{Custom: map[string]json.RawMessage{
		"time_window": json.RawMessage(`{"windows":[]}`),
	}}
	ctx := &Context{Username: "u", Timestamp: time.Now()}
	if matchCondition(ctx, cond) {
		t.Error("time_window config error should not match")
	}
}

// ── plugins_example.go: parseTimeWindow ────────────────────────────────

func TestParseTimeWindow(t *testing.T) {
	tests := []struct {
		in         string
		start, end int
		wantErr    bool
	}{
		{"09:00-12:00", 540, 720, false},
		{"09:00 - 12:00", 540, 720, false}, // spaces trimmed
		{"0900", 0, 0, true},               // no dash
		{"25:00-12:00", 0, 0, true},        // invalid start hour
		{"09:00-24:00", 0, 0, true},        // invalid end hour
	}
	for _, tt := range tests {
		start, end, err := parseTimeWindow(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseTimeWindow(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && (start != tt.start || end != tt.end) {
			t.Errorf("parseTimeWindow(%q) = %d,%d want %d,%d", tt.in, start, end, tt.start, tt.end)
		}
	}
}

// ── plugins_example.go: parseHM ────────────────────────────────────────

func TestParseHM(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"09:30", 570},
		{"00:00", 0},
		{"23:59", 1439},
		{"0930", -1},  // no colon
		{"ab:30", -1}, // non-digit hour
		{"09:cd", -1}, // non-digit minute
		{"24:00", -1}, // hour out of range
		{"09:60", -1}, // minute out of range
	}
	for _, tt := range tests {
		if got := parseHM(tt.in); got != tt.want {
			t.Errorf("parseHM(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

// ── plugins_example.go: sqlNotRegexPlugin.Eval ─────────────────────────

func TestSQLNotRegexPluginInvalidConfig(t *testing.T) {
	p := &sqlNotRegexPlugin{}
	ctx := &Context{RawSQL: "SELECT 1"}

	if _, err := p.Eval(ctx, json.RawMessage(`{bad json`)); err == nil {
		t.Error("invalid JSON config should return error")
	}
}

func TestSQLNotRegexPluginEmptyPatterns(t *testing.T) {
	p := &sqlNotRegexPlugin{}
	ctx := &Context{RawSQL: "SELECT 1"}

	match, err := p.Eval(ctx, json.RawMessage(`{"patterns":[]}`))
	if err != nil {
		t.Fatalf("Eval failed: %v", err)
	}
	if match {
		t.Error("no patterns configured: condition must not trigger")
	}
}

func TestSQLNotRegexPluginPatternMatches(t *testing.T) {
	p := &sqlNotRegexPlugin{}
	ctx := &Context{RawSQL: "SELECT * FROM users"}

	raw := json.RawMessage(`{"patterns":["(?i)SELECT\\s+\\*"]}`)
	match, err := p.Eval(ctx, raw)
	if err != nil {
		t.Fatalf("Eval failed: %v", err)
	}
	if match {
		t.Error("pattern matches SQL: condition (NOT regex) must not trigger")
	}
}

func TestSQLNotRegexPluginNoPatternMatches(t *testing.T) {
	p := &sqlNotRegexPlugin{}
	ctx := &Context{RawSQL: "SELECT id, name FROM users"}

	raw := json.RawMessage(`{"patterns":["(?i)SELECT\\s+\\*","(?i)pg_catalog"]}`)
	match, err := p.Eval(ctx, raw)
	if err != nil {
		t.Fatalf("Eval failed: %v", err)
	}
	if !match {
		t.Error("no pattern matches SQL: condition (NOT regex) must trigger")
	}
}

func TestSQLNotRegexPluginName(t *testing.T) {
	p := &sqlNotRegexPlugin{}
	if p.Name() != "sql_not_regex" {
		t.Errorf("Name() = %q, want %q", p.Name(), "sql_not_regex")
	}
}

// ── sqli_helpers.go: removeStringLiterals — escaped quote ('') ─────────

func TestRemoveStringLiteralsEscapedQuote(t *testing.T) {
	got := removeStringLiterals("SELECT 'it''s a test' FROM t")
	if got != "SELECT @ FROM t" {
		t.Errorf("escaped quote: got %q, want %q", got, "SELECT @ FROM t")
	}

	// Doubled double-quote inside a double-quoted literal.
	got = removeStringLiterals(`SELECT "he said ""hi""" FROM t`)
	if got != "SELECT @ FROM t" {
		t.Errorf("escaped double quote: got %q, want %q", got, "SELECT @ FROM t")
	}
}

// ── sqli_helpers.go: detectSQLInjectionUpper — CHAR( long rest, no comma ─

func TestDetectSQLInjectionCHARLongRestNoComma(t *testing.T) {
	// The argument after CHAR( is longer than the 30-byte scan window and has
	// no comma within it → must not be flagged.
	sql := "SELECT CHAR(" + strings.Repeat("A", 40) + ") FROM t"
	if detectSQLInjection(sql) {
		t.Error("CHAR() with long single argument should NOT be flagged as SQLi")
	}
}
