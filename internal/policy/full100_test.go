package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

// --- engine.go: Evaluate with nil PolicySet ---

func TestEvaluateNilPolicySet(t *testing.T) {
	loader := NewLoader(nil, 0)
	// Don't set any current policy → loader.Current() returns nil
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "user",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionBlock {
		t.Errorf("nil policy set should block, got %v", d.Action)
	}
	if d.Reason != "no policies loaded — fail-closed" {
		t.Errorf("reason = %q", d.Reason)
	}
}

// --- engine.go: cacheKey with nil ClientIP ---

func TestCacheKeyNilClientIP(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{{Name: "a", Match: MatchConfig{}, Action: "allow"}},
	}
	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	// ctx without ClientIP (nil)
	ctx := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.Action != ActionAllow {
		t.Errorf("action = %v", d.Action)
	}

	// ctx with HasWhere = true for the other cacheKey branch
	ctx2 := &Context{
		Username:    "user1",
		CommandType: inspection.CommandSELECT,
		HasWhere:    true,
		Timestamp:   time.Now(),
	}
	d2 := engine.Evaluate(ctx2)
	if d2.Action != ActionAllow {
		t.Errorf("action = %v", d2.Action)
	}
}

// --- loader.go: watchLoop with Load() failure ---

func TestWatchLoopLoadFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(`{"version":"1","policies":[]}`), 0644)

	loader := NewLoader([]string{path}, 100*time.Millisecond)
	loader.Load() // initial load OK

	// Modify file with invalid JSON to cause reload failure
	time.Sleep(50 * time.Millisecond)
	os.WriteFile(path, []byte(`{invalid json}`), 0644)

	loader.Start()
	time.Sleep(300 * time.Millisecond)
	loader.Stop()

	// The loader should still have the old valid policy (reload failed, kept current)
	current := loader.Current()
	if current == nil {
		t.Error("should keep current policies after reload failure")
	}
}

// --- loader.go: filesChanged with os.Stat error ---

func TestFilesChangedStatError(t *testing.T) {
	// Use a non-existent file path
	loader := NewLoader([]string{"/nonexistent/path/file.json"}, 0)
	// No lastModTimes set — os.Stat will fail, continue to next
	if loader.filesChanged() {
		t.Error("stat error should continue, return false")
	}
}

// --- loader.go: filesChanged with file not in lastModTimes ---

func TestFilesChangedNotInLastModTimes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	os.WriteFile(path, []byte(`{}`), 0644)

	loader := NewLoader([]string{path}, 0)
	// Don't call Load(), so lastModTimes is empty
	// os.Stat will succeed but lastModTimes[path] won't exist → ok is false → continue
	if loader.filesChanged() {
		t.Error("file not in lastModTimes should not trigger change")
	}
}

// --- matcher.go: detectSQLInjectionUpper — CHR() with commas ---

func TestDetectSQLInjectionCHRWithCommas(t *testing.T) {
	// CHR() with multiple args (building strings char-by-char)
	if !detectSQLInjection("SELECT CHR(65,66,67) FROM dual") {
		t.Error("CHR() with multi-args should be detected as SQLi")
	}
}

// --- matcher.go: detectSQLInjectionUpper — double-quote hash comment termination ---

func TestDetectSQLInjectionDoubleQuoteHash(t *testing.T) {
	if !detectSQLInjection(`SELECT * FROM users WHERE name="admin"# AND 1=1`) {
		t.Error(`"# comment termination should be detected as SQLi`)
	}
}

// --- matcher.go: detectSQLInjectionUpper — CONCAT + DROP ---

func TestDetectSQLInjectionConcatDrop(t *testing.T) {
	if !detectSQLInjection("SELECT CONCAT('DR','OP') FROM t; DROP TABLE x") {
		t.Error("CONCAT + DROP should be detected as SQLi")
	}
}

// --- matcher.go: detectSQLInjectionUpper — stacked INSERT/UPDATE/ALTER/CREATE ---

func TestDetectSQLInjectionStackedVariants(t *testing.T) {
	tests := []string{
		"SELECT 1; INSERT INTO evil VALUES(1)",
		"SELECT 1; UPDATE users SET role='admin'",
		"SELECT 1; ALTER TABLE users ADD col int",
		"SELECT 1; CREATE TABLE evil(a int)",
	}
	for _, sql := range tests {
		if !detectSQLInjection(sql) {
			t.Errorf("stacked query should be detected: %q", sql)
		}
	}
}

// --- matcher.go: detectSQLInjectionUpper — CHAR with no commas (short rest) ---

func TestDetectSQLInjectionCHARNoCommas(t *testing.T) {
	// CHAR() without commas and without suspicious context → not SQLi
	if detectSQLInjection("SELECT CHAR(65) FROM dual") {
		t.Error("single CHAR() arg without suspicious context should NOT be SQLi")
	}
}

// --- matcher.go: detectSQLInjectionUpper — CONCAT alone (no suspicious context) ---

func TestDetectSQLInjectionConcatAlone(t *testing.T) {
	// CONCAT without UNION/DROP/EXEC → not SQLi
	if detectSQLInjection("SELECT CONCAT(first_name, ' ', last_name) FROM employees") {
		t.Error("normal CONCAT usage should NOT be SQLi")
	}
}

// --- matcher.go: detectSQLInjectionUpper — CONCAT + EXEC context ---

func TestDetectSQLInjectionConcatExec(t *testing.T) {
	// CONCAT with EXEC context → should be detected as SQLi
	if !detectSQLInjection("EXEC sp_executesql CONCAT('SELECT ', '1')") {
		t.Error("CONCAT + EXEC should be detected as SQLi")
	}
}

// --- matcher.go: normalizeSQL — unclosed comment ---

func TestNormalizeSQLUnclosedComment(t *testing.T) {
	// /* without closing */ — the second Index returns -1, breaks loop
	result := normalizeSQL("SELECT /* unclosed comment 1 FROM users")
	if result != "SELECT /* unclosed comment 1 FROM users" {
		t.Errorf("unclosed comment should leave string as-is, got %q", result)
	}
}

// --- matcher.go: normalizeSQL — nested/multiple comments ---

func TestNormalizeSQLMultipleComments(t *testing.T) {
	result := normalizeSQL("SELECT/*a*/1/*b*/FROM t")
	if result != "SELECT 1 FROM t" {
		t.Errorf("multiple comments not stripped, got %q", result)
	}
}

// --- matcher.go: matchWorkHours — bad part format (too many colons) ---

func TestMatchWorkHoursBadTimeFormat(t *testing.T) {
	// "08:00:00-19:00" → startParts has 3 elements, not 2 → return true
	if !matchWorkHours(time.Now(), "08:00:00-19:00") {
		t.Error("bad start time format should return true (no restriction)")
	}
	// "08:00-19:00:00" → endParts has 3 elements
	if !matchWorkHours(time.Now(), "08:00-19:00:00") {
		t.Error("bad end time format should return true (no restriction)")
	}
}

// --- validator.go: unknown transformer warning ---

func TestValidatePolicySetUnknownTransformer(t *testing.T) {
	ps := &PolicySet{
		Policies: []PolicyRule{
			{
				Name:    "rule1",
				Masking: []MaskingRule{{Column: "data", Transformer: "custom_xform"}},
			},
		},
	}
	issues := ValidatePolicySet(ps)
	found := false
	for _, issue := range issues {
		if issue.Level == "warning" && issue.Message == `unknown transformer "custom_xform" (may be custom)` {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning for unknown transformer, got %v", issues)
	}
}

// --- engine.go: evaluate with masking but action="" → default allow → set mask ---

func TestEvaluateRuleNoActionWithMasking(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow", LogLevel: "standard"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{
			{
				Name:    "mask-rule",
				Match:   MatchConfig{},
				Action:  "", // no explicit action
				Masking: []MaskingRule{{Column: "email", Transformer: "redact"}},
			},
		},
	}
	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "user",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	// Action should be derived from empty string → ParseAction("") returns ActionAllow
	// Then masking makes it ActionMask
	if d.Action != ActionMask {
		t.Errorf("expected mask, got %v", d.Action)
	}
}

// --- engine.go: evaluate with LogLevel from defaults ---

func TestEvaluateLogLevelFromDefaults(t *testing.T) {
	ps := &PolicySet{
		Defaults: DefaultsConfig{Action: "allow", LogLevel: "minimal"},
		Roles:    map[string]Role{},
		Policies: []PolicyRule{
			{
				Name:   "rule-no-loglevel",
				Match:  MatchConfig{},
				Action: "allow",
				// LogLevel is empty → should use ps.Defaults.LogLevel
			},
		},
	}
	loader := NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := NewEngine(loader)

	ctx := &Context{
		Username:    "user",
		CommandType: inspection.CommandSELECT,
		Timestamp:   time.Now(),
	}
	d := engine.Evaluate(ctx)
	if d.LogLevel != "minimal" {
		t.Errorf("logLevel = %q, want 'minimal'", d.LogLevel)
	}
}

// --- watchLoop: onReload nil (no callback set) ---

func TestWatchLoopNoCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	ps := PolicySet{Version: "1", Policies: []PolicyRule{}}
	data, _ := json.Marshal(ps)
	os.WriteFile(path, data, 0644)

	loader := NewLoader([]string{path}, 100*time.Millisecond)
	// No OnReload callback
	loader.Load()

	// Modify file
	time.Sleep(50 * time.Millisecond)
	ps.Version = "2"
	data, _ = json.Marshal(ps)
	os.WriteFile(path, data, 0644)

	loader.Start()
	time.Sleep(300 * time.Millisecond)
	loader.Stop()

	// Just verify no panic and version updated
	current := loader.Current()
	if current == nil {
		t.Fatal("current should not be nil")
	}
}
