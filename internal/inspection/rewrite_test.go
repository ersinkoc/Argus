package inspection

import "testing"

func TestRewriteAddLimit(t *testing.T) {
	r := NewRewriter()
	r.SetMaxLimit(1000)

	cmd := Classify("SELECT * FROM users")
	result, applied := r.Rewrite("SELECT * FROM users", cmd)

	if result != "SELECT * FROM users LIMIT 1000" {
		t.Errorf("got %q", result)
	}
	if len(applied) != 1 {
		t.Errorf("applied = %v", applied)
	}
}

func TestRewriteNoLimitIfExists(t *testing.T) {
	r := NewRewriter()
	r.SetMaxLimit(1000)

	cmd := Classify("SELECT * FROM users LIMIT 10")
	result, applied := r.Rewrite("SELECT * FROM users LIMIT 10", cmd)

	if result != "SELECT * FROM users LIMIT 10" {
		t.Errorf("should not modify: %q", result)
	}
	if len(applied) != 0 {
		t.Error("should not apply any rewrite")
	}
}

func TestRewriteNoLimitForInsert(t *testing.T) {
	r := NewRewriter()
	r.SetMaxLimit(1000)

	cmd := Classify("INSERT INTO t VALUES (1)")
	result, _ := r.Rewrite("INSERT INTO t VALUES (1)", cmd)

	if result != "INSERT INTO t VALUES (1)" {
		t.Errorf("should not add LIMIT to INSERT: %q", result)
	}
}

func TestRewriteForceWhere(t *testing.T) {
	r := NewRewriter()
	r.SetForceWhere("tenant_id = 42")

	cmd := Classify("SELECT * FROM users")
	result, applied := r.Rewrite("SELECT * FROM users", cmd)

	if result != "SELECT * FROM users WHERE tenant_id = 42" {
		t.Errorf("got %q", result)
	}
	if len(applied) != 1 {
		t.Errorf("applied = %v", applied)
	}
}

func TestRewriteForceWhereWithExisting(t *testing.T) {
	r := NewRewriter()
	r.SetForceWhere("tenant_id = 42")

	cmd := Classify("SELECT * FROM users WHERE active = true")
	result, _ := r.Rewrite("SELECT * FROM users WHERE active = true", cmd)

	if result != "SELECT * FROM users WHERE tenant_id = 42 AND active = true" {
		t.Errorf("got %q", result)
	}
}

func TestRewriteForceWhereBeforeOrderBy(t *testing.T) {
	r := NewRewriter()
	r.SetForceWhere("tenant_id = 42")

	cmd := Classify("SELECT * FROM users ORDER BY name")
	result, _ := r.Rewrite("SELECT * FROM users ORDER BY name", cmd)

	if result != "SELECT * FROM users WHERE tenant_id = 42 ORDER BY name" {
		t.Errorf("got %q", result)
	}
}

func TestRewriteBothLimitAndWhere(t *testing.T) {
	r := NewRewriter()
	r.SetMaxLimit(500)
	r.SetForceWhere("org_id = 1")

	cmd := Classify("SELECT * FROM orders")
	result, applied := r.Rewrite("SELECT * FROM orders", cmd)

	if len(applied) != 2 {
		t.Errorf("expected 2 rewrites, got %d: %v", len(applied), applied)
	}
	if !hasKeyword(result, "LIMIT") {
		t.Error("should have LIMIT")
	}
	if !hasKeyword(result, "WHERE") {
		t.Error("should have WHERE")
	}
}
