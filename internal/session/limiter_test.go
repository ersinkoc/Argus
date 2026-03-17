package session

import "testing"

func TestConcurrencyLimiter(t *testing.T) {
	l := NewConcurrencyLimiter(3)

	// Allow up to 3
	if !l.Acquire("alice") {
		t.Error("1st should be allowed")
	}
	if !l.Acquire("alice") {
		t.Error("2nd should be allowed")
	}
	if !l.Acquire("alice") {
		t.Error("3rd should be allowed")
	}

	// 4th should be denied
	if l.Acquire("alice") {
		t.Error("4th should be denied (limit=3)")
	}

	if l.Count("alice") != 3 {
		t.Errorf("count = %d, want 3", l.Count("alice"))
	}

	// Different user independent
	if !l.Acquire("bob") {
		t.Error("bob should be allowed (independent)")
	}

	// Release and re-acquire
	l.Release("alice")
	if !l.Acquire("alice") {
		t.Error("after release, should be allowed")
	}
}

func TestConcurrencyLimiterUnlimited(t *testing.T) {
	l := NewConcurrencyLimiter(0)

	for range 100 {
		if !l.Acquire("alice") {
			t.Fatal("unlimited should always allow")
		}
	}
}

func TestConcurrencyLimiterRelease(t *testing.T) {
	l := NewConcurrencyLimiter(1)

	l.Acquire("alice")
	l.Release("alice")
	l.Release("alice") // double release should be safe

	if l.Count("alice") != 0 {
		t.Errorf("count after double release = %d", l.Count("alice"))
	}
}

func TestConcurrencyLimiterAllCounts(t *testing.T) {
	l := NewConcurrencyLimiter(10)
	l.Acquire("alice")
	l.Acquire("alice")
	l.Acquire("bob")

	counts := l.AllCounts()
	if counts["alice"] != 2 {
		t.Errorf("alice = %d, want 2", counts["alice"])
	}
	if counts["bob"] != 1 {
		t.Errorf("bob = %d, want 1", counts["bob"])
	}
}
