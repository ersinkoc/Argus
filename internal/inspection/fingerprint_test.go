package inspection

import "testing"

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{
			"simple select with number",
			"SELECT * FROM users WHERE id = 42",
			"SELECT * FROM users WHERE id = ?",
		},
		{
			"select with string literal",
			"SELECT * FROM users WHERE name = 'John'",
			"SELECT * FROM users WHERE name = ?",
		},
		{
			"insert with values",
			"INSERT INTO logs (level, msg) VALUES ('INFO', 'hello')",
			"INSERT INTO logs ( level , msg ) VALUES ( ? , ? )",
		},
		{
			"update with multiple literals",
			"UPDATE users SET name = 'Jane', age = 30 WHERE id = 1",
			"UPDATE users SET name = ? , age = ? WHERE id = ?",
		},
		{
			"comment stripped",
			"SELECT * FROM users -- get all users",
			"SELECT * FROM users",
		},
		{
			"same structure different values",
			"SELECT * FROM orders WHERE total > 100 AND status = 'active'",
			"SELECT * FROM orders WHERE total > ? AND status = ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Fingerprint(tt.sql)
			if got != tt.want {
				t.Errorf("Fingerprint(%q)\n  got  %q\n  want %q", tt.sql, got, tt.want)
			}
		})
	}
}

func TestFingerprintHash(t *testing.T) {
	// Same structure queries should produce same hash
	h1 := FingerprintHash("SELECT * FROM users WHERE id = 1")
	h2 := FingerprintHash("SELECT * FROM users WHERE id = 999")
	if h1 != h2 {
		t.Errorf("same structure should produce same hash: %s != %s", h1, h2)
	}

	// Different structure should produce different hash
	h3 := FingerprintHash("SELECT * FROM orders WHERE total > 100")
	if h1 == h3 {
		t.Error("different structure should produce different hash")
	}

	// Hash should be 16 hex chars
	if len(h1) != 16 {
		t.Errorf("hash length = %d, want 16", len(h1))
	}
}

func BenchmarkFingerprint(b *testing.B) {
	sql := "SELECT u.id, u.name, u.email FROM users u JOIN orders o ON u.id = o.user_id WHERE u.status = 'active' AND o.total > 100 ORDER BY o.created_at DESC LIMIT 50"
	for b.Loop() {
		Fingerprint(sql)
	}
}
