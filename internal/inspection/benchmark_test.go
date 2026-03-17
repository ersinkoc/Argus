package inspection

import "testing"

func BenchmarkTokenizer(b *testing.B) {
	sql := "SELECT u.id, u.name, u.email, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.status = 'active' AND o.created_at > '2024-01-01' ORDER BY o.total DESC LIMIT 100"
	b.ResetTimer()
	for b.Loop() {
		t := NewTokenizer(sql)
		t.Tokenize()
	}
}

func BenchmarkClassify(b *testing.B) {
	sql := "SELECT u.id, u.name, u.email, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.status = 'active' AND o.created_at > '2024-01-01' ORDER BY o.total DESC LIMIT 100"
	b.ResetTimer()
	for b.Loop() {
		Classify(sql)
	}
}

func BenchmarkClassifySimple(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1"
	b.ResetTimer()
	for b.Loop() {
		Classify(sql)
	}
}

func BenchmarkClassifyInsert(b *testing.B) {
	sql := "INSERT INTO logs (level, message, timestamp) VALUES ('INFO', 'user logged in', '2024-01-01T00:00:00Z')"
	b.ResetTimer()
	for b.Loop() {
		Classify(sql)
	}
}

func BenchmarkClassifyDDL(b *testing.B) {
	sql := "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE)"
	b.ResetTimer()
	for b.Loop() {
		Classify(sql)
	}
}
