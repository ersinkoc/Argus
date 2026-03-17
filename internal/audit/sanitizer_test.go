package audit

import "testing"

func TestSanitizeSQL(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{
			"simple string literal",
			"SELECT * FROM users WHERE name = 'John'",
			"SELECT * FROM users WHERE name = $1",
		},
		{
			"multiple string literals",
			"SELECT * FROM users WHERE name = 'John' AND email = 'john@example.com'",
			"SELECT * FROM users WHERE name = $1 AND email = $2",
		},
		{
			"escaped quote in string",
			"SELECT * FROM users WHERE name = 'O''Brien'",
			"SELECT * FROM users WHERE name = $1",
		},
		{
			"numeric literal",
			"SELECT * FROM users WHERE id = 42",
			"SELECT * FROM users WHERE id = $1",
		},
		{
			"no literals",
			"SELECT * FROM users",
			"SELECT * FROM users",
		},
		{
			"empty",
			"",
			"",
		},
		{
			"insert with values",
			"INSERT INTO users (name, age) VALUES ('Alice', 30)",
			"INSERT INTO users (name, age) VALUES ($1, $2)",
		},
		{
			"dollar quoted string",
			"SELECT $$hello world$$",
			"SELECT $1",
		},
		{
			"identifier with numbers preserved",
			"SELECT col1 FROM table2",
			"SELECT col1 FROM table2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeSQL(tt.sql)
			if got != tt.want {
				t.Errorf("SanitizeSQL(%q)\n  got  %q\n  want %q", tt.sql, got, tt.want)
			}
		})
	}
}
