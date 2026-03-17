package inspection

import "testing"

func TestEstimateCost(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		minScore int
		maxScore int
		factors  []string
	}{
		{
			"simple select with where",
			"SELECT id, name FROM users WHERE id = 1",
			0, 10, nil,
		},
		{
			"select star no where",
			"SELECT * FROM users",
			20, 40,
			[]string{"SELECT *", "no WHERE clause"},
		},
		{
			"join query",
			"SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.id = 1",
			15, 40,
			[]string{"JOIN"},
		},
		{
			"complex query",
			"SELECT DISTINCT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name ORDER BY COUNT(o.id) DESC",
			40, 100,
			[]string{"JOIN", "ORDER BY", "GROUP BY", "DISTINCT"},
		},
		{
			"subquery",
			"SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)",
			20, 60,
			[]string{"subquery"},
		},
		{
			"union",
			"SELECT name FROM users UNION SELECT name FROM admins",
			15, 60,
			[]string{"UNION"},
		},
		{
			"delete no where",
			"DELETE FROM users",
			20, 40,
			[]string{"no WHERE clause"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := Classify(tt.sql)
			est := EstimateCost(cmd)

			if est.Score < tt.minScore || est.Score > tt.maxScore {
				t.Errorf("score = %d, want [%d, %d]. factors: %v",
					est.Score, tt.minScore, tt.maxScore, est.Factors)
			}

			for _, wantFactor := range tt.factors {
				found := false
				for _, f := range est.Factors {
					if f == wantFactor {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing factor %q, got %v", wantFactor, est.Factors)
				}
			}
		})
	}
}

func BenchmarkEstimateCost(b *testing.B) {
	cmd := Classify("SELECT u.name, COUNT(o.id) FROM users u JOIN orders o ON u.id = o.user_id WHERE u.status = 'active' GROUP BY u.name ORDER BY COUNT(o.id) DESC LIMIT 100")
	b.ResetTimer()
	for b.Loop() {
		EstimateCost(cmd)
	}
}
