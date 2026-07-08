package core

import (
	"testing"

	"github.com/ersinkoc/argus/internal/metrics"
)

func TestRecordProtocolCommand(t *testing.T) {
	tests := []struct {
		protocol string
		want     func() int64
	}{
		{"postgresql", func() int64 { return metrics.ProtocolStats.PGCommands.Load() }},
		{"mysql", func() int64 { return metrics.ProtocolStats.MySQLCommands.Load() }},
		{"mssql", func() int64 { return metrics.ProtocolStats.MSSQLCommands.Load() }},
		{"mongodb", func() int64 { return metrics.ProtocolStats.MongoDBCommands.Load() }},
		{"unknown", func() int64 { return metrics.ProtocolStats.PGCommands.Load() }},
	}

	for _, tt := range tests {
		before := tt.want()
		recordProtocolCommand(tt.protocol)
		after := tt.want()
		if after != before+1 && tt.protocol != "unknown" {
			t.Errorf("recordProtocolCommand(%q): count %d, want %d", tt.protocol, after, before+1)
		}
	}
}
