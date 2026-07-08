package core

import (
	"github.com/ersinkoc/argus/internal/metrics"
)

// recordProtocolCommand increments the per-protocol command counter metric.
// Extracted as a characterization seam so commandLoop is easier to split and test.
func recordProtocolCommand(protocolName string) {
	switch protocolName {
	case "postgresql":
		metrics.ProtocolStats.PGCommands.Add(1)
	case "mysql":
		metrics.ProtocolStats.MySQLCommands.Add(1)
	case "mssql":
		metrics.ProtocolStats.MSSQLCommands.Add(1)
	case "mongodb":
		metrics.ProtocolStats.MongoDBCommands.Add(1)
	}
}
