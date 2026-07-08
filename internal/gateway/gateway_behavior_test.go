package gateway

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/core"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/ratelimit"
)

func TestExecuteOnBackendPostgreSQL(t *testing.T) {
	// Build mock PG response
	var resp []byte
	resp = append(resp, pgRowDescription([]string{"x"})...)
	resp = append(resp, pgDataRow([]string{"1"})...)
	resp = append(resp, pgCommandComplete("SELECT 1")...)
	resp = append(resp, pgReadyForQuery()...)

	serverConn, clientConn := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		serverConn.Read(buf)
		serverConn.Write(resp)
		time.Sleep(100 * time.Millisecond)
		serverConn.Close()
	}()

	pl := pool.NewPool("test-pg", 1, 0, time.Hour, 10*time.Second, 0)
	pl.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})

	cfg := config.DefaultConfig()
	cfg.Targets = []config.Target{
		{Name: "test-pg", Protocol: "postgresql", Host: "localhost", Port: 5432},
	}
	cfg.Routing.DefaultTarget = "test-pg"
	cfg.Gateway.MaxResultRows = 100

	pset := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)

	logger := audit.NewLogger(10, audit.LevelStandard, 4096)
	logger.Start()
	defer logger.Close()

	gw := &Gateway{
		cfg:          cfg,
		policyEngine: policy.NewEngine(loader),
		auditLogger:  logger,
		pools:        map[string]*pool.Pool{"test-pg": pl},
		allowlist:    NewAllowlist(),
		apiKeyStore:  NewAPIKeyStore(),
		rateLimiters: make(map[string]*ratelimit.Limiter),
		approvalManager: core.NewApprovalManager(5 * time.Minute),
		cleanupStop:  make(chan struct{}),
	}
	defer close(gw.cleanupStop)

	result := gw.ExecuteQuery(context.Background(), QueryRequest{
		SQL: "SELECT x FROM t", Username: "alice", Database: "testdb",
	})

	if result.Status != "ok" {
		t.Errorf("status = %q, want ok. Error: %s", result.Status, result.Error)
	}
	if result.RowCount != 1 {
		t.Errorf("row_count = %d, want 1", result.RowCount)
	}
}

func TestExecuteOnBackendMySQL(t *testing.T) {
	var resp []byte
	resp = append(resp, mysqlColumnCount(1, 1)...)
	resp = append(resp, mysqlColumnDef(2, "y")...)
	resp = append(resp, mysqlEOFPacket(3)...)
	resp = append(resp, mysqlTextRow(4, []string{"hello"})...)
	resp = append(resp, mysqlEOFPacket(5)...)

	serverConn, clientConn := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		serverConn.Read(buf)
		serverConn.Write(resp)
		time.Sleep(100 * time.Millisecond)
		serverConn.Close()
	}()

	pl := pool.NewPool("test-mysql", 1, 0, time.Hour, 10*time.Second, 0)
	pl.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})

	cfg := config.DefaultConfig()
	cfg.Targets = []config.Target{
		{Name: "test-mysql", Protocol: "mysql", Host: "localhost", Port: 3306},
	}
	cfg.Routing.DefaultTarget = "test-mysql"
	cfg.Gateway.MaxResultRows = 100

	pset := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)

	logger := audit.NewLogger(10, audit.LevelStandard, 4096)
	logger.Start()
	defer logger.Close()

	gw := &Gateway{
		cfg:          cfg,
		policyEngine: policy.NewEngine(loader),
		auditLogger:  logger,
		pools:        map[string]*pool.Pool{"test-mysql": pl},
		allowlist:    NewAllowlist(),
		apiKeyStore:  NewAPIKeyStore(),
		rateLimiters: make(map[string]*ratelimit.Limiter),
		approvalManager: core.NewApprovalManager(5 * time.Minute),
		cleanupStop:  make(chan struct{}),
	}
	defer close(gw.cleanupStop)

	result := gw.ExecuteQuery(context.Background(), QueryRequest{
		SQL: "SELECT y FROM t", Username: "bob", Database: "testdb",
	})

	if result.Status != "ok" {
		t.Errorf("status = %q, want ok. Error: %s", result.Status, result.Error)
	}
	if result.RowCount != 1 {
		t.Errorf("row_count = %d, want 1", result.RowCount)
	}
}

func TestExecuteOnBackendNoTarget(t *testing.T) {
	gw := testGateway(t)

	result := gw.ExecuteQuery(context.Background(), QueryRequest{
		SQL: "SELECT 1", Username: "alice", Database: "unknown_db",
	})

	if result.Status != "error" {
		t.Errorf("status = %q, want error", result.Status)
	}
}

func TestExecuteOnBackendUnsupportedProtocol(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Targets = []config.Target{
		{Name: "test-mssql", Protocol: "mssql", Host: "localhost", Port: 1433},
	}
	cfg.Routing.DefaultTarget = "test-mssql"

	pset := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(pset)

	logger := audit.NewLogger(10, audit.LevelStandard, 4096)
	logger.Start()
	defer logger.Close()

	pl := pool.NewPool("test-mssql", 1, 0, time.Hour, 10*time.Second, 0)

	gw := &Gateway{
		cfg:          cfg,
		policyEngine: policy.NewEngine(loader),
		auditLogger:  logger,
		pools:        map[string]*pool.Pool{"test-mssql": pl},
		allowlist:    NewAllowlist(),
		apiKeyStore:  NewAPIKeyStore(),
		rateLimiters: make(map[string]*ratelimit.Limiter),
		approvalManager: core.NewApprovalManager(5 * time.Minute),
		cleanupStop:  make(chan struct{}),
	}
	defer close(gw.cleanupStop)

	result := gw.ExecuteQuery(context.Background(), QueryRequest{
		SQL: "SELECT 1", Username: "alice", Database: "testdb",
	})

	if result.Status != "error" {
		t.Errorf("status = %q, want error (unsupported protocol)", result.Status)
	}
}

// mysqlColumnCount, mysqlColumnDef, mysqlEOFPacket, mysqlTextRow are defined in executor_mysql_test.go
// pgRowDescription, pgDataRow, pgCommandComplete, pgReadyForQuery are defined in executor_test.go

func mysqlColumnCountLocal(seqID byte, count int) []byte {
	return mysqlPacket(seqID, []byte{byte(count)})
}

func pgMsgLocal(typ byte, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(4+len(payload)))
	copy(buf[5:], payload)
	return buf
}
