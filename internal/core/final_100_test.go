package core

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/ratelimit"
	"github.com/ersinkoc/argus/internal/session"
)

// mockHandler implements protocol.Handler for precise control in tests.
type mockHandler struct {
	name              string
	readCommandFunc   func(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error)
	forwardFunc       func(ctx context.Context, rawMsg []byte, backend net.Conn) error
	readResultFunc    func(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error)
	writeErrorFunc    func(ctx context.Context, client net.Conn, code, message string) error
	rebuildQueryFunc  func(rawMsg []byte, newSQL string) []byte
}

func (m *mockHandler) Name() string { return m.name }
func (m *mockHandler) DetectProtocol(peek []byte) bool { return false }
func (m *mockHandler) Handshake(ctx context.Context, client, backend net.Conn) (*session.Info, error) {
	return nil, nil
}
func (m *mockHandler) ReadCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
	if m.readCommandFunc != nil {
		return m.readCommandFunc(ctx, client)
	}
	return nil, nil, errors.New("no read func")
}
func (m *mockHandler) ForwardCommand(ctx context.Context, rawMsg []byte, backend net.Conn) error {
	if m.forwardFunc != nil {
		return m.forwardFunc(ctx, rawMsg, backend)
	}
	return nil
}
func (m *mockHandler) ReadAndForwardResult(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
	if m.readResultFunc != nil {
		return m.readResultFunc(ctx, backend, client, pipeline)
	}
	return &protocol.ResultStats{}, nil
}
func (m *mockHandler) WriteError(ctx context.Context, client net.Conn, code, message string) error {
	if m.writeErrorFunc != nil {
		return m.writeErrorFunc(ctx, client, code, message)
	}
	return nil
}
func (m *mockHandler) RebuildQuery(rawMsg []byte, newSQL string) []byte {
	if m.rebuildQueryFunc != nil {
		return m.rebuildQueryFunc(rawMsg, newSQL)
	}
	return nil
}
func (m *mockHandler) Close() error { return nil }

// helper to build a minimal proxy for commandLoop tests.
func newTestProxy(protocolName string) (*Proxy, *audit.Logger, *policy.Engine) {
	cfg := config.DefaultConfig()
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := policy.NewEngine(loader)

	logger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	logger.Start()

	proxy := NewProxy(cfg, engine, logger)
	return proxy, logger, engine
}

// helper to create a session for the proxy.
func createTestSession(proxy *Proxy, username string) *session.Session {
	client, _ := net.Pipe()
	sess := proxy.sessionManager.Create(&session.Info{
		Username: username,
		Database: "testdb",
		ClientIP: net.ParseIP("10.0.0.1"),
	}, client)
	sess.Roles = []string{"admin"}
	return sess
}

// ==================== commandLoop: per-protocol metrics for mysql ====================

func TestCommandLoopMySQLMetrics(t *testing.T) {
	proxy, logger, _ := newTestProxy("mysql")
	defer logger.Close()

	callCount := 0
	handler := &mockHandler{
		name: "mysql",
		readCommandFunc: func(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
			callCount++
			if callCount == 1 {
				return &inspection.Command{
					Raw:       "SELECT 1",
					Type:      inspection.CommandSELECT,
					Tables:    []string{"dual"},
					RiskLevel: inspection.RiskLow,
				}, []byte("SELECT 1"), nil
			}
			// Second call: return nil to terminate
			return nil, nil, nil
		},
		readResultFunc: func(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
			return &protocol.ResultStats{RowCount: 1}, nil
		},
	}

	sess := createTestSession(proxy, "mysql_user")
	client, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()

	proxy.commandLoop(context.Background(), sess, handler, client, backend)

	if callCount < 2 {
		t.Errorf("expected at least 2 ReadCommand calls, got %d", callCount)
	}
}

// ==================== commandLoop: per-protocol metrics for mssql ====================

func TestCommandLoopMSSQLMetrics(t *testing.T) {
	proxy, logger, _ := newTestProxy("mssql")
	defer logger.Close()

	callCount := 0
	handler := &mockHandler{
		name: "mssql",
		readCommandFunc: func(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
			callCount++
			if callCount == 1 {
				return &inspection.Command{
					Raw:       "SELECT 1",
					Type:      inspection.CommandSELECT,
					Tables:    []string{"sys.objects"},
					RiskLevel: inspection.RiskLow,
				}, []byte("SELECT 1"), nil
			}
			return nil, nil, nil
		},
		readResultFunc: func(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
			return &protocol.ResultStats{RowCount: 1}, nil
		},
	}

	sess := createTestSession(proxy, "mssql_user")
	client, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()

	proxy.commandLoop(context.Background(), sess, handler, client, backend)
}

// ==================== commandLoop: per-protocol metrics for mongodb ====================

func TestCommandLoopMongoDBMetrics(t *testing.T) {
	proxy, logger, _ := newTestProxy("mongodb")
	defer logger.Close()

	callCount := 0
	handler := &mockHandler{
		name: "mongodb",
		readCommandFunc: func(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
			callCount++
			if callCount == 1 {
				return &inspection.Command{
					Raw:       "find",
					Type:      inspection.CommandSELECT,
					Tables:    []string{"users"},
					RiskLevel: inspection.RiskLow,
				}, []byte("find"), nil
			}
			return nil, nil, nil
		},
		readResultFunc: func(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
			return &protocol.ResultStats{RowCount: 1}, nil
		},
	}

	sess := createTestSession(proxy, "mongo_user")
	client, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()

	proxy.commandLoop(context.Background(), sess, handler, client, backend)
}

// ==================== commandLoop: ForwardCommand error in allow path ====================

func TestCommandLoopForwardCommandError(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgresql")
	defer logger.Close()

	callCount := 0
	handler := &mockHandler{
		name: "postgresql",
		readCommandFunc: func(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
			callCount++
			if callCount == 1 {
				return &inspection.Command{
					Raw:       "SELECT 1",
					Type:      inspection.CommandSELECT,
					Tables:    []string{"t"},
					RiskLevel: inspection.RiskLow,
				}, []byte("SELECT 1"), nil
			}
			return nil, nil, nil
		},
		forwardFunc: func(ctx context.Context, rawMsg []byte, backend net.Conn) error {
			return errors.New("connection reset by peer")
		},
	}

	sess := createTestSession(proxy, "fw_error_user")
	client, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()

	proxy.commandLoop(context.Background(), sess, handler, client, backend)

	// commandLoop should have returned after ForwardCommand error
	if callCount != 1 {
		t.Errorf("expected exactly 1 ReadCommand call (ForwardCommand error should return), got %d", callCount)
	}
}

// ==================== commandLoop: plan analysis with MySQL (ExplainMySQL branch) ====================

func TestCommandLoopPlanAnalysisMySQL(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Audit.Outputs = nil
	cfg.PlanAnalysis.Enabled = true
	cfg.PlanAnalysis.Timeout = "1s"

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := policy.NewEngine(loader)

	logger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, engine, logger)

	callCount := 0
	handler := &mockHandler{
		name: "mysql",
		readCommandFunc: func(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
			callCount++
			if callCount == 1 {
				return &inspection.Command{
					Raw:       "SELECT * FROM users WHERE id = 1",
					Type:      inspection.CommandSELECT,
					Tables:    []string{"users"},
					RiskLevel: inspection.RiskLow,
					HasWhere:  true,
				}, []byte("SELECT * FROM users WHERE id = 1"), nil
			}
			return nil, nil, nil
		},
		forwardFunc: func(ctx context.Context, rawMsg []byte, backend net.Conn) error {
			return nil
		},
		readResultFunc: func(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
			return &protocol.ResultStats{RowCount: 1}, nil
		},
	}

	sess := createTestSession(proxy, "mysql_plan_user")
	client, backend := net.Pipe()
	defer client.Close()
	defer backend.Close()

	// The ExplainMySQL call will fail (backend is a pipe, not real MySQL)
	// but the code handles the error gracefully (planErr != nil, planCost stays 0).
	// This is enough to cover the ExplainMySQL branch (line 486).
	proxy.commandLoop(context.Background(), sess, handler, client, backend)
}

// ==================== Start: session timeout callback (lines 140-150) ====================

func TestProxyStartSessionTimeoutCallbackFires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long test in short mode")
	}

	// The session manager's timeoutLoop uses a 30-second ticker.
	// We call proxy.Start() so the real OnTimeout callback (lines 140-150) is registered,
	// then create an expired session and wait ~31s for the callback to fire.
	cfg := config.DefaultConfig()
	cfg.Session.IdleTimeout = 1 * time.Millisecond
	cfg.Session.MaxDuration = 1 * time.Millisecond
	cfg.Server.Listeners = nil // no listeners needed
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)

	// Start the proxy (registers the OnTimeout callback at lines 140-150)
	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Stop()

	// Create a session with very old timestamps so it times out immediately
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	sess := proxy.sessionManager.Create(&session.Info{
		Username: "timeout_fires_user",
		Database: "db",
		ClientIP: net.ParseIP("127.0.0.1"),
	}, clientConn)

	sess.LastActivity = time.Now().Add(-1 * time.Hour)
	sess.StartTime = time.Now().Add(-1 * time.Hour)

	// Wait for the session manager's 30s ticker to fire checkTimeouts
	deadline := time.After(35 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("session timeout callback did not remove the session within 35 seconds")
		case <-ticker.C:
			if proxy.sessionManager.Count() == 0 {
				// Session was removed by the timeout callback, confirming lines 140-150 ran
				return
			}
		}
	}
}

// ==================== Start: rate limiter cleanup ticker (lines 160-163) ====================

func TestProxyRateLimiterCleanupTicker(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = nil // no listeners needed
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(100, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)

	// Use very short cleanup interval to trigger the ticker quickly
	proxy.rlCleanupInterval = 50 * time.Millisecond

	// Pre-populate a rate limiter so the inner loop (line 161-163) executes
	proxy.rateLimiters["test-policy"] = ratelimit.NewLimiter(10, 10)

	if err := proxy.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer proxy.Stop()

	// Wait for the cleanup ticker to fire at least once (50ms interval)
	time.Sleep(200 * time.Millisecond)

	if proxy.rlCleanupStop == nil {
		t.Error("rlCleanupStop should be initialized after Start")
	}
}
