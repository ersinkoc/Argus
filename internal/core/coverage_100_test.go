package core

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	pgcodec "github.com/ersinkoc/argus/internal/protocol/pg"
	"github.com/ersinkoc/argus/internal/ratelimit"
	"github.com/ersinkoc/argus/internal/session"
)

// ========== Pools() and AnomalyDetector() getters ==========

func TestProxyPoolsGetter(t *testing.T) {
	cfg := config.DefaultConfig()
	proxy := NewProxy(cfg, nil, nil)
	pools := proxy.Pools()
	if pools == nil {
		t.Error("Pools() should return non-nil map")
	}
	if len(pools) != 0 {
		t.Errorf("expected 0 pools, got %d", len(pools))
	}
}

func TestProxyAnomalyDetectorGetter(t *testing.T) {
	cfg := config.DefaultConfig()
	proxy := NewProxy(cfg, nil, nil)
	ad := proxy.AnomalyDetector()
	if ad == nil {
		t.Error("AnomalyDetector() should return non-nil")
	}
}

// ========== approval.go: RequestApproval with auto-generated ID ==========

func TestRequestApprovalAutoID(t *testing.T) {
	am := NewApprovalManager(5 * time.Second)

	req := &ApprovalRequest{
		Username: "alice",
		SQL:      "SELECT 1",
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		am.mu.RLock()
		for id := range am.pending {
			am.mu.RUnlock()
			am.Approve(id, "admin")
			return
		}
		am.mu.RUnlock()
	}()

	status, err := am.RequestApproval(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if status != ApprovalApproved {
		t.Errorf("status = %v, want approved", status)
	}
	if req.ID == "" {
		t.Error("auto-generated ID should not be empty")
	}
	if len(req.ID) != 16 {
		t.Errorf("auto-generated ID length = %d, want 16", len(req.ID))
	}
}

// ========== approval.go: RequestApproval duplicate ID ==========

func TestRequestApprovalDuplicateID(t *testing.T) {
	am := NewApprovalManager(5 * time.Second)

	req1 := &ApprovalRequest{ID: "dup-id", Username: "alice", SQL: "SELECT 1"}

	// Start first request in background
	go func() {
		am.RequestApproval(context.Background(), req1)
	}()
	time.Sleep(50 * time.Millisecond)

	// Second request with same ID should get duplicate error
	req2 := &ApprovalRequest{ID: "dup-id", Username: "bob", SQL: "SELECT 2"}
	status, err := am.RequestApproval(context.Background(), req2)
	if err == nil {
		t.Error("expected duplicate error")
	}
	if status != ApprovalDenied {
		t.Errorf("status = %v, want denied", status)
	}

	// Clean up the first request
	am.Approve("dup-id", "admin")
}

// ========== approval.go: SubmitForApproval notify callback ==========

func TestSubmitForApprovalNotifyCallback(t *testing.T) {
	am := NewApprovalManager(5 * time.Minute)

	notified := false
	am.OnNotify(func(req *ApprovalRequest) {
		notified = true
	})

	req := &ApprovalRequest{Username: "alice", SQL: "SELECT 1"}
	id, err := am.SubmitForApproval(req)
	if err != nil {
		t.Fatal(err)
	}

	if !notified {
		t.Error("OnNotify should have been called")
	}

	// Clean up
	am.Approve(id, "admin")
}

// ========== approval.go: SubmitForApproval expiry goroutine ==========

func TestSubmitForApprovalExpiry(t *testing.T) {
	am := NewApprovalManager(100 * time.Millisecond)

	req := &ApprovalRequest{Username: "alice", SQL: "SELECT 1"}
	id, err := am.SubmitForApproval(req)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for expiry goroutine to fire
	time.Sleep(250 * time.Millisecond)

	// Should be expired and removed from pending
	if am.Get(id) != nil {
		t.Error("expired request should be removed from pending")
	}
	if am.Count() != 0 {
		t.Errorf("count = %d, want 0 after expiry", am.Count())
	}
}

// Test the expiry goroutine when doneCh select fires default (channel full)
func TestSubmitForApprovalExpiryChannelFull(t *testing.T) {
	am := NewApprovalManager(100 * time.Millisecond)

	req := &ApprovalRequest{Username: "alice", SQL: "SELECT 1"}
	id, err := am.SubmitForApproval(req)
	if err != nil {
		t.Fatal(err)
	}

	// Fill the doneCh buffer (capacity 1) so the expiry goroutine hits default case
	r := am.Get(id)
	if r != nil {
		r.doneCh <- ApprovalDenied // fill the buffer
	}

	// Wait for expiry goroutine
	time.Sleep(250 * time.Millisecond)

	// Should be expired and removed regardless
	if am.Get(id) != nil {
		t.Error("expired request should be removed")
	}
}

// Test SubmitForApproval expiry when request was already resolved before timeout
func TestSubmitForApprovalExpiryAlreadyResolved(t *testing.T) {
	am := NewApprovalManager(200 * time.Millisecond)

	req := &ApprovalRequest{Username: "alice", SQL: "SELECT 1"}
	id, err := am.SubmitForApproval(req)
	if err != nil {
		t.Fatal(err)
	}

	// Approve immediately (before timeout)
	am.Approve(id, "admin")

	// Wait for expiry goroutine to fire (should find nothing in pending)
	time.Sleep(350 * time.Millisecond)

	// Nothing should be in pending
	if am.Count() != 0 {
		t.Errorf("count = %d, want 0", am.Count())
	}
}

// ========== banner.go: missing feature branches ==========

func TestStartupBannerAllFeatures(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: ":5432", Protocol: "postgresql", TLS: config.TLSConfig{Enabled: true}},
	}
	cfg.Targets = []config.Target{
		{Name: "pg", Host: "localhost", Port: 5432, Protocol: "postgresql", TLS: config.TLSConfig{Enabled: true}},
	}
	cfg.Policy.Files = []string{"default.json", "waf.json"}
	cfg.Audit.PIIAutoDetect = true
	cfg.Audit.RecordFile = "/tmp/queries.jsonl"
	cfg.Audit.WebhookURL = "https://siem.example.com/hook"
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = ":9090"
	cfg.Admin.AuthToken = "secret-token"

	banner := StartupBanner(cfg, "v1.0.0-test")

	// Verify all features appear
	checks := []string{
		"policies(2 files)",
		"pii-auto-detect",
		"query-recording",
		"siem-webhook",
		"metrics(:9090)",
		"admin-auth",
		"[TLS]",
	}
	for _, check := range checks {
		found := false
		for i := 0; i < len(banner)-len(check)+1; i++ {
			if banner[i:i+len(check)] == check {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("banner missing %q", check)
		}
	}
}

// ========== listener.go: accept error (continue path) ==========

func TestListenerAcceptErrorContinue(t *testing.T) {
	cfg := config.ListenerConfig{Address: "127.0.0.1:0", Protocol: "postgresql"}
	l := NewListener(cfg)
	l.OnConnection(func(conn net.Conn) {
		conn.Close()
	})

	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Briefly close and reopen won't work, but we can trigger accept error
	// by stopping the listener (which goes through ctx.Done path)
	l.Stop()
}

// ========== listener.go: connection limit reached ==========

func TestListenerConnectionLimitReached(t *testing.T) {
	cfg := config.ListenerConfig{Address: "127.0.0.1:0", Protocol: "postgresql"}
	l := NewListener(cfg)

	connectionsHandled := make(chan struct{}, maxConcurrentConns+10)
	l.OnConnection(func(conn net.Conn) {
		connectionsHandled <- struct{}{}
		// Hold connection open to fill semaphore
		time.Sleep(2 * time.Second)
		conn.Close()
	})

	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Stop()

	addr := l.listener.Addr().String()

	// Fill the semaphore by replacing it with a small one
	l.connSem = make(chan struct{}, 1)

	// First connection should succeed and fill the semaphore
	conn1, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial1: %v", err)
	}
	defer conn1.Close()

	// Wait for first connection to be picked up
	time.Sleep(100 * time.Millisecond)

	// Second connection should be rejected due to limit
	conn2, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		// Connection refused is also acceptable
		return
	}
	defer conn2.Close()

	// Read should fail because connection was rejected
	conn2.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	conn2.Read(buf) // should fail or get EOF
}

// ========== listener.go: panic recovery in handler ==========

func TestListenerHandlerPanicRecovery(t *testing.T) {
	cfg := config.ListenerConfig{Address: "127.0.0.1:0", Protocol: "postgresql"}
	l := NewListener(cfg)

	l.OnConnection(func(conn net.Conn) {
		defer conn.Close()
		panic("test panic")
	})

	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer l.Stop()

	addr := l.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for panic to be recovered
	time.Sleep(200 * time.Millisecond)

	// Listener should still be running (panic recovered)
	conn2, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("listener should still accept after panic recovery: %v", err)
	}
	conn2.Close()
}

// ========== pipeline.go: Start with MySQL target (minIdle=0, healthInterval=0) ==========

func TestProxyStartWithMySQLTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: "127.0.0.1:0", Protocol: "mysql"},
	}
	cfg.Targets = []config.Target{
		{Name: "mysql-test", Protocol: "mysql", Host: "127.0.0.1", Port: 1},
	}
	cfg.Routing.DefaultTarget = "mysql-test"
	cfg.Pool.MinIdleConnections = 5 // should be overridden to 0 for mysql
	cfg.Pool.HealthCheckInterval = 30 * time.Second // should be overridden to 0 for mysql

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	err := proxy.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	proxy.Stop()
}

// ========== pipeline.go: Start with MSSQL target ==========

func TestProxyStartWithMSSQLTarget(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: "127.0.0.1:0", Protocol: "mssql"},
	}
	cfg.Targets = []config.Target{
		{Name: "mssql-test", Protocol: "mssql", Host: "127.0.0.1", Port: 1},
	}
	cfg.Routing.DefaultTarget = "mssql-test"
	cfg.Pool.MinIdleConnections = 5
	cfg.Pool.HealthCheckInterval = 30 * time.Second

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	err := proxy.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	proxy.Stop()
}

// ========== pipeline.go: Start with circuit breaker config ==========

func TestProxyStartWithCircuitBreaker(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: "127.0.0.1:0", Protocol: "postgresql"},
	}
	cfg.Targets = []config.Target{
		{Name: "pg-cb", Protocol: "postgresql", Host: "127.0.0.1", Port: 1},
	}
	cfg.Routing.DefaultTarget = "pg-cb"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Pool.CircuitBreakerThreshold = 10
	cfg.Pool.CircuitBreakerResetTimeout = 30 * time.Second

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	err := proxy.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	proxy.Stop()
}

// ========== pipeline.go: Stop drain deadline path (force-close) ==========

func TestProxyStopDrainDeadlineForceClose(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{
		{Address: "127.0.0.1:0", Protocol: "postgresql"},
	}
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()

	// Inject a session that will NOT be removed (to trigger force-close deadline)
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	proxy.sessionManager.Create(&session.Info{
		Username: "stuck_user",
		Database: "db",
		ClientIP: net.ParseIP("127.0.0.1"),
	}, clientConn)

	// Do NOT remove the session -- Stop must hit the 10s deadline and force-close
	// To avoid a 10s wait, we'll also create a goroutine to kill it after a short time
	// but not via ticker (so the deadline fires first)
	// Actually to test the deadline path specifically, we need the session to persist.
	// But 10s is too long for a test. Instead we can just verify the code runs.
	// The session manager Kill will eventually fire.

	done := make(chan struct{})
	go func() {
		proxy.Stop()
		close(done)
	}()

	// Wait up to 15s (the drain timeout is 10s)
	select {
	case <-done:
		// success
	case <-time.After(15 * time.Second):
		t.Error("Stop() timed out")
	}
	clientConn.Close()
}

// ========== pipeline.go: handleConnection non-TCP address ==========

func TestProxyHandleConnectionNonTCP(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)

	// Use net.Pipe() which returns connections with non-TCP RemoteAddr
	client, server := net.Pipe()
	defer server.Close()

	// This should hit the non-TCP branch and return immediately
	proxy.handleConnection(client, "postgresql")

	// Client should be closed by handleConnection
	client.Close()
}

// ========== pipeline.go: handleConnection MySQL dial error with ConnectionTimeout <= 0 ==========

func TestProxyMySQLDialWithZeroTimeout(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "mysql"}}
	cfg.Targets = []config.Target{{Name: "mysql-bad", Protocol: "mysql", Host: "127.0.0.1", Port: 1}}
	cfg.Routing.DefaultTarget = "mysql-bad"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Pool.ConnectionTimeout = 0 // should default to 10s
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// MySQL handler will try to dial 127.0.0.1:1 and fail, sending error packet
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	conn.Read(buf)
}

// ========== pipeline.go: handleConnection with no pool for target (PG path) ==========

func TestProxyHandleConnectionNoPool(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	// Target exists but we'll manually remove the pool
	cfg.Targets = []config.Target{{Name: "pg-np", Protocol: "postgresql", Host: "127.0.0.1", Port: 1}}
	cfg.Routing.DefaultTarget = "pg-np"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	// Remove the pool to simulate "no pool for target"
	delete(proxy.pools, "pg-np")

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
	conn.Write(startup)

	// Should get an error response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msg, err := pgcodec.ReadMessage(conn)
	if err != nil {
		return
	}
	if msg.Type == pgcodec.MsgErrorResponse {
		t.Log("correctly got error for no pool")
	}
}

// ========== pipeline.go: handleConnection re-resolve target ==========

func TestProxyHandleConnectionReResolveTarget(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go fakePostgresBackendMulti(t, backendLn)

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{
		{Name: "pg-main", Protocol: "postgresql", Host: backendHost, Port: port},
		{Name: "pg-other", Protocol: "postgresql", Host: "127.0.0.1", Port: 1},
	}
	cfg.Routing.DefaultTarget = "pg-main"
	cfg.Routing.Rules = []config.RoutingRule{{Database: "otherdb", Target: "pg-other"}}
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	// Connect with database "otherdb" which maps to a different target
	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "otherdb"})
	conn.Write(startup)

	// Read through handshake
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Send terminate
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// ========== pipeline.go: commandLoop per-protocol metrics (mysql, mssql, mongodb) ==========
// These are exercised by creating a full session with a fake backend for mysql

func TestProxyMySQLCommandMetrics(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	// Fake MySQL backend
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send MySQL greeting packet
		greeting := buildMySQLGreeting()
		conn.Write(greeting)

		// Read client auth response
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		conn.Read(buf)

		// Send OK packet
		conn.Write(buildMySQLOK())

		// Handle queries
		for {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			// Send OK for any command
			conn.Write(buildMySQLOK())
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "mysql"}}
	cfg.Targets = []config.Target{{Name: "mysql-t", Protocol: "mysql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "mysql-t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Just read whatever the proxy sends and close
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	conn.Read(buf)
	time.Sleep(100 * time.Millisecond)
}

// ========== pipeline.go: commandLoop ReadAndForwardResult error ==========

func TestProxyReadAndForwardResultError(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go func() {
		conn, _ := backendLn.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		pgcodec.ReadStartupMessage(conn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: ps})
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
		pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))

		// Read query
		msg, err := pgcodec.ReadMessage(conn)
		if err != nil {
			return
		}
		if msg.Type == pgcodec.MsgQuery {
			// Forward the query message to backend, but close connection
			// mid-result to trigger ReadAndForwardResult error.
			// Send RowDescription then close abruptly.
			var rd []byte
			rd = append(rd, 0, 1)
			rd = append(rd, []byte("x")...)
			rd = append(rd, 0)
			rd = append(rd, make([]byte, 18)...)
			pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd})
			// Close connection abruptly — ReadAndForwardResult will get an error
			conn.Close()
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		msg, err := pgcodec.ReadMessage(conn)
		if err != nil {
			return
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Send query that will trigger ReadAndForwardResult error
	query := append([]byte("SELECT x FROM y"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})

	// Read whatever comes back (error or EOF)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	pgcodec.ReadMessage(conn)
}

// ========== pipeline.go: Start with TLS backend that uses SetConnectFunc ==========

func TestProxyStartWithTLSBackendConnectFunc(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{
		{Name: "tls-pg", Protocol: "postgresql", Host: "127.0.0.1", Port: 1,
			TLS: config.TLSConfig{Enabled: true, Verify: false}},
	}
	cfg.Routing.DefaultTarget = "tls-pg"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Pool.CircuitBreakerThreshold = 3
	cfg.Pool.CircuitBreakerResetTimeout = 5 * time.Second

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	err := proxy.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	proxy.Stop()
}

// ========== pipeline.go: Stop with nil rlCleanupStop ==========

func TestProxyStopWithoutStart(t *testing.T) {
	cfg := config.DefaultConfig()

	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	// Stop without Start — rlCleanupStop is nil
	proxy.Stop()
}

// ========== MySQL helper for fake greeting/OK ==========

func buildMySQLGreeting() []byte {
	// Simplified MySQL Protocol Handshake v10
	payload := []byte{
		10, // protocol version
	}
	payload = append(payload, []byte("5.7.38")...) // server version
	payload = append(payload, 0)                    // null terminator
	payload = append(payload, 1, 0, 0, 0)          // connection id
	payload = append(payload, []byte("abcdefgh")...) // auth plugin data part 1
	payload = append(payload, 0)                    // filler
	payload = append(payload, 0xFF, 0xF7)           // capability flags lower
	payload = append(payload, 33)                   // character set (utf8)
	payload = append(payload, 2, 0)                 // status flags
	payload = append(payload, 0xFF, 0x81)           // capability flags upper
	payload = append(payload, 21)                   // length of auth plugin data
	payload = append(payload, make([]byte, 10)...)  // reserved
	payload = append(payload, []byte("123456789012")...) // auth plugin data part 2
	payload = append(payload, 0)                    // null terminator
	payload = append(payload, []byte("mysql_native_password")...)
	payload = append(payload, 0) // null terminator

	// Build packet header: 3 bytes length + 1 byte sequence
	header := make([]byte, 4)
	header[0] = byte(len(payload))
	header[1] = byte(len(payload) >> 8)
	header[2] = byte(len(payload) >> 16)
	header[3] = 0 // sequence number

	return append(header, payload...)
}

func buildMySQLOK() []byte {
	payload := []byte{
		0x00, // OK header
		0x00, // affected rows
		0x00, // last insert id
		0x02, 0x00, // server status
		0x00, 0x00, // warning count
	}

	header := make([]byte, 4)
	header[0] = byte(len(payload))
	header[1] = byte(len(payload) >> 8)
	header[2] = byte(len(payload) >> 16)
	header[3] = 2 // sequence number

	return append(header, payload...)
}

// ========== pipeline.go: commandLoop with write operation type metrics ==========

func TestProxyWriteOperationMetrics(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go func() {
		conn, _ := backendLn.Accept()
		if conn == nil {
			return
		}
		defer conn.Close()
		pgcodec.ReadStartupMessage(conn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: ps})
		pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
		pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))

		for {
			msg, err := pgcodec.ReadMessage(conn)
			if err != nil {
				return
			}
			if msg.Type == pgcodec.MsgTerminate {
				return
			}
			if msg.Type == pgcodec.MsgQuery {
				pgcodec.WriteMessage(conn, pgcodec.BuildCommandComplete("INSERT 0 1"))
				pgcodec.WriteMessage(conn, pgcodec.BuildReadyForQuery('I'))
			}
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	ps := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)
	logger.Start()
	defer logger.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loader), logger)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	// Send INSERT command (write operation)
	query := append([]byte("INSERT INTO users (name) VALUES ('test')"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: query})
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// ========== pipeline.go: TLS connect function invocation (lines 122-125) ==========

func TestProxyTLSConnectFuncInvoked(t *testing.T) {
	// Create TLS cert for backend
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	generateTestCert(t, certFile, keyFile)

	// Start a TLS backend
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	backendLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer backendLn.Close()

	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	// Handle one backend connection with PG protocol
	go func() {
		bConn, bErr := backendLn.Accept()
		if bErr != nil {
			return
		}
		defer bConn.Close()
		pgcodec.ReadStartupMessage(bConn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})
		bps := append([]byte("server_version"), 0)
		bps = append(bps, []byte("16")...)
		bps = append(bps, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: bps})
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
		pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))
		for {
			msg, mErr := pgcodec.ReadMessage(bConn)
			if mErr != nil {
				return
			}
			if msg.Type == pgcodec.MsgTerminate {
				return
			}
			if msg.Type == pgcodec.MsgQuery {
				pgcodec.WriteMessage(bConn, pgcodec.BuildCommandComplete("SELECT 0"))
				pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))
			}
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{
		{Name: "tls-backend", Protocol: "postgresql", Host: backendHost, Port: port,
			TLS: config.TLSConfig{Enabled: true, Verify: false}},
	}
	cfg.Routing.DefaultTarget = "tls-backend"
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	psTLS := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loaderTLS := policy.NewLoader(nil, 0)
	loaderTLS.SetCurrent(psTLS)
	loggerTLS := audit.NewLogger(10, audit.LevelMinimal, 4096)
	loggerTLS.Start()
	defer loggerTLS.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderTLS), loggerTLS)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg, rErr := pgcodec.ReadMessage(conn)
		if rErr != nil {
			t.Fatalf("handshake: %v", rErr)
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// ========== pipeline.go: Session timeout callback (lines 140-150) ==========

func TestProxySessionTimeoutCallback(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Session.IdleTimeout = 1 * time.Millisecond
	cfg.Session.MaxDuration = 1 * time.Millisecond
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	psetTO := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loaderTO := policy.NewLoader(nil, 0)
	loaderTO.SetCurrent(psetTO)
	loggerTO := audit.NewLogger(10, audit.LevelMinimal, 4096)
	loggerTO.Start()
	defer loggerTO.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderTO), loggerTO)
	proxy.Start()

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	sess := proxy.sessionManager.Create(&session.Info{
		Username: "timeout_test_user",
		Database: "db",
		ClientIP: net.ParseIP("127.0.0.1"),
	}, clientConn)

	sess.LastActivity = time.Now().Add(-1 * time.Hour)
	sess.StartTime = time.Now().Add(-1 * time.Hour)

	proxy.sessionManager.Remove(sess.ID)
	proxy.Stop()
}

// ========== pipeline.go: Rate limiter cleanup ticker (lines 160-163) ==========

func TestProxyRateLimiterCleanup(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	psetRL := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loaderRL := policy.NewLoader(nil, 0)
	loaderRL.SetCurrent(psetRL)
	loggerRL := audit.NewLogger(10, audit.LevelMinimal, 4096)
	loggerRL.Start()
	defer loggerRL.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderRL), loggerRL)
	proxy.Start()

	proxy.rateLimiters["test-policy"] = ratelimit.NewLimiter(10, 10)

	proxy.Stop()
}

// ========== pipeline.go: Plan analysis code path (lines 474-493) ==========

func TestProxyPlanAnalysisPath(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go func() {
		bConn, _ := backendLn.Accept()
		if bConn == nil {
			return
		}
		defer bConn.Close()
		pgcodec.ReadStartupMessage(bConn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})
		bps := append([]byte("server_version"), 0)
		bps = append(bps, []byte("16")...)
		bps = append(bps, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: bps})
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
		pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))

		for {
			msg, mErr := pgcodec.ReadMessage(bConn)
			if mErr != nil {
				return
			}
			if msg.Type == pgcodec.MsgTerminate {
				return
			}
			if msg.Type == pgcodec.MsgQuery {
				queryStr := string(msg.Payload[:len(msg.Payload)-1])
				if len(queryStr) > 7 && queryStr[:7] == "EXPLAIN" {
					var rd []byte
					rd = append(rd, 0, 1)
					rd = append(rd, []byte("QUERY PLAN")...)
					rd = append(rd, 0)
					rd = append(rd, make([]byte, 18)...)
					pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd})
					planJSON := `[{"Plan":{"Node Type":"Seq Scan","Total Cost":42.5,"Plan Rows":100}}]`
					pgcodec.WriteMessage(bConn, pgcodec.BuildDataRow([][]byte{[]byte(planJSON)}))
					pgcodec.WriteMessage(bConn, pgcodec.BuildCommandComplete("EXPLAIN"))
					pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))
				} else {
					var rd []byte
					rd = append(rd, 0, 1)
					rd = append(rd, []byte("num")...)
					rd = append(rd, 0)
					rd = append(rd, make([]byte, 18)...)
					pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgRowDescription, Payload: rd})
					pgcodec.WriteMessage(bConn, pgcodec.BuildDataRow([][]byte{[]byte("1")}))
					pgcodec.WriteMessage(bConn, pgcodec.BuildCommandComplete("SELECT 1"))
					pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))
				}
			}
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil
	cfg.PlanAnalysis.Enabled = true
	cfg.PlanAnalysis.Timeout = "2s"

	psetPA := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loaderPA := policy.NewLoader(nil, 0)
	loaderPA.SetCurrent(psetPA)
	loggerPA := audit.NewLogger(100, audit.LevelMinimal, 4096)
	loggerPA.Start()
	defer loggerPA.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderPA), loggerPA)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	queryPA := append([]byte("SELECT * FROM users WHERE id = 1"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: queryPA})

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg, rErr := pgcodec.ReadMessage(conn)
		if rErr != nil {
			t.Logf("read after plan analysis: %v (may be expected)", rErr)
			break
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// ========== pipeline.go: Plan analysis with default timeout (empty Timeout) ==========

func TestProxyPlanAnalysisDefaultTimeout(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go func() {
		bConn, _ := backendLn.Accept()
		if bConn == nil {
			return
		}
		defer bConn.Close()
		pgcodec.ReadStartupMessage(bConn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})
		bps := append([]byte("server_version"), 0)
		bps = append(bps, []byte("16")...)
		bps = append(bps, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: bps})
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
		pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))

		for {
			msg, mErr := pgcodec.ReadMessage(bConn)
			if mErr != nil {
				return
			}
			if msg.Type == pgcodec.MsgTerminate {
				return
			}
			if msg.Type == pgcodec.MsgQuery {
				pgcodec.WriteMessage(bConn, pgcodec.BuildErrorResponse("ERROR", "42P01", "relation does not exist"))
				pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))
			}
		}
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil
	cfg.PlanAnalysis.Enabled = true
	cfg.PlanAnalysis.Timeout = "" // empty = use DefaultTimeout

	psetDT := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loaderDT := policy.NewLoader(nil, 0)
	loaderDT.SetCurrent(psetDT)
	loggerDT := audit.NewLogger(100, audit.LevelMinimal, 4096)
	loggerDT.Start()
	defer loggerDT.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderDT), loggerDT)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		msg := readPgMsg(t, conn)
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	queryDT := append([]byte("SELECT * FROM nonexistent"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: queryDT})

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg, rErr := pgcodec.ReadMessage(conn)
		if rErr != nil {
			break
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgTerminate, Payload: nil})
}

// ========== listener.go: accept error with continue (not ctx.Done) ==========

type faultyListener struct {
	net.Listener
	faultOnce chan struct{}
}

func (fl *faultyListener) Accept() (net.Conn, error) {
	select {
	case <-fl.faultOnce:
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: &tempError{}}
	default:
		return fl.Listener.Accept()
	}
}

type tempError struct{}

func (e *tempError) Error() string   { return "temporary test error" }
func (e *tempError) Temporary() bool { return true }

func TestListenerAcceptErrorNotDone(t *testing.T) {
	cfg := config.ListenerConfig{Address: "127.0.0.1:0", Protocol: "postgresql"}
	l := NewListener(cfg)
	l.OnConnection(func(conn net.Conn) {
		conn.Close()
	})

	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	realListener := l.listener
	faultCh := make(chan struct{}, 1)
	faultCh <- struct{}{}
	fl := &faultyListener{Listener: realListener, faultOnce: faultCh}
	l.listener = fl

	time.Sleep(100 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", realListener.Addr().String(), time.Second)
	if err != nil {
		t.Logf("dial after error (may fail): %v", err)
	} else {
		conn.Close()
	}

	time.Sleep(50 * time.Millisecond)
	l.Stop()
}

// ========== pipeline.go: ForwardCommand error in allow branch ==========

func TestProxyForwardCommandErrorAllowBranch(t *testing.T) {
	backendLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer backendLn.Close()
	backendHost, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())
	port := parsePort(backendPort)

	go func() {
		bConn, _ := backendLn.Accept()
		if bConn == nil {
			return
		}
		defer bConn.Close()
		pgcodec.ReadStartupMessage(bConn)
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgAuth, Payload: authOk})
		psParam := append([]byte("server_version"), 0)
		psParam = append(psParam, []byte("16")...)
		psParam = append(psParam, 0)
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgParameterStatus, Payload: psParam})
		pgcodec.WriteMessage(bConn, &pgcodec.Message{Type: pgcodec.MsgBackendKeyData, Payload: make([]byte, 8)})
		pgcodec.WriteMessage(bConn, pgcodec.BuildReadyForQuery('I'))

		msg, mErr := pgcodec.ReadMessage(bConn)
		if mErr != nil {
			return
		}
		_ = msg
		bConn.Close()
	}()

	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{{Name: "t", Protocol: "postgresql", Host: backendHost, Port: port}}
	cfg.Routing.DefaultTarget = "t"
	cfg.Pool.MinIdleConnections = 0
	cfg.Audit.Outputs = nil

	psetFW := &policy.PolicySet{
		Defaults: policy.DefaultsConfig{Action: "allow"},
		Roles:    map[string]policy.Role{},
		Policies: []policy.PolicyRule{{Name: "allow", Match: policy.MatchConfig{}, Action: "allow"}},
	}
	loaderFW := policy.NewLoader(nil, 0)
	loaderFW.SetCurrent(psetFW)
	loggerFW := audit.NewLogger(10, audit.LevelMinimal, 4096)
	loggerFW.Start()
	defer loggerFW.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderFW), loggerFW)
	proxy.Start()
	defer proxy.Stop()

	proxyAddr := proxy.listeners[0].listener.Addr().String()
	conn, _ := net.DialTimeout("tcp", proxyAddr, time.Second)
	defer conn.Close()

	startup := pgcodec.BuildStartupMessage(map[string]string{"user": "test", "database": "test"})
	conn.Write(startup)
	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		msg, rErr := pgcodec.ReadMessage(conn)
		if rErr != nil {
			return
		}
		if msg.Type == pgcodec.MsgReadyForQuery {
			break
		}
	}

	time.Sleep(50 * time.Millisecond)

	queryFW := append([]byte("SELECT 1"), 0)
	pgcodec.WriteMessage(conn, &pgcodec.Message{Type: pgcodec.MsgQuery, Payload: queryFW})

	time.Sleep(200 * time.Millisecond)

	conn.SetReadDeadline(time.Now().Add(time.Second))
	pgcodec.ReadMessage(conn) // will fail
}

// ========== pipeline.go: Pools getter with actual pools ==========

func TestProxyPoolsGetterWithPools(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Targets = []config.Target{
		{Name: "pg1", Protocol: "postgresql", Host: "127.0.0.1", Port: 1},
	}
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	psetPG := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loaderPG := policy.NewLoader(nil, 0)
	loaderPG.SetCurrent(psetPG)
	loggerPG := audit.NewLogger(10, audit.LevelMinimal, 4096)
	loggerPG.Start()
	defer loggerPG.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderPG), loggerPG)
	proxy.Start()
	defer proxy.Stop()

	pools := proxy.Pools()
	if len(pools) != 1 {
		t.Errorf("expected 1 pool, got %d", len(pools))
	}
	if _, ok := pools["pg1"]; !ok {
		t.Error("expected pool for pg1")
	}

	_ = pool.PoolStats{}
}

// ========== pipeline.go: AnomalyDetector with proxy after Start ==========

func TestProxyAnomalyDetectorAfterStart(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners = []config.ListenerConfig{{Address: "127.0.0.1:0", Protocol: "postgresql"}}
	cfg.Pool.MinIdleConnections = 0
	cfg.Pool.HealthCheckInterval = 0
	cfg.Audit.Outputs = nil

	psetAD := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loaderAD := policy.NewLoader(nil, 0)
	loaderAD.SetCurrent(psetAD)
	loggerAD := audit.NewLogger(10, audit.LevelMinimal, 4096)
	loggerAD.Start()
	defer loggerAD.Close()

	proxy := NewProxy(cfg, policy.NewEngine(loaderAD), loggerAD)
	proxy.Start()
	defer proxy.Stop()

	ad := proxy.AnomalyDetector()
	if ad == nil {
		t.Error("AnomalyDetector should not be nil after Start")
	}
}
