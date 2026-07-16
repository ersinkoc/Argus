package core

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/metrics"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/protocol/mysql"
	"github.com/ersinkoc/argus/internal/protocol/mssql"
	"github.com/ersinkoc/argus/internal/protocol/pg"
	"github.com/ersinkoc/argus/internal/session"
)

// PostAuthClientAndServer performs proxy auth for PostgreSQL:
//  1. Reads the client startup, extracts the username
//  2. Calls the identity resolver to get the resolved target and credential
//  3. Connects to the resolved target
//  4. Authenticates as a client to the resolved backend (ProxyAuthClient)
//  5. Authenticates as a server to the original client (ProxyAuthServer)
//  6. Returns the session info and backend connection
//
// This replaces the standard passthrough handshake for proxy auth mode.
func (p *Proxy) PostAuthClientAndServer(
	clientConn net.Conn,
	remoteAddr *net.TCPAddr,
	protocolName string,
) (*session.Info, net.Conn, error) {
	if p.identityResolver == nil {
		return nil, nil, fmt.Errorf("no identity resolver configured")
	}

	// Step 1: Read startup from client (PG-specific)
	startupData, err := pg.ReadStartupMessage(clientConn)
	if err != nil {
		return nil, nil, fmt.Errorf("reading client startup: %w", err)
	}

	startup, err := pg.ParseStartupMessage(startupData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing startup message: %w", err)
	}

	username := startup.Parameters["user"]
	database := startup.Parameters["database"]
	if database == "" {
		database = username
	}

	slog.Info("proxy auth: client connecting",
		"user", username, "database", database, "client_ip", remoteAddr.IP)

	// Step 2: Resolve identity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolved, err := p.identityResolver.Resolve(ctx, &ResolveIdentity{
		Username: username,
		Database: database,
		ClientIP: remoteAddr.IP.String(),
		Protocol: protocolName,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("identity resolution failed: %w", err)
	}

	if resolved == nil {
		return nil, nil, fmt.Errorf("identity resolver returned nil target")
	}

	slog.Info("proxy auth: identity resolved",
		"user", username,
		"target", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port),
		"db_user", resolved.Username,
	)

	// Step 3: Connect to resolved target
	dialTimeout := 10 * time.Second
	if p.cfg.Pool.ConnectionTimeout > 0 {
		dialTimeout = p.cfg.Pool.ConnectionTimeout
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), dialTimeout)
	defer dialCancel()

	var d net.Dialer
	backendConn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		return nil, nil, fmt.Errorf("connecting to resolved target %s:%d: %w",
			resolved.Host, resolved.Port, err)
	}

	// Build new startup with resolved username
	resolvedParams := make(map[string]string)
	for k, v := range startup.Parameters {
		resolvedParams[k] = v
	}
	resolvedParams["user"] = resolved.Username
	resolvedStartup := pg.BuildStartupMessage(resolvedParams)

	// Forward startup to backend
	if err := pg.WriteRawBytes(backendConn, resolvedStartup); err != nil {
		backendConn.Close()
		return nil, nil, fmt.Errorf("forwarding startup to resolved target: %w", err)
	}

	// Step 4: Authenticate to the backend (as client) using resolved credential
	if err := pg.ProxyAuthClient(ctx, backendConn, resolved.Password); err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		backendConn.Close()
		return nil, nil, fmt.Errorf("backend proxy auth failed: %w", err)
	}
	slog.Debug("proxy auth: backend authenticated")

	// Step 5: Authenticate the client (as server) using the same credential
	if err := pg.ProxyAuthServer(ctx, clientConn, resolved.Password); err != nil {
		backendConn.Close()
		return nil, nil, fmt.Errorf("client proxy auth failed: %w", err)
	}
	slog.Debug("proxy auth: client authenticated")

	// Step 6: Relay post-auth messages from backend to client
	if err := pg.RelayPostAuthFromBackend(backendConn, clientConn); err != nil {
		backendConn.Close()
		return nil, nil, fmt.Errorf("relaying post-auth messages: %w", err)
	}

	// Build session info
	info := &session.Info{
		Username:   username,
		Database:   database,
		ClientIP:   remoteAddr.IP,
		Parameters: startup.Parameters,
		AuthMethod: "proxy_scram_sha_256",
	}
	if info.Database == "" {
		info.Database = info.Username
	}

	slog.Info("proxy auth: session established",
		"user", info.Username,
		"database", info.Database,
		"resolved_user", resolved.Username,
		"target", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port),
	)

	return info, backendConn, nil
}

// handleProxyAuthMySQL handles proxy auth for MySQL connections.
func (p *Proxy) handleProxyAuthMySQL(clientConn net.Conn, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	ctx := context.Background()

	// Step 1: Send proxy greeting, read client handshake
	handshake, _, err := mysql.ProxyAuthServer(clientConn, "")
	if err != nil {
		slog.Error("mysql proxy auth: client handshake failed", "error", err)
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(), ClientIP: remoteAddr.IP.String(),
			Action: "block", Error: err.Error(),
		})
		return
	}

	// Step 2: Resolve identity
	resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	resolved, err := p.identityResolver.Resolve(resolveCtx, &ResolveIdentity{
		Username: handshake.Username,
		Database: handshake.Database,
		ClientIP: remoteAddr.IP.String(),
		Protocol: "mysql",
	})
	cancel()
	if err != nil {
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(), ClientIP: remoteAddr.IP.String(),
			Action: "block", Error: err.Error(),
		})
		return
	}

	// Step 3: Connect to resolved target
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	backendConn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		slog.Error("mysql proxy auth: connect to resolved target failed", "error", err)
		return
	}

	// Step 4: Authenticate to backend
	if err := mysql.ProxyAuthClient(backendConn, resolved.Username, handshake.Database, resolved.Password); err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		backendConn.Close()
		slog.Error("mysql proxy auth: backend auth failed", "error", err)
		return
	}

	// Step 5: Session setup
	sessionInfo := &session.Info{
		Username:   handshake.Username,
		Database:   handshake.Database,
		ClientIP:   remoteAddr.IP,
		AuthMethod: "proxy_mysql_native",
	}
	p.setupProxyAuthSession(ctx, clientConn, backendConn, sessionInfo, remoteAddr, handler)
}

// handleProxyAuthMSSQL handles proxy auth for MSSQL connections.
func (p *Proxy) handleProxyAuthMSSQL(clientConn net.Conn, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	ctx := context.Background()

	// Step 1: Read PreLogin + Login7 from client
	username, _, err := mssql.ProxyAuthServer(clientConn)
	if err != nil {
		slog.Error("mssql proxy auth: client handshake failed", "error", err)
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(), ClientIP: remoteAddr.IP.String(),
			Action: "block", Error: err.Error(),
		})
		return
	}

	// Extract PreLogin data for forwarding (stored by ProxyAuthServer call)
	// We need to keep the PreLogin data — ProxyAuthServer consumes the PreLogin
	// from the client. For MSSQL, we forward the client's PreLogin to the backend.
	// The PreLogin data is consumed from the client — we need to reconstruct it.
	preLoginData := buildMSSQLPreLogin()

	// Step 2: Resolve identity
	resolveCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	resolved, err := p.identityResolver.Resolve(resolveCtx, &ResolveIdentity{
		Username: username,
		Database: "",
		ClientIP: remoteAddr.IP.String(),
		Protocol: "mssql",
	})
	cancel()
	if err != nil {
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(), ClientIP: remoteAddr.IP.String(),
			Action: "block", Error: err.Error(),
		})
		return
	}

	// Step 3: Connect to resolved target
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	backendConn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		slog.Error("mssql proxy auth: connect to resolved target failed", "error", err)
		return
	}

	// Step 4: Authenticate to backend
	loginResp, err := mssql.ProxyAuthClient(backendConn, preLoginData, resolved.Username, resolved.Password)
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		backendConn.Close()
		slog.Error("mssql proxy auth: backend auth failed", "error", err)
		return
	}

	// Forward backend login response to client
	// This must be wrapped in the proper TDS packet type
	mssql.ForwardLoginResponse(clientConn, loginResp)

	// Step 5: Session setup
	sessionInfo := &session.Info{
		Username:   username,
		ClientIP:   remoteAddr.IP,
		AuthMethod: "proxy_tds7",
	}
	p.setupProxyAuthSession(ctx, clientConn, backendConn, sessionInfo, remoteAddr, handler)
}

// setupProxyAuthSession handles the common session setup after a successful proxy auth:
// session creation, role resolution, audit logging, and command loop dispatch.
func (p *Proxy) setupProxyAuthSession(ctx context.Context, clientConn, backendConn net.Conn, sessionInfo *session.Info, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	if p.sessionLimiter != nil {
		if !p.sessionLimiter.Acquire(sessionInfo.Username) {
			handler.WriteError(ctx, clientConn, "53300", "Too many connections for user "+sessionInfo.Username)
			p.auditLogger.Log(audit.Event{
				EventType: audit.ConnectionClose.String(), Username: sessionInfo.Username,
				ClientIP: remoteAddr.IP.String(), Action: "rejected",
				Reason: "concurrent session limit exceeded",
			})
			return
		}
		defer p.sessionLimiter.Release(sessionInfo.Username)
	}

	sess := p.sessionManager.Create(sessionInfo, clientConn)
	sess.BackendConn = backendConn
	if ps := p.policyEngine.Loader().Current(); ps != nil {
		sess.Roles = policy.ResolveUserRoles(sessionInfo.Username, ps.Roles)
	}

	metrics.Global.ConnectionsTotal.Add(1)
	p.auditLogger.Log(audit.Event{
		EventType: audit.AuthSuccess.String(), SessionID: sess.ID,
		Username: sess.Username, Roles: sess.Roles,
		ClientIP: remoteAddr.IP.String(), Database: sess.Database,
		Action: "allow",
	})
	slog.Info("session opened", "session_id", sess.ID[:8], "user", sess.Username, "database", sess.Database, "client_ip", remoteAddr.IP)

	p.commandLoop(ctx, sess, handler, clientConn, backendConn)

	p.sessionManager.Remove(sess.ID)
	p.auditLogger.Log(audit.Event{
		EventType: audit.ConnectionClose.String(), SessionID: sess.ID,
		Username: sess.Username, ClientIP: remoteAddr.IP.String(),
		Database: sess.Database, Action: "close",
	})
	cmdCount, _, _ := sess.Stats()
	slog.Info("session closed", "session_id", sess.ID[:8], "commands", cmdCount)
}

// dialTimeout returns the connection timeout from config or a default.

// buildMSSQLPreLogin builds a minimal PreLogin packet for MSSQL proxy auth.
func buildMSSQLPreLogin() []byte {
	return []byte{0x12, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00}
}
