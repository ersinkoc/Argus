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

func (p *Proxy) PostAuthClientAndServer(
	clientConn net.Conn,
	remoteAddr *net.TCPAddr,
	protocolName string,
) (*session.Info, net.Conn, error) {
	if p.identityResolver == nil {
		return nil, nil, fmt.Errorf("no identity resolver configured")
	}

	startupData, err := pg.ReadStartupMessage(clientConn)
	if err != nil {
		return nil, nil, fmt.Errorf("reading client startup: %w", err)
	}
	startup, err := pg.ParseStartupMessage(startupData)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing startup: %w", err)
	}

	username := startup.Parameters["user"]
	database := startup.Parameters["database"]
	if database == "" {
		database = username
	}

	slog.Info("proxy auth: client connecting",
		"user", username, "database", database, "client_ip", remoteAddr.IP)

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
		"target", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port),
		"db_user", resolved.Username)

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
		return nil, nil, fmt.Errorf("connecting to %s:%d: %w", resolved.Host, resolved.Port, err)
	}

	resolvedParams := make(map[string]string)
	for k, v := range startup.Parameters {
		resolvedParams[k] = v
	}
	resolvedParams["user"] = resolved.Username
	resolvedStartup := pg.BuildStartupMessage(resolvedParams)

	if err := pg.WriteRawBytes(backendConn, resolvedStartup); err != nil {
		backendConn.Close()
		return nil, nil, fmt.Errorf("forwarding startup: %w", err)
	}

	if err := pg.ProxyAuthClient(ctx, backendConn, resolved.Password); err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		backendConn.Close()
		return nil, nil, fmt.Errorf("backend proxy auth failed: %w", err)
	}
	slog.Debug("proxy auth: backend authenticated")

	if err := pg.ProxyAuthServer(ctx, clientConn, resolved.Password); err != nil {
		backendConn.Close()
		return nil, nil, fmt.Errorf("client proxy auth failed: %w", err)
	}
	slog.Debug("proxy auth: client authenticated")

	if err := pg.RelayPostAuthFromBackend(backendConn, clientConn); err != nil {
		backendConn.Close()
		return nil, nil, fmt.Errorf("relaying post-auth: %w", err)
	}

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
		"target", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	return info, backendConn, nil
}

func (p *Proxy) handleProxyAuthMySQL(clientConn net.Conn, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	ctx := context.Background()

	handshake, _, err := mysql.ProxyAuthServer(clientConn, "")
	if err != nil {
		slog.Error("mysql proxy auth: client handshake failed", "error", err)
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(), ClientIP: remoteAddr.IP.String(),
			Action: "block", Error: err.Error(),
		})
		return
	}

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

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	backendConn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		slog.Error("mysql proxy auth: connect failed", "error", err)
		return
	}

	if err := mysql.ProxyAuthClient(backendConn, resolved.Username, handshake.Database, resolved.Password); err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		backendConn.Close()
		slog.Error("mysql proxy auth: backend auth failed", "error", err)
		return
	}

	sessionInfo := &session.Info{
		Username:   handshake.Username,
		Database:   handshake.Database,
		ClientIP:   remoteAddr.IP,
		AuthMethod: "proxy_mysql_native",
	}
	p.setupProxyAuthSession(ctx, clientConn, backendConn, sessionInfo, remoteAddr, handler)
}

func (p *Proxy) handleProxyAuthMSSQL(clientConn net.Conn, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	ctx := context.Background()

	username, _, err := mssql.ProxyAuthServer(clientConn)
	if err != nil {
		slog.Error("mssql proxy auth: client handshake failed", "error", err)
		p.auditLogger.Log(audit.Event{
			EventType: audit.AuthFailure.String(), ClientIP: remoteAddr.IP.String(),
			Action: "block", Error: err.Error(),
		})
		return
	}

	preLoginData := buildMSSQLPreLogin()

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

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	var d net.Dialer
	backendConn, err := d.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		slog.Error("mssql proxy auth: connect failed", "error", err)
		return
	}

	loginResp, err := mssql.ProxyAuthClient(backendConn, preLoginData, resolved.Username, resolved.Password)
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		backendConn.Close()
		slog.Error("mssql proxy auth: backend auth failed", "error", err)
		return
	}

	mssql.ForwardLoginResponse(clientConn, loginResp)

	sessionInfo := &session.Info{
		Username:   username,
		ClientIP:   remoteAddr.IP,
		AuthMethod: "proxy_tds7",
	}
	p.setupProxyAuthSession(ctx, clientConn, backendConn, sessionInfo, remoteAddr, handler)
}

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

func buildMSSQLPreLogin() []byte {
	return []byte{0x12, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00}
}
