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
		return nil, nil, fmt.Errorf("no identity resolver")
	}
	sd, err := pg.ReadStartupMessage(clientConn)
	if err != nil {
		return nil, nil, fmt.Errorf("reading startup: %w", err)
	}
	su, err := pg.ParseStartupMessage(sd)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing startup: %w", err)
	}
	if su.IsSSLRequest {
		if _, err := clientConn.Write([]byte{'N'}); err != nil {
			return nil, nil, fmt.Errorf("SSL reject: %w", err)
		}
		sd, err = pg.ReadStartupMessage(clientConn)
		if err != nil {
			return nil, nil, fmt.Errorf("reading post-SSL startup: %w", err)
		}
		su, err = pg.ParseStartupMessage(sd)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing post-SSL startup: %w", err)
		}
	}
	username := su.Parameters["user"]
	database := su.Parameters["database"]
	if database == "" {
		database = username
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := p.identityResolver.Resolve(ctx, &ResolveIdentity{
		Username: username, Database: database,
		ClientIP: remoteAddr.IP.String(), Protocol: protocolName,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: %w", err)
	}
	if resolved == nil {
		return nil, nil, fmt.Errorf("resolve nil")
	}
	dt := 10 * time.Second
	if p.cfg.Pool.ConnectionTimeout > 0 {
		dt = p.cfg.Pool.ConnectionTimeout
	}
	dc, dl := context.WithTimeout(context.Background(), dt)
	defer dl()
	var d net.Dialer
	bc, err := d.DialContext(dc, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	rp := make(map[string]string)
	for k, v := range su.Parameters {
		rp[k] = v
	}
	rp["user"] = resolved.Username
	rs := pg.BuildStartupMessage(rp)
	if err := pg.WriteRawBytes(bc, rs); err != nil {
		bc.Close()
		return nil, nil, fmt.Errorf("startup: %w", err)
	}
	if err := pg.ProxyAuthClient(ctx, bc, resolved.Password); err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		bc.Close()
		return nil, nil, fmt.Errorf("backend auth: %w", err)
	}
	if err := pg.ProxyAuthServer(ctx, clientConn, resolved.Password); err != nil {
		bc.Close()
		return nil, nil, fmt.Errorf("client auth: %w", err)
	}
	if err := pg.RelayPostAuthFromBackend(bc, clientConn); err != nil {
		bc.Close()
		return nil, nil, fmt.Errorf("relay: %w", err)
	}
	info := &session.Info{
		Username: username, Database: database,
		ClientIP: remoteAddr.IP, Parameters: su.Parameters,
		AuthMethod: "proxy_scram_sha_256",
	}
	if info.Database == "" {
		info.Database = info.Username
	}
	return info, bc, nil
}

func (p *Proxy) handleProxyAuthMySQL(clientConn net.Conn, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	hs, err := mysql.ProxyAuthServer(clientConn, "")
	if err != nil {
		authFailLog(p, "mysql", remoteAddr, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resolved, err := p.identityResolver.Resolve(ctx, &ResolveIdentity{
		Username: hs.Username, Database: hs.Database,
		ClientIP: remoteAddr.IP.String(), Protocol: "mysql",
	})
	cancel()
	if err != nil {
		authFailLog(p, "mysql", remoteAddr, err)
		return
	}
	dc, dl := context.WithTimeout(context.Background(), 10*time.Second)
	defer dl()
	var d net.Dialer
	bc, err := d.DialContext(dc, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		return
	}
	if err := mysql.ProxyAuthClient(bc, resolved.Username, hs.Database, resolved.Password); err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		bc.Close()
		return
	}
	setupAuthSession(p, context.Background(), clientConn, bc,
		&session.Info{Username: hs.Username, Database: hs.Database, ClientIP: remoteAddr.IP, AuthMethod: "proxy_mysql_native"},
		remoteAddr, handler)
}

func (p *Proxy) handleProxyAuthMSSQL(clientConn net.Conn, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	username, err := mssql.ProxyAuthServer(clientConn)
	if err != nil {
		authFailLog(p, "mssql", remoteAddr, err)
		return
	}
	pld := []byte{0x12, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resolved, err := p.identityResolver.Resolve(ctx, &ResolveIdentity{
		Username: username, Database: "",
		ClientIP: remoteAddr.IP.String(), Protocol: "mssql",
	})
	cancel()
	if err != nil {
		authFailLog(p, "mssql", remoteAddr, err)
		return
	}
	dc, dl := context.WithTimeout(context.Background(), 10*time.Second)
	defer dl()
	var d net.Dialer
	bc, err := d.DialContext(dc, "tcp", fmt.Sprintf("%s:%d", resolved.Host, resolved.Port))
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		return
	}
	lr, err := mssql.ProxyAuthClient(bc, pld, resolved.Username, resolved.Password)
	if err != nil {
		metrics.Global.ConnectionsFailed.Add(1)
		bc.Close()
		return
	}
	mssql.ForwardLoginResponse(clientConn, lr)
	setupAuthSession(p, context.Background(), clientConn, bc,
		&session.Info{Username: username, ClientIP: remoteAddr.IP, AuthMethod: "proxy_tds7"},
		remoteAddr, handler)
}

func authFailLog(p *Proxy, proto string, addr *net.TCPAddr, err error) {
	slog.Error(proto+" proxy auth failed", "error", err)
	p.auditLogger.Log(audit.Event{
		EventType: audit.AuthFailure.String(), ClientIP: addr.IP.String(),
		Action: "block", Error: err.Error(),
	})
}

func setupAuthSession(p *Proxy, ctx context.Context, clientConn, backendConn net.Conn, si *session.Info, remoteAddr *net.TCPAddr, handler protocol.Handler) {
	if p.sessionLimiter != nil {
		if !p.sessionLimiter.Acquire(si.Username) {
			handler.WriteError(ctx, clientConn, "53300", "Too many connections")
			return
		}
		defer p.sessionLimiter.Release(si.Username)
	}
	sess := p.sessionManager.Create(si, clientConn)
	sess.BackendConn = backendConn
	if ps := p.policyEngine.Loader().Current(); ps != nil {
		sess.Roles = policy.ResolveUserRoles(si.Username, ps.Roles)
	}
	metrics.Global.ConnectionsTotal.Add(1)
	p.auditLogger.Log(audit.Event{
		EventType: audit.AuthSuccess.String(), SessionID: sess.ID,
		Username: sess.Username, Roles: sess.Roles,
		ClientIP: remoteAddr.IP.String(), Database: sess.Database, Action: "allow",
	})
	p.commandLoop(ctx, sess, handler, clientConn, backendConn)
	p.sessionManager.Remove(sess.ID)
	p.auditLogger.Log(audit.Event{
		EventType: audit.ConnectionClose.String(), SessionID: sess.ID,
		Username: sess.Username, ClientIP: remoteAddr.IP.String(),
		Database: sess.Database, Action: "close",
	})
}
