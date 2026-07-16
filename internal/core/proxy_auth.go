package core

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ersinkoc/argus/internal/metrics"
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
