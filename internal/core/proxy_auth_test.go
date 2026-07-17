package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/protocol/mssql"
	"github.com/ersinkoc/argus/internal/protocol/mysql"
	"github.com/ersinkoc/argus/internal/protocol/pg"
	"github.com/ersinkoc/argus/internal/session"
)

// ==================== helpers ====================

func proxyAuthTestAddr() *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
}

// pipeWithDeadline returns a net.Pipe pair with deadlines so no test hangs.
func pipeWithDeadline(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	dl := time.Now().Add(5 * time.Second)
	c1.SetDeadline(dl)
	c2.SetDeadline(dl)
	t.Cleanup(func() { c1.Close(); c2.Close() })
	return c1, c2
}

// closedPort returns a 127.0.0.1 port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// startTCPBackend starts a one-shot TCP backend that runs fn on the accepted
// connection and reports fn's result on the returned channel.
func startTCPBackend(t *testing.T, fn func(conn net.Conn) error) (int, chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		done <- fn(conn)
	}()
	return l.Addr().(*net.TCPAddr).Port, done
}

func waitErrChan(t *testing.T, ch chan error, what string) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: timed out", what)
	}
}

func sslRequestBytes() []byte {
	return []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
}

// fakePGBackendScript reads the startup, performs the SCRAM server side with
// the given password, then sends ReadyForQuery.
func fakePGBackendScript(password string) func(conn net.Conn) error {
	return func(conn net.Conn) error {
		if _, err := pg.ReadStartupMessage(conn); err != nil {
			return fmt.Errorf("backend startup: %w", err)
		}
		if err := pg.ProxyAuthServer(context.Background(), conn, password); err != nil {
			return fmt.Errorf("backend auth: %w", err)
		}
		return pg.WriteMessage(conn, &pg.Message{Type: pg.MsgReadyForQuery, Payload: []byte{'I'}})
	}
}

// runFakePGProxyClient acts as a psql-like client against the proxy: sends the
// startup, authenticates with the client secret, then reads relayed messages
// until ReadyForQuery.
func runFakePGProxyClient(conn net.Conn, params map[string]string, secret string) error {
	if err := pg.WriteRawBytes(conn, pg.BuildStartupMessage(params)); err != nil {
		return err
	}
	if err := pg.ProxyAuthClient(context.Background(), conn, secret); err != nil {
		return err
	}
	for {
		msg, err := pg.ReadMessage(conn)
		if err != nil {
			return err
		}
		if msg.Type == pg.MsgReadyForQuery {
			return nil
		}
	}
}

// ==================== PostAuthClientAndServer ====================

func TestPostAuthClientAndServerNoResolver(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	client, _ := pipeWithDeadline(t)
	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "no identity resolver") {
		t.Fatalf("err = %v, want no identity resolver", err)
	}
}

func TestPostAuthClientAndServerStartupReadError(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{})

	client, far := pipeWithDeadline(t)
	far.Close()
	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "reading startup") {
		t.Fatalf("err = %v, want reading startup", err)
	}
}

func TestPostAuthClientAndServerStartupErrors(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{"invalid length", []byte{0x00, 0x00, 0x00, 0x02}, "reading startup"},
		{"too short to parse", []byte{0x00, 0x00, 0x00, 0x04}, "parsing startup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, logger, _ := newTestProxy("postgres")
			defer logger.Close()
			proxy.SetIdentityResolver(&fakeResolver{})

			client, far := pipeWithDeadline(t)
			cerr := make(chan error, 1)
			go func() {
				_, err := far.Write(tt.raw)
				cerr <- err
			}()
			_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %s", err, tt.wantErr)
			}
			waitErrChan(t, cerr, "client write")
		})
	}
}

func TestPostAuthClientAndServerSSLRejectWriteError(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{})

	client, far := pipeWithDeadline(t)
	go func() {
		// net.Pipe writes are synchronous: once this returns, the proxy has
		// consumed the SSLRequest. Closing now fails the proxy's 'N' reply.
		if _, err := far.Write(sslRequestBytes()); err == nil {
			far.Close()
		}
	}()
	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "SSL reject") {
		t.Fatalf("err = %v, want SSL reject", err)
	}
}

func TestPostAuthClientAndServerPostSSLStartupErrors(t *testing.T) {
	tests := []struct {
		name    string
		second  []byte // written after the SSL 'N' reply; nil closes instead
		wantErr string
	}{
		{"read error", nil, "reading post-SSL startup"},
		{"parse error", []byte{0x00, 0x00, 0x00, 0x04}, "parsing post-SSL startup"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, logger, _ := newTestProxy("postgres")
			defer logger.Close()
			proxy.SetIdentityResolver(&fakeResolver{})

			client, far := pipeWithDeadline(t)
			cerr := make(chan error, 1)
			go func() {
				if _, err := far.Write(sslRequestBytes()); err != nil {
					cerr <- err
					return
				}
				reply := make([]byte, 1)
				if _, err := far.Read(reply); err != nil {
					cerr <- err
					return
				}
				if reply[0] != 'N' {
					cerr <- fmt.Errorf("SSL reply = %q, want N", reply[0])
					return
				}
				if tt.second == nil {
					far.Close()
					cerr <- nil
					return
				}
				_, err := far.Write(tt.second)
				cerr <- err
			}()
			_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %s", err, tt.wantErr)
			}
			waitErrChan(t, cerr, "client")
		})
	}
}

func TestPostAuthClientAndServerResolverError(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	resolver := &fakeResolver{err: errors.New("unknown user")}
	proxy.SetIdentityResolver(resolver)

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		// SSLRequest first to also cover the SSL-reject-then-startup path.
		if _, err := far.Write(sslRequestBytes()); err != nil {
			cerr <- err
			return
		}
		reply := make([]byte, 1)
		if _, err := far.Read(reply); err != nil {
			cerr <- err
			return
		}
		_, err := far.Write(pg.BuildStartupMessage(map[string]string{"user": "alice"}))
		cerr <- err
	}()

	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "resolve:") {
		t.Fatalf("err = %v, want resolve error", err)
	}
	waitErrChan(t, cerr, "client")

	if resolver.got == nil {
		t.Fatal("resolver was not called")
	}
	if resolver.got.Username != "alice" {
		t.Fatalf("resolved username = %q, want alice", resolver.got.Username)
	}
	if resolver.got.Database != "alice" {
		t.Fatalf("resolved database = %q, want alice (defaulted to username)", resolver.got.Database)
	}
	if resolver.got.Protocol != "postgres" {
		t.Fatalf("resolved protocol = %q, want postgres", resolver.got.Protocol)
	}
	if resolver.got.ClientIP != "127.0.0.1" {
		t.Fatalf("resolved client IP = %q, want 127.0.0.1", resolver.got.ClientIP)
	}
}

func TestPostAuthClientAndServerResolveNil(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		_, err := far.Write(pg.BuildStartupMessage(map[string]string{"user": "alice", "database": "db1"}))
		cerr <- err
	}()
	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "resolve nil") {
		t.Fatalf("err = %v, want resolve nil", err)
	}
	waitErrChan(t, cerr, "client")
}

func TestPostAuthClientAndServerDialError(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: closedPort(t), Username: "svc", Password: "pw",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		_, err := far.Write(pg.BuildStartupMessage(map[string]string{"user": "alice"}))
		cerr <- err
	}()
	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "dial:") {
		t.Fatalf("err = %v, want dial error", err)
	}
	waitErrChan(t, cerr, "client")
}

func TestPostAuthClientAndServerBackendAuthError(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	// Backend reads the rewritten startup, then hangs up before auth.
	port, backendDone := startTCPBackend(t, func(conn net.Conn) error {
		_, err := pg.ReadStartupMessage(conn)
		return err
	})
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc", Password: "pw",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		_, err := far.Write(pg.BuildStartupMessage(map[string]string{"user": "alice"}))
		cerr <- err
	}()
	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "backend auth") {
		t.Fatalf("err = %v, want backend auth error", err)
	}
	waitErrChan(t, cerr, "client")
	waitErrChan(t, backendDone, "backend")
}

func TestPostAuthClientAndServerClientAuthError(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	port, backendDone := startTCPBackend(t, fakePGBackendScript("backend-pw"))
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc",
		Password: "backend-pw", ClientSecret: "right-secret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		// Authenticate to the proxy with the wrong client secret.
		cerr <- runFakePGProxyClient(far, map[string]string{"user": "alice"}, "wrong-secret")
	}()
	_, _, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err == nil || !strings.Contains(err.Error(), "client auth") {
		t.Fatalf("err = %v, want client auth error", err)
	}
	select {
	case err := <-cerr:
		if err == nil {
			t.Fatal("client auth with wrong secret unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client goroutine timed out")
	}
	select {
	case <-backendDone:
	case <-time.After(5 * time.Second):
		t.Fatal("backend goroutine timed out")
	}
}

func TestPostAuthClientAndServerHappyPath(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	port, backendDone := startTCPBackend(t, fakePGBackendScript("backend-pw"))
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc",
		Password: "backend-pw", ClientSecret: "client-secret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- runFakePGProxyClient(far, map[string]string{"user": "alice"}, "client-secret")
	}()

	info, backendConn, err := proxy.PostAuthClientAndServer(client, proxyAuthTestAddr(), "postgres")
	if err != nil {
		t.Fatalf("PostAuthClientAndServer: %v", err)
	}
	defer backendConn.Close()
	waitErrChan(t, cerr, "client")
	waitErrChan(t, backendDone, "backend")

	if info.Username != "alice" {
		t.Fatalf("info.Username = %q, want alice", info.Username)
	}
	if info.Database != "alice" {
		t.Fatalf("info.Database = %q, want alice (defaulted)", info.Database)
	}
	if info.AuthMethod != "proxy_scram_sha_256" {
		t.Fatalf("info.AuthMethod = %q, want proxy_scram_sha_256", info.AuthMethod)
	}
}

// ==================== handleProxyAuthPG ====================

func TestHandleProxyAuthPGAuthFailure(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	// No identity resolver set: PostAuthClientAndServer fails immediately and
	// the failure is audited.
	client, _ := pipeWithDeadline(t)
	proxy.handleProxyAuthPG(client, proxyAuthTestAddr(), &mockHandler{name: "postgres"})
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestHandleProxyAuthPGHappyPath(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	port, backendDone := startTCPBackend(t, fakePGBackendScript("backend-pw"))
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc",
		Password: "backend-pw", ClientSecret: "client-secret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- runFakePGProxyClient(far, map[string]string{"user": "alice", "database": "db1"}, "client-secret")
	}()

	handler := &mockHandler{
		name: "postgres",
		readCommandFunc: func(_ context.Context, _ net.Conn) (*inspection.Command, []byte, error) {
			return nil, nil, nil // terminate the command loop immediately
		},
	}
	proxy.handleProxyAuthPG(client, proxyAuthTestAddr(), handler)

	waitErrChan(t, cerr, "client")
	waitErrChan(t, backendDone, "backend")
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count after close = %d, want 0", got)
	}
}

func TestHandleProxyAuthPGSessionLimit(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	port, backendDone := startTCPBackend(t, fakePGBackendScript("backend-pw"))
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc",
		Password: "backend-pw", ClientSecret: "client-secret",
	}})

	limiter := session.NewConcurrencyLimiter(1)
	if !limiter.Acquire("alice") {
		t.Fatal("pre-acquire failed")
	}
	proxy.SetSessionLimiter(limiter)

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- runFakePGProxyClient(far, map[string]string{"user": "alice"}, "client-secret")
	}()

	wroteErr := false
	handler := &mockHandler{
		name: "postgres",
		writeErrorFunc: func(_ context.Context, _ net.Conn, code, _ string) error {
			wroteErr = true
			if code != "53300" {
				t.Errorf("error code = %q, want 53300", code)
			}
			return nil
		},
	}
	proxy.handleProxyAuthPG(client, proxyAuthTestAddr(), handler)

	waitErrChan(t, cerr, "client")
	waitErrChan(t, backendDone, "backend")
	if !wroteErr {
		t.Fatal("expected WriteError for concurrent session limit")
	}
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

// ==================== handleProxyAuthMySQL ====================

// buildFakeMySQLGreetingPayload builds a minimal MySQL v10 greeting carrying
// the given 20-byte scramble, parseable by the mysql package's client side.
func buildFakeMySQLGreetingPayload(scramble []byte) []byte {
	var p []byte
	p = append(p, 10)
	p = append(p, []byte("8.0.0-fake\x00")...)
	p = append(p, 1, 0, 0, 0)          // thread id
	p = append(p, scramble[:8]...)     // auth data part 1
	p = append(p, 0)                   // filler
	p = append(p, 0xff, 0xf7)          // capabilities low
	p = append(p, 45)                  // charset
	p = append(p, 0x02, 0x00)          // status
	p = append(p, 0x00, 0x00)          // capabilities high
	p = append(p, 21)                  // auth data length
	p = append(p, make([]byte, 10)...) // reserved
	p = append(p, scramble[8:20]...)   // auth data part 2
	p = append(p, 0)
	p = append(p, []byte("mysql_native_password\x00")...)
	return p
}

func fakeMySQLBackendScript() func(conn net.Conn) error {
	return func(conn net.Conn) error {
		scramble := make([]byte, 20)
		for i := range scramble {
			scramble[i] = byte(i + 1)
		}
		if err := mysql.WritePacket(conn, &mysql.Packet{SequenceID: 0, Payload: buildFakeMySQLGreetingPayload(scramble)}); err != nil {
			return fmt.Errorf("backend greeting: %w", err)
		}
		if _, err := mysql.ReadPacket(conn); err != nil {
			return fmt.Errorf("backend handshake response: %w", err)
		}
		return mysql.WritePacket(conn, mysql.BuildOKPacket(2, 0, 0))
	}
}

func TestHandleProxyAuthMySQLClientHandshakeError(t *testing.T) {
	proxy, logger, _ := newTestProxy("mysql")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{})

	client, far := pipeWithDeadline(t)
	far.Close()
	proxy.handleProxyAuthMySQL(client, proxyAuthTestAddr(), &mockHandler{name: "mysql"})
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestHandleProxyAuthMySQLResolverError(t *testing.T) {
	proxy, logger, _ := newTestProxy("mysql")
	defer logger.Close()
	resolver := &fakeResolver{err: errors.New("unknown user")}
	proxy.SetIdentityResolver(resolver)

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- mysql.ProxyAuthClient(far, "bob", "shop", "pw")
	}()
	proxy.handleProxyAuthMySQL(client, proxyAuthTestAddr(), &mockHandler{name: "mysql"})

	// The proxy bails out without answering; unblock the fake client.
	client.Close()
	select {
	case <-cerr:
	case <-time.After(5 * time.Second):
		t.Fatal("mysql client goroutine timed out")
	}

	if resolver.got == nil {
		t.Fatal("resolver was not called")
	}
	if resolver.got.Username != "bob" || resolver.got.Database != "shop" {
		t.Fatalf("resolver identity = %q/%q, want bob/shop", resolver.got.Username, resolver.got.Database)
	}
	if resolver.got.Protocol != "mysql" {
		t.Fatalf("resolver protocol = %q, want mysql", resolver.got.Protocol)
	}
}

func TestHandleProxyAuthMySQLBadSecret(t *testing.T) {
	proxy, logger, _ := newTestProxy("mysql")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: 3306, Username: "svc",
		Password: "pw", ClientSecret: "right-secret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- mysql.ProxyAuthClient(far, "bob", "shop", "wrong-secret")
	}()
	proxy.handleProxyAuthMySQL(client, proxyAuthTestAddr(), &mockHandler{name: "mysql"})

	select {
	case err := <-cerr:
		if err == nil {
			t.Fatal("client with wrong secret unexpectedly authenticated")
		}
		if !strings.Contains(err.Error(), "1045") {
			t.Fatalf("client err = %v, want access denied (1045)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mysql client goroutine timed out")
	}
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestHandleProxyAuthMySQLDialError(t *testing.T) {
	proxy, logger, _ := newTestProxy("mysql")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: closedPort(t), Username: "svc",
		Password: "pw", ClientSecret: "s3cret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- mysql.ProxyAuthClient(far, "bob", "shop", "s3cret")
	}()
	proxy.handleProxyAuthMySQL(client, proxyAuthTestAddr(), &mockHandler{name: "mysql"})

	client.Close()
	select {
	case <-cerr:
	case <-time.After(5 * time.Second):
		t.Fatal("mysql client goroutine timed out")
	}
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestHandleProxyAuthMySQLBackendAuthError(t *testing.T) {
	proxy, logger, _ := newTestProxy("mysql")
	defer logger.Close()

	// Backend hangs up without a greeting: mysql.ProxyAuthClient fails.
	port, backendDone := startTCPBackend(t, func(conn net.Conn) error {
		return nil
	})
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc",
		Password: "pw", ClientSecret: "s3cret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- mysql.ProxyAuthClient(far, "bob", "shop", "s3cret")
	}()
	proxy.handleProxyAuthMySQL(client, proxyAuthTestAddr(), &mockHandler{name: "mysql"})

	client.Close()
	select {
	case <-cerr:
	case <-time.After(5 * time.Second):
		t.Fatal("mysql client goroutine timed out")
	}
	waitErrChan(t, backendDone, "backend")
}

func TestHandleProxyAuthMySQLHappyPath(t *testing.T) {
	proxy, logger, _ := newTestProxy("mysql")
	defer logger.Close()

	port, backendDone := startTCPBackend(t, fakeMySQLBackendScript())
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc",
		Password: "backend-pw", ClientSecret: "s3cret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- mysql.ProxyAuthClient(far, "bob", "shop", "s3cret")
	}()

	handler := &mockHandler{
		name: "mysql",
		readCommandFunc: func(_ context.Context, _ net.Conn) (*inspection.Command, []byte, error) {
			return nil, nil, nil
		},
	}
	proxy.handleProxyAuthMySQL(client, proxyAuthTestAddr(), handler)

	waitErrChan(t, cerr, "mysql client")
	waitErrChan(t, backendDone, "mysql backend")
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count after close = %d, want 0", got)
	}
}

// ==================== handleProxyAuthMSSQL ====================

// runFakeMSSQLProxyClient drives the client side of the MSSQL proxy handshake:
// pre-login, pre-login response, Login7 (carrying the client secret).
func runFakeMSSQLProxyClient(conn net.Conn, username, secret string, readLoginResponse bool) error {
	preLogin := &mssql.Packet{Type: mssql.PacketPreLogin, Status: mssql.StatusEOM, Data: mssql.BuildPreLoginResponse().Data}
	if err := mssql.WritePacket(conn, preLogin); err != nil {
		return err
	}
	resp, err := mssql.ReadPacket(conn)
	if err != nil {
		return err
	}
	if resp.Type != mssql.PacketReply {
		return fmt.Errorf("pre-login reply type = 0x%02x, want 0x%02x", resp.Type, mssql.PacketReply)
	}
	if err := mssql.WritePacket(conn, mssql.BuildProxyLogin7(username, secret, nil)); err != nil {
		return err
	}
	if readLoginResponse {
		if _, err := mssql.ReadPacket(conn); err != nil {
			return err
		}
	}
	return nil
}

func fakeMSSQLBackendScript() func(conn net.Conn) error {
	return func(conn net.Conn) error {
		if _, ptype, err := mssql.ReadAllPackets(conn); err != nil {
			return fmt.Errorf("backend pre-login: %w", err)
		} else if ptype != mssql.PacketPreLogin {
			return fmt.Errorf("backend pre-login type = 0x%02x", ptype)
		}
		if err := mssql.WritePacket(conn, mssql.BuildPreLoginResponse()); err != nil {
			return fmt.Errorf("backend pre-login response: %w", err)
		}
		if _, ptype, err := mssql.ReadAllPackets(conn); err != nil {
			return fmt.Errorf("backend login7: %w", err)
		} else if ptype != mssql.PacketTDS7Login {
			return fmt.Errorf("backend login7 type = 0x%02x", ptype)
		}
		// Minimal login acknowledgement payload; content is opaque to the proxy.
		return mssql.WritePacket(conn, &mssql.Packet{Type: mssql.PacketReply, Status: mssql.StatusEOM, Data: []byte{0xFD, 0x00, 0x00, 0x00}})
	}
}

func TestHandleProxyAuthMSSQLClientHandshakeError(t *testing.T) {
	proxy, logger, _ := newTestProxy("mssql")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{})

	client, far := pipeWithDeadline(t)
	far.Close()
	proxy.handleProxyAuthMSSQL(client, proxyAuthTestAddr(), &mockHandler{name: "mssql"}, nil, false)
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestHandleProxyAuthMSSQLResolverError(t *testing.T) {
	proxy, logger, _ := newTestProxy("mssql")
	defer logger.Close()
	resolver := &fakeResolver{err: errors.New("unknown user")}
	proxy.SetIdentityResolver(resolver)

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- runFakeMSSQLProxyClient(far, "sa-user", "sekret", false)
	}()
	proxy.handleProxyAuthMSSQL(client, proxyAuthTestAddr(), &mockHandler{name: "mssql"}, nil, false)

	waitErrChan(t, cerr, "mssql client")
	if resolver.got == nil {
		t.Fatal("resolver was not called")
	}
	if resolver.got.Username != "sa-user" {
		t.Fatalf("resolver username = %q, want sa-user", resolver.got.Username)
	}
	if resolver.got.Protocol != "mssql" {
		t.Fatalf("resolver protocol = %q, want mssql", resolver.got.Protocol)
	}
}

func TestHandleProxyAuthMSSQLBadSecret(t *testing.T) {
	proxy, logger, _ := newTestProxy("mssql")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: 1433, Username: "svc",
		Password: "pw", ClientSecret: "right-secret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- runFakeMSSQLProxyClient(far, "sa-user", "wrong-secret", false)
	}()
	proxy.handleProxyAuthMSSQL(client, proxyAuthTestAddr(), &mockHandler{name: "mssql"}, nil, false)

	waitErrChan(t, cerr, "mssql client")
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestHandleProxyAuthMSSQLDialError(t *testing.T) {
	proxy, logger, _ := newTestProxy("mssql")
	defer logger.Close()
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: closedPort(t), Username: "svc",
		Password: "pw", ClientSecret: "sekret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- runFakeMSSQLProxyClient(far, "sa-user", "sekret", false)
	}()
	proxy.handleProxyAuthMSSQL(client, proxyAuthTestAddr(), &mockHandler{name: "mssql"}, nil, false)

	waitErrChan(t, cerr, "mssql client")
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestHandleProxyAuthMSSQLHappyPath(t *testing.T) {
	proxy, logger, _ := newTestProxy("mssql")
	defer logger.Close()

	port, backendDone := startTCPBackend(t, fakeMSSQLBackendScript())
	proxy.SetIdentityResolver(&fakeResolver{resolved: &ResolvedIdentity{
		Host: "127.0.0.1", Port: port, Username: "svc",
		Password: "backend-pw", ClientSecret: "sekret",
	}})

	client, far := pipeWithDeadline(t)
	cerr := make(chan error, 1)
	go func() {
		cerr <- runFakeMSSQLProxyClient(far, "sa-user", "sekret", true)
	}()

	handler := &mockHandler{
		name: "mssql",
		readCommandFunc: func(_ context.Context, _ net.Conn) (*inspection.Command, []byte, error) {
			return nil, nil, nil
		},
	}
	proxy.handleProxyAuthMSSQL(client, proxyAuthTestAddr(), handler, nil, false)

	waitErrChan(t, cerr, "mssql client")
	waitErrChan(t, backendDone, "mssql backend")
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count after close = %d, want 0", got)
	}
}

// ==================== setupAuthSession / authFailLog ====================

func TestAuthFailLog(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	// Must not panic and must enqueue an audit event.
	authFailLog(proxy, "postgres", proxyAuthTestAddr(), errors.New("bad credentials"))
}

func TestSetupAuthSessionLimiterExhausted(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()

	limiter := session.NewConcurrencyLimiter(1)
	if !limiter.Acquire("bob") {
		t.Fatal("pre-acquire failed")
	}
	proxy.SetSessionLimiter(limiter)

	wroteErr := false
	handler := &mockHandler{
		name: "postgres",
		writeErrorFunc: func(_ context.Context, _ net.Conn, code, _ string) error {
			wroteErr = true
			if code != "53300" {
				t.Errorf("error code = %q, want 53300", code)
			}
			return nil
		},
	}
	client, backend := pipeWithDeadline(t)
	info := &session.Info{Username: "bob", Database: "db1", ClientIP: net.ParseIP("127.0.0.1")}
	setupAuthSession(proxy, context.Background(), client, backend, info, proxyAuthTestAddr(), handler)

	if !wroteErr {
		t.Fatal("expected WriteError for exhausted limiter")
	}
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count = %d, want 0", got)
	}
}

func TestSetupAuthSessionHappyPath(t *testing.T) {
	proxy, logger, _ := newTestProxy("postgres")
	defer logger.Close()
	proxy.SetSessionLimiter(session.NewConcurrencyLimiter(4))

	sawSession := false
	handler := &mockHandler{
		name: "postgres",
		readCommandFunc: func(_ context.Context, _ net.Conn) (*inspection.Command, []byte, error) {
			if proxy.sessionManager.Count() == 1 {
				sawSession = true
			}
			return nil, nil, nil
		},
	}
	client, backend := pipeWithDeadline(t)
	info := &session.Info{Username: "bob", Database: "db1", ClientIP: net.ParseIP("127.0.0.1")}
	setupAuthSession(proxy, context.Background(), client, backend, info, proxyAuthTestAddr(), handler)

	if !sawSession {
		t.Fatal("session was not registered during the command loop")
	}
	if got := proxy.sessionManager.Count(); got != 0 {
		t.Fatalf("session count after close = %d, want 0", got)
	}
}
