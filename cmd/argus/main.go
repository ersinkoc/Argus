package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ersinkoc/argus/internal/admin"
	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/core"
	"github.com/ersinkoc/argus/internal/gateway"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/resolve"
	"github.com/ersinkoc/argus/internal/session"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "argus.json", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	validateOnly := flag.Bool("validate", false, "Validate configuration and exit")
	resolveURL := flag.String("resolve-url", "", "Monopam resolve API endpoint (e.g. http://monopam:8080/api/db/resolve)")
	resolveAPIKey := flag.String("resolve-api-key", "", "API key for the resolve endpoint")
	flag.Parse()

	if *showVersion {
		fmt.Printf("argus %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(handler))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if err := run(context.Background(), *configPath, *validateOnly, *resolveURL, *resolveAPIKey, sigCh, os.Stdout); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// run executes the main application logic. sigCh can be nil (defaults to OS signals).
func run(ctx context.Context, configPath string, validateOnly bool, resolveURL, resolveAPIKey string, sigCh <-chan os.Signal, output io.Writer) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	config.ResolvePolicyPaths(cfg, configPath)

	if validateOnly {
		fmt.Fprintln(output, "Configuration is valid.")
		return nil
	}

	slog.Info("starting", "version", version, "build_time", buildTime)
	fmt.Fprint(output, core.StartupBanner(cfg, version))

	auditLevel := audit.ParseLogLevel(cfg.Audit.Level)
	auditLogger := audit.NewLogger(cfg.Audit.BufferSize, auditLevel, cfg.Audit.SQLMaxLength)
	auditLogger.SetOverflowPolicy(audit.ParseOverflowPolicy(cfg.Audit.OverflowPolicy))

	if err := setupAuditOutputs(auditLogger, cfg); err != nil {
		return err
	}
	webhookWriter := setupWebhook(cfg, auditLogger)
	auditLogger.Start()

	policyLoader := policy.NewLoader(cfg.Policy.Files, cfg.Policy.ReloadInterval)
	if len(cfg.Policy.Files) > 0 {
		if err := policyLoader.Load(); err != nil {
			slog.Warn("failed to load policies", "error", err)
		} else {
			ps := policyLoader.Current()
			slog.Info("policies loaded", "files", len(cfg.Policy.Files), "roles", len(ps.Roles), "rules", len(ps.Policies))
		}
	}

	policyEngine := policy.NewEngine(policyLoader)

	policyLoader.OnReload(makeOnReloadFn(policyEngine, auditLogger))
	policyLoader.Start()

	admin.Version = version
	proxy := core.NewProxy(cfg, policyEngine, auditLogger)

	queryRecorder := setupQueryRecorder(cfg, proxy)

	if cfg.Session.MaxPerUser > 0 {
		proxy.SetSessionLimiter(session.NewConcurrencyLimiter(cfg.Session.MaxPerUser))
		slog.Info("session limit set", "max_per_user", cfg.Session.MaxPerUser)
	}

	setupRewriter(cfg, proxy)
	setupSlowQueryLogger(cfg, proxy, auditLogger)

	// Identity resolution and proxy auth (optional).
	// When a resolve URL is configured, Argus calls Monopam's /api/db/resolve
	// to resolve the real database target and credential for the session.
	// In proxy auth mode, this replaces the standard passthrough handshake
	// with a full SASL/SCRAM authentication exchange on both sides.
	if resolveURL != "" {
		resolveClient := resolve.NewClient(resolveURL, resolveAPIKey)
		resolveAdapter := &monopamResolver{client: resolveClient}

		// Set the identity resolver for proxy auth mode (PG).
		// This enables reading the startup, resolving the target, and
		// performing SASL/SCRAM auth with both the client and backend.
		proxy.SetIdentityResolver(resolveAdapter)

		// Also register a PostAuth hook for logging and non-PG protocols.
		resolveHook := core.NewIdentityResolverHook(resolveAdapter)
		proxy.SetPipelineHooks(resolveHook)

		slog.Info("proxy auth mode enabled", "endpoint", resolveURL)
	}

	if err := proxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	adminServers := setupAdmin(cfg, proxy, policyLoader, policyEngine, auditLogger)

	reloadFn := makeReloadFn(policyLoader, policyEngine)

	slog.Info("argus is ready")
	slog.Info("know who connects, control what they do, protect what they see")

	waitForSignals(sigCh, reloadFn)
	gracefulShutdown(ctx, proxy, adminServers, policyLoader, webhookWriter, queryRecorder, auditLogger)

	return nil
}

func setupAuditOutputs(auditLogger *audit.Logger, cfg *config.Config) error {
	for _, out := range cfg.Audit.Outputs {
		switch out.Type {
		case "stdout":
			auditLogger.AddWriter(os.Stdout)
		case "file":
			if out.Rotation != nil && out.Rotation.MaxSizeMB > 0 {
				rw, err := audit.NewRotatingWriter(out.Path, out.Rotation.MaxSizeMB, out.Rotation.MaxFiles)
				if err != nil {
					return fmt.Errorf("failed to create rotating audit writer: %w", err)
				}
				auditLogger.AddWriter(rw)
			} else {
				if err := auditLogger.AddFileWriter(out.Path); err != nil {
					return fmt.Errorf("failed to open audit file: %w", err)
				}
			}
		}
	}
	return nil
}

func setupQueryRecorder(cfg *config.Config, proxy *core.Proxy) *audit.QueryRecorder {
	if cfg.Audit.RecordFile == "" {
		return nil
	}
	qr, err := audit.NewQueryRecorder(cfg.Audit.RecordFile)
	if err != nil {
		slog.Warn("query recorder failed", "error", err)
		return nil
	}
	proxy.SetQueryRecorder(qr)
	slog.Info("query recording enabled", "path", cfg.Audit.RecordFile)
	return qr
}

func setupWebhook(cfg *config.Config, auditLogger *audit.Logger) *audit.WebhookWriter {
	if cfg.Audit.WebhookURL == "" {
		return nil
	}
	ww := audit.NewWebhookWriter(audit.WebhookConfig{
		URL:       cfg.Audit.WebhookURL,
		BatchSize: 100,
	})
	auditLogger.AddWriter(ww)
	ww.Start()
	slog.Info("siem webhook enabled", "url", cfg.Audit.WebhookURL)
	return ww
}

func setupRewriter(cfg *config.Config, proxy *core.Proxy) {
	if cfg.Rewrite.MaxLimit <= 0 && cfg.Rewrite.ForceWhere == "" {
		return
	}
	rw := inspection.NewRewriter()
	if cfg.Rewrite.MaxLimit > 0 {
		rw.SetMaxLimit(cfg.Rewrite.MaxLimit)
		slog.Info("query rewrite: auto-LIMIT", "max_limit", cfg.Rewrite.MaxLimit)
	}
	if cfg.Rewrite.ForceWhere != "" {
		rw.SetForceWhere(cfg.Rewrite.ForceWhere)
		slog.Info("query rewrite: force WHERE", "condition", cfg.Rewrite.ForceWhere)
	}
	proxy.SetRewriter(rw)
}

func setupSlowQueryLogger(cfg *config.Config, proxy *core.Proxy, auditLogger *audit.Logger) {
	if cfg.SlowQuery.Threshold == "" {
		return
	}
	threshold, err := time.ParseDuration(cfg.SlowQuery.Threshold)
	if err != nil {
		slog.Warn("invalid slow_query threshold", "error", err)
		return
	}
	proxy.SetSlowQueryLogger(audit.NewSlowQueryLogger(threshold, auditLogger))
	slog.Info("slow query threshold configured", "threshold", threshold)
}

func makeOnReloadFn(policyEngine *policy.Engine, auditLogger *audit.Logger) func() {
	return func() {
		policyEngine.InvalidateCache()
		auditLogger.Log(audit.Event{
			EventType: audit.PolicyReloaded.String(),
			Action:    "reload",
		})
	}
}

func makeReloadFn(policyLoader *policy.Loader, policyEngine *policy.Engine) func() {
	return func() {
		slog.Info("reloading policies...")
		if err := policyLoader.Load(); err != nil {
			slog.Error("policy reload failed", "error", err)
			return
		}
		policyEngine.InvalidateCache()
		slog.Info("policies reloaded successfully")
	}
}

func makePolicyReloadFn(policyLoader *policy.Loader, policyEngine *policy.Engine) func() error {
	return func() error {
		if err := policyLoader.Load(); err != nil {
			return err
		}
		policyEngine.InvalidateCache()
		return nil
	}
}

func setupAdmin(cfg *config.Config, proxy *core.Proxy, policyLoader *policy.Loader, policyEngine *policy.Engine, auditLogger *audit.Logger) []*admin.Server {
	if !cfg.Admin.Enabled && !cfg.Metrics.Enabled {
		return nil
	}

	newServer := func(addr string, enableAdminRoutes, enableMetricRoutes bool) *admin.Server {
		if enableAdminRoutes && len(cfg.Admin.AuthToken) < 32 {
			slog.Error("admin enabled without secure auth token")
			return nil
		}
		srv := admin.NewServer(proxy, addr)
		srv.SetRouteModes(enableAdminRoutes, enableMetricRoutes)
		srv.OnPolicyReload(makePolicyReloadFn(policyLoader, policyEngine))

		if enableAdminRoutes {
			if cfg.Admin.AuthToken != "" {
				srv.SetAuthToken(cfg.Admin.AuthToken, cfg.Admin.AllowedSources...)
			}
			srv.SetAllowedOrigins(cfg.Admin.AllowedOrigins...)
			if len(cfg.Admin.TrustedProxies) > 0 {
				srv.SetTrustedProxies(cfg.Admin.TrustedProxies)
			}
			srv.SetApprovalProvider(proxy.ApprovalManager())
			proxy.SetOnEvent(makeEventBroadcast(srv))
			srv.SetDryRunFunc(makeDryRunFunc(policyEngine))
			srv.SetConfigExporter(makeConfigExporter(cfg))
			srv.SetPolicyValidator(makePolicyValidator(policyLoader))
			srv.SetPolicyListFn(makePolicyListFn(policyLoader))
			srv.SetClassifyFunc(makeClassifyFunc())
			srv.SetPluginListFunc(makePluginListFunc())
			srv.SetOnSessionKill(makeSessionKillFn(auditLogger))
			for _, out := range cfg.Audit.Outputs {
				if out.Type == "file" && out.Path != "" {
					srv.SetAuditLogPath(out.Path)
					break
				}
			}
			if cfg.Audit.RecordFile != "" {
				srv.SetRecordFile(cfg.Audit.RecordFile)
			}
			if cfg.Gateway.Enabled {
				setupGateway(cfg, srv, policyEngine, auditLogger, proxy)
			}
			setupTestRunner(cfg)
		}

		srv.Start()
		return srv
	}

	if cfg.Admin.Enabled && cfg.Metrics.Enabled && cfg.Admin.Address != cfg.Metrics.Address {
		adminSrv := newServer(cfg.Admin.Address, true, false)
		metricsSrv := newServer(cfg.Metrics.Address, false, true)
		return []*admin.Server{adminSrv, metricsSrv}
	}

	addr := cfg.Admin.Address
	if !cfg.Admin.Enabled {
		addr = cfg.Metrics.Address
	}
	return []*admin.Server{newServer(addr, cfg.Admin.Enabled, cfg.Metrics.Enabled)}
}

func setupGateway(cfg *config.Config, srv *admin.Server, policyEngine *policy.Engine, auditLogger *audit.Logger, proxy *core.Proxy) {
	var piiDetector *masking.PIIDetector
	if cfg.Audit.PIIAutoDetect {
		piiDetector = masking.NewPIIDetector()
	}
	gw := gateway.New(gateway.GatewayDeps{
		Cfg:             cfg,
		PolicyEngine:    policyEngine,
		AuditLogger:     auditLogger,
		ApprovalManager: proxy.ApprovalManager(),
		Pools:           proxy.Pools(),
		AnomalyDetector: proxy.AnomalyDetector(),
		PIIDetector:     piiDetector,
	})
	if cfg.Gateway.WebhookURL != "" {
		gw.SetWebhookNotifier(gateway.NewWebhookNotifier(
			cfg.Gateway.WebhookURL,
			cfg.Gateway.WebhookHeaders,
		))
	}
	srv.SetGateway(gw, gw.APIKeyStore().Middleware)
	slog.Info("sql gateway enabled", "api_keys", gw.APIKeyStore().Count())
}

func setupTestRunner(cfg *config.Config) {
	if len(cfg.Targets) == 0 {
		return
	}
	trc := &admin.TestRunnerConfig{}
	for _, t := range cfg.Targets {
		switch t.Protocol {
		case "postgresql":
			for _, l := range cfg.Server.Listeners {
				if l.Protocol == "postgresql" {
					trc.PGHost = "host.docker.internal"
					trc.PGPort = extractPort(l.Address)
					trc.PGPassword = "argus_pass"
				}
			}
		case "mysql":
			for _, l := range cfg.Server.Listeners {
				if l.Protocol == "mysql" {
					trc.MySQLHost = "host.docker.internal"
					trc.MySQLPort = extractPort(l.Address)
					trc.MySQLUser = "argus_test"
					trc.MySQLPassword = "argus_pass"
				}
			}
		}
	}
	admin.SetTestRunnerConfig(trc)
}

func waitForSignals(sigCh <-chan os.Signal, reloadFn func()) {
	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			reloadFn()
			continue
		}
		slog.Info("received shutdown signal", "signal", sig)
		break
	}
}

func gracefulShutdown(ctx context.Context, proxy *core.Proxy, adminServers []*admin.Server, policyLoader *policy.Loader, webhookWriter *audit.WebhookWriter, queryRecorder *audit.QueryRecorder, auditLogger *audit.Logger) {
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		proxy.Stop()
		for _, adminServer := range adminServers {
			if adminServer != nil {
				adminServer.Stop()
			}
		}
		policyLoader.Stop()
		if webhookWriter != nil {
			webhookWriter.Stop()
		}
		if queryRecorder != nil {
			queryRecorder.Close()
		}
		auditLogger.Close()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("graceful shutdown complete")
	case <-shutdownCtx.Done():
		slog.Warn("shutdown timed out, forcing exit")
	}
}

func extractPort(addr string) int {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			p := 0
			for _, c := range addr[i+1:] {
				p = p*10 + int(c-'0')
			}
			return p
		}
	}
	return 0
}

func countErrors(issues []policy.ValidationIssue) int {
	n := 0
	for _, i := range issues {
		if i.Level == "error" {
			n++
		}
	}
	return n
}

// ── Resolve API adapter ─────────────────────────────────────────────

// monopamResolver adapts resolve.Client to the core.IdentityResolver interface.
// It converts between the resolve package types and the core package types.
type monopamResolver struct {
	client *resolve.Client
}

func (a *monopamResolver) Resolve(ctx context.Context, identity *core.ResolveIdentity) (*core.ResolvedIdentity, error) {
	req := &resolve.ResolveRequest{
		Username: identity.Username,
		Database: identity.Database,
		ClientIP: identity.ClientIP,
		Protocol: identity.Protocol,
	}

	target, err := a.client.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}

	return &core.ResolvedIdentity{
		Host:       target.Host,
		Port:       target.Port,
		Username:   target.Username,
		Password:   target.Password,
		AuthMethod: target.AuthMethod,
		Roles:      target.Roles,
	}, nil
}
