package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ersinkoc/argus/internal/admin"
	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/classify"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/core"
	"github.com/ersinkoc/argus/internal/gateway"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/plugin"
	"github.com/ersinkoc/argus/internal/policy"
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
	flag.Parse()

	if *showVersion {
		fmt.Printf("argus %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	log.SetPrefix("[argus] ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	if err := run(context.Background(), *configPath, *validateOnly, sigCh, os.Stdout); err != nil {
		log.Fatalf("%v", err)
	}
}

// run executes the main application logic. sigCh can be nil (defaults to OS signals).
func run(ctx context.Context, configPath string, validateOnly bool, sigCh <-chan os.Signal, output io.Writer) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	config.ResolvePolicyPaths(cfg, configPath)

	if validateOnly {
		fmt.Fprintln(output, "Configuration is valid.")
		return nil
	}

	log.Printf("Argus — The Hundred-Eyed Database Guardian")
	log.Printf("Version: %s (built %s)", version, buildTime)
	fmt.Fprint(output, core.StartupBanner(cfg, version))

	auditLevel := audit.ParseLogLevel(cfg.Audit.Level)
	auditLogger := audit.NewLogger(cfg.Audit.BufferSize, auditLevel, cfg.Audit.SQLMaxLength)

	if err := setupAuditOutputs(auditLogger, cfg); err != nil {
		return err
	}
	auditLogger.Start()

	policyLoader := policy.NewLoader(cfg.Policy.Files, cfg.Policy.ReloadInterval)
	if len(cfg.Policy.Files) > 0 {
		if err := policyLoader.Load(); err != nil {
			log.Printf("Warning: failed to load policies: %v", err)
		} else {
			ps := policyLoader.Current()
			log.Printf("Policies loaded: %d file(s), %d role(s), %d rule(s)",
				len(cfg.Policy.Files), len(ps.Roles), len(ps.Policies))
		}
	}

	policyEngine := policy.NewEngine(policyLoader)

	policyLoader.OnReload(makeOnReloadFn(policyEngine, auditLogger))
	policyLoader.Start()

	admin.Version = version
	proxy := core.NewProxy(cfg, policyEngine, auditLogger)

	queryRecorder := setupQueryRecorder(cfg, proxy)
	webhookWriter := setupWebhook(cfg, auditLogger)

	if cfg.Session.MaxPerUser > 0 {
		proxy.SetSessionLimiter(session.NewConcurrencyLimiter(cfg.Session.MaxPerUser))
		log.Printf("Session limit: %d per user", cfg.Session.MaxPerUser)
	}

	setupRewriter(cfg, proxy)
	setupSlowQueryLogger(cfg, proxy, auditLogger)

	if err := proxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	adminServer := setupAdmin(cfg, proxy, policyLoader, policyEngine, auditLogger)

	reloadFn := makeReloadFn(policyLoader, policyEngine)

	log.Println("Argus is ready.")
	log.Println("\"Know who connects. Control what they do. Protect what they see.\"")

	waitForSignals(sigCh, reloadFn)
	gracefulShutdown(ctx, proxy, adminServer, policyLoader, webhookWriter, queryRecorder, auditLogger)

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
		log.Printf("Warning: query recorder failed: %v", err)
		return nil
	}
	proxy.SetQueryRecorder(qr)
	log.Printf("Query recording enabled: %s", cfg.Audit.RecordFile)
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
	log.Printf("SIEM webhook enabled: %s", cfg.Audit.WebhookURL)
	return ww
}

func setupRewriter(cfg *config.Config, proxy *core.Proxy) {
	if cfg.Rewrite.MaxLimit <= 0 && cfg.Rewrite.ForceWhere == "" {
		return
	}
	rw := inspection.NewRewriter()
	if cfg.Rewrite.MaxLimit > 0 {
		rw.SetMaxLimit(cfg.Rewrite.MaxLimit)
		log.Printf("Query rewrite: auto-LIMIT %d", cfg.Rewrite.MaxLimit)
	}
	if cfg.Rewrite.ForceWhere != "" {
		rw.SetForceWhere(cfg.Rewrite.ForceWhere)
		log.Printf("Query rewrite: force WHERE %s", cfg.Rewrite.ForceWhere)
	}
	proxy.SetRewriter(rw)
}

func setupSlowQueryLogger(cfg *config.Config, proxy *core.Proxy, auditLogger *audit.Logger) {
	if cfg.SlowQuery.Threshold == "" {
		return
	}
	threshold, err := time.ParseDuration(cfg.SlowQuery.Threshold)
	if err != nil {
		log.Printf("Warning: invalid slow_query threshold: %v", err)
		return
	}
	proxy.SetSlowQueryLogger(audit.NewSlowQueryLogger(threshold, auditLogger))
	log.Printf("Slow query threshold: %s", threshold)
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
		log.Println("Reloading policies...")
		if err := policyLoader.Load(); err != nil {
			log.Printf("Policy reload failed: %v", err)
			return
		}
		policyEngine.InvalidateCache()
		log.Println("Policies reloaded successfully")
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

func makeConfigExporter(cfg *config.Config) func() ([]byte, error) {
	return func() ([]byte, error) {
		safe := *cfg
		safe.Admin.AuthToken = "***REDACTED***"
		for i := range safe.Targets {
			if safe.Targets[i].TLS.KeyFile != "" {
				safe.Targets[i].TLS.KeyFile = "***REDACTED***"
			}
		}
		for i := range safe.Server.Listeners {
			if safe.Server.Listeners[i].TLS.KeyFile != "" {
				safe.Server.Listeners[i].TLS.KeyFile = "***REDACTED***"
			}
		}
		return json.MarshalIndent(&safe, "", "  ")
	}
}

func makePolicyValidator(policyLoader *policy.Loader) func() (any, error) {
	return func() (any, error) {
		ps := policyLoader.Current()
		if ps == nil {
			return nil, fmt.Errorf("no policies loaded")
		}
		issues := policy.ValidatePolicySet(ps)
		return map[string]any{
			"issues": issues,
			"count":  len(issues),
			"valid":  countErrors(issues) == 0,
		}, nil
	}
}

func makeClassifyFunc() func(columns []string) any {
	engine := classify.NewEngine()
	return func(columns []string) any {
		return engine.ClassifyColumns(columns)
	}
}

func makePluginListFunc() func() any {
	registry := plugin.NewRegistry()
	return func() any {
		return map[string]any{
			"plugins": registry.List(),
			"count":   registry.Count(),
		}
	}
}

func makeSessionKillFn(auditLogger *audit.Logger) func(string) {
	return func(sessionID string) {
		auditLogger.Log(audit.Event{
			EventType: audit.SessionKilled.String(),
			SessionID: sessionID,
			Action:    "killed",
			Reason:    "admin_api",
		})
	}
}

func makeDryRunFunc(policyEngine *policy.Engine) func(string, string, string, string) (any, error) {
	return func(username, database, sql, clientIP string) (any, error) {
		result := policyEngine.DryRun(policy.DryRunInput{
			Username: username,
			Database: database,
			SQL:      sql,
			ClientIP: clientIP,
		})
		return result, nil
	}
}

func makeEventBroadcast(srv *admin.Server) func(any) {
	return func(event any) {
		srv.EventStream.Broadcast(event)
	}
}

func setupAdmin(cfg *config.Config, proxy *core.Proxy, policyLoader *policy.Loader, policyEngine *policy.Engine, auditLogger *audit.Logger) *admin.Server {
	if !cfg.Metrics.Enabled {
		return nil
	}

	srv := admin.NewServer(proxy, cfg.Metrics.Address)
	srv.OnPolicyReload(makePolicyReloadFn(policyLoader, policyEngine))

	if cfg.Admin.AuthToken != "" {
		srv.SetAuthToken(cfg.Admin.AuthToken)
	}

	srv.SetApprovalProvider(proxy.ApprovalManager())
	proxy.SetOnEvent(makeEventBroadcast(srv))
	srv.SetDryRunFunc(makeDryRunFunc(policyEngine))
	srv.SetConfigExporter(makeConfigExporter(cfg))

	for _, out := range cfg.Audit.Outputs {
		if out.Type == "file" && out.Path != "" {
			srv.SetAuditLogPath(out.Path)
			break
		}
	}
	if cfg.Audit.RecordFile != "" {
		srv.SetRecordFile(cfg.Audit.RecordFile)
	}

	srv.SetPolicyValidator(makePolicyValidator(policyLoader))
	srv.SetClassifyFunc(makeClassifyFunc())
	srv.SetPluginListFunc(makePluginListFunc())
	srv.SetOnSessionKill(makeSessionKillFn(auditLogger))

	if cfg.Gateway.Enabled {
		setupGateway(cfg, srv, policyEngine, auditLogger, proxy)
	}

	setupTestRunner(cfg)

	srv.Start()

	return srv
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
	log.Printf("SQL Gateway enabled with %d API key(s)", gw.APIKeyStore().Count())
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
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		break
	}
}

func gracefulShutdown(ctx context.Context, proxy *core.Proxy, adminServer *admin.Server, policyLoader *policy.Loader, webhookWriter *audit.WebhookWriter, queryRecorder *audit.QueryRecorder, auditLogger *audit.Logger) {
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		proxy.Stop()
		if adminServer != nil {
			adminServer.Stop()
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
		log.Println("Graceful shutdown complete.")
	case <-shutdownCtx.Done():
		log.Println("Shutdown timed out, forcing exit.")
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
