package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
	"github.com/ersinkoc/argus/internal/inspection"
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

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	config.ResolvePolicyPaths(cfg, *configPath)

	if *validateOnly {
		fmt.Println("Configuration is valid.")
		os.Exit(0)
	}

	log.Printf("Argus — The Hundred-Eyed Database Guardian")
	log.Printf("Version: %s (built %s)", version, buildTime)
	// Startup banner
	fmt.Print(core.StartupBanner(cfg, version))

	// Initialize audit logger
	auditLevel := audit.ParseLogLevel(cfg.Audit.Level)
	auditLogger := audit.NewLogger(cfg.Audit.BufferSize, auditLevel, cfg.Audit.SQLMaxLength)

	for _, output := range cfg.Audit.Outputs {
		switch output.Type {
		case "stdout":
			auditLogger.AddWriter(os.Stdout)
		case "file":
			if output.Rotation != nil && output.Rotation.MaxSizeMB > 0 {
				rw, err := audit.NewRotatingWriter(output.Path, output.Rotation.MaxSizeMB, output.Rotation.MaxFiles)
				if err != nil {
					log.Fatalf("Failed to create rotating audit writer: %v", err)
				}
				auditLogger.AddWriter(rw)
			} else {
				if err := auditLogger.AddFileWriter(output.Path); err != nil {
					log.Fatalf("Failed to open audit file: %v", err)
				}
			}
		}
	}
	auditLogger.Start()

	// Initialize policy engine
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

	// Set up policy hot-reload
	policyLoader.OnReload(func() {
		policyEngine.InvalidateCache()
		auditLogger.Log(audit.Event{
			EventType: audit.PolicyReloaded.String(),
			Action:    "reload",
		})
	})
	policyLoader.Start()

	// Create and start proxy
	admin.Version = version
	proxy := core.NewProxy(cfg, policyEngine, auditLogger)

	// Query recording
	if cfg.Audit.RecordFile != "" {
		recorder, err := audit.NewQueryRecorder(cfg.Audit.RecordFile)
		if err != nil {
			log.Printf("Warning: query recorder failed: %v", err)
		} else {
			proxy.SetQueryRecorder(recorder)
			log.Printf("Query recording enabled: %s", cfg.Audit.RecordFile)
		}
	}

	// SIEM webhook
	var webhookWriter *audit.WebhookWriter
	if cfg.Audit.WebhookURL != "" {
		webhookWriter = audit.NewWebhookWriter(audit.WebhookConfig{
			URL:       cfg.Audit.WebhookURL,
			BatchSize: 100,
		})
		auditLogger.AddWriter(webhookWriter)
		webhookWriter.Start()
		log.Printf("SIEM webhook enabled: %s", cfg.Audit.WebhookURL)
	}

	// Session concurrency limiter
	if cfg.Session.MaxPerUser > 0 {
		proxy.SetSessionLimiter(session.NewConcurrencyLimiter(cfg.Session.MaxPerUser))
		log.Printf("Session limit: %d per user", cfg.Session.MaxPerUser)
	}

	// Query rewriter
	if cfg.Rewrite.MaxLimit > 0 || cfg.Rewrite.ForceWhere != "" {
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

	// Slow query logger
	if cfg.SlowQuery.Threshold != "" {
		threshold, err := time.ParseDuration(cfg.SlowQuery.Threshold)
		if err != nil {
			log.Printf("Warning: invalid slow_query threshold: %v", err)
		} else {
			proxy.SetSlowQueryLogger(audit.NewSlowQueryLogger(threshold, auditLogger))
			log.Printf("Slow query threshold: %s", threshold)
		}
	}

	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	// Start admin/metrics server
	var adminServer *admin.Server
	if cfg.Metrics.Enabled {
		adminServer = admin.NewServer(proxy, cfg.Metrics.Address)
		adminServer.OnPolicyReload(func() error {
			if err := policyLoader.Load(); err != nil {
				return err
			}
			policyEngine.InvalidateCache()
			return nil
		})

		// Admin API authentication
		if cfg.Admin.AuthToken != "" {
			adminServer.SetAuthToken(cfg.Admin.AuthToken)
		}

		// Wire approval workflow to admin API
		adminServer.SetApprovalProvider(proxy.ApprovalManager())

		// Wire WebSocket live monitoring
		proxy.SetOnEvent(func(event any) {
			adminServer.EventStream.Broadcast(event)
		})

		// Wire dry-run
		adminServer.SetDryRunFunc(func(username, database, sql, clientIP string) (any, error) {
			result := policyEngine.DryRun(policy.DryRunInput{
				Username: username,
				Database: database,
				SQL:      sql,
				ClientIP: clientIP,
			})
			return result, nil
		})

		// Wire config export
		adminServer.SetConfigExporter(func() ([]byte, error) {
			return json.MarshalIndent(cfg, "", "  ")
		})

		// Set audit/recording paths for search and replay
		for _, out := range cfg.Audit.Outputs {
			if out.Type == "file" && out.Path != "" {
				adminServer.SetAuditLogPath(out.Path)
				break
			}
		}
		if cfg.Audit.RecordFile != "" {
			adminServer.SetRecordFile(cfg.Audit.RecordFile)
		}

		// Wire policy validator
		adminServer.SetPolicyValidator(func() (any, error) {
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
		})

		// Wire data classification
		classifyEngine := classify.NewEngine()
		adminServer.SetClassifyFunc(func(columns []string) any {
			return classifyEngine.ClassifyColumns(columns)
		})

		// Wire plugin registry
		pluginRegistry := plugin.NewRegistry()
		adminServer.SetPluginListFunc(func() any {
			return map[string]any{
				"plugins": pluginRegistry.List(),
				"count":   pluginRegistry.Count(),
			}
		})

		adminServer.SetOnSessionKill(func(sessionID string) {
			auditLogger.Log(audit.Event{
				EventType: audit.SessionKilled.String(),
				SessionID: sessionID,
				Action:    "killed",
				Reason:    "admin_api",
			})
		})

		// Wire test runner with proxy addresses
		if len(cfg.Targets) > 0 {
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

		if err := adminServer.Start(); err != nil {
			log.Printf("Warning: admin server failed to start: %v", err)
		}
	}

	reloadFn := func() {
		log.Println("Reloading policies...")
		if err := policyLoader.Load(); err != nil {
			log.Printf("Policy reload failed: %v", err)
			return
		}
		policyEngine.InvalidateCache()
		log.Println("Policies reloaded successfully")
	}

	log.Println("Argus is ready.")
	log.Println("\"Know who connects. Control what they do. Protect what they see.\"")

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			// SIGHUP = reload config and policies
			reloadFn()
			continue
		}
		log.Printf("Received signal %v, initiating graceful shutdown...", sig)
		break
	}

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		// Stop accepting new connections
		proxy.Stop()

		// Stop admin server
		if adminServer != nil {
			adminServer.Stop()
		}

		// Stop policy watcher
		policyLoader.Stop()

		// Flush pending webhook events before closing audit logger
		if webhookWriter != nil {
			webhookWriter.Stop()
		}

		// Flush audit logs
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
	// addr is like ":30100" or "0.0.0.0:30100"
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
