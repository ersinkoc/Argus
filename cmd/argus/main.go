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
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/core"
	"github.com/ersinkoc/argus/internal/policy"
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
	log.Printf("Configuration loaded: %s", cfg)

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
	if cfg.Audit.WebhookURL != "" {
		wh := audit.NewWebhookWriter(audit.WebhookConfig{
			URL:       cfg.Audit.WebhookURL,
			BatchSize: 100,
		})
		auditLogger.AddWriter(wh)
		wh.Start()
		log.Printf("SIEM webhook enabled: %s", cfg.Audit.WebhookURL)
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
