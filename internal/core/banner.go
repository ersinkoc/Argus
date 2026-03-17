package core

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/ersinkoc/argus/internal/config"
)

// StartupBanner generates a summary of enabled features at boot.
func StartupBanner(cfg *config.Config, version string) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString("    _____                        \n")
	b.WriteString("   /  _  \\_______  ____  __ __  ______\n")
	b.WriteString("  /  /_\\  \\_  __ \\/ ___\\|  |  \\/  ___/\n")
	b.WriteString(" /    |    \\  | \\/ /_/  >  |  /\\___ \\ \n")
	b.WriteString(" \\____|__  /__|  \\___  /|____//____  >\n")
	b.WriteString("         \\/    /_____/             \\/ \n")
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf(" The Hundred-Eyed Database Guardian  v%s\n", version))
	b.WriteString(fmt.Sprintf(" Go %s | %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH))
	b.WriteString("\n")

	// Listeners
	for _, l := range cfg.Server.Listeners {
		tls := ""
		if l.TLS.Enabled {
			tls = " [TLS]"
		}
		b.WriteString(fmt.Sprintf(" Listen   %s (%s)%s\n", l.Address, l.Protocol, tls))
	}

	// Targets
	for _, t := range cfg.Targets {
		tls := ""
		if t.TLS.Enabled {
			tls = " [TLS]"
		}
		b.WriteString(fmt.Sprintf(" Target   %s → %s:%d%s\n", t.Name, t.Host, t.Port, tls))
	}

	// Features
	b.WriteString("\n")
	features := []string{}

	if len(cfg.Policy.Files) > 0 {
		features = append(features, fmt.Sprintf("policies(%d files)", len(cfg.Policy.Files)))
	}
	if cfg.Audit.PIIAutoDetect {
		features = append(features, "pii-auto-detect")
	}
	if cfg.Audit.RecordFile != "" {
		features = append(features, "query-recording")
	}
	if cfg.Audit.WebhookURL != "" {
		features = append(features, "siem-webhook")
	}
	if cfg.Metrics.Enabled {
		features = append(features, fmt.Sprintf("metrics(%s)", cfg.Metrics.Address))
	}
	if cfg.Admin.AuthToken != "" {
		features = append(features, "admin-auth")
	}

	b.WriteString(fmt.Sprintf(" Features %s\n", strings.Join(features, ", ")))
	b.WriteString(fmt.Sprintf(" Audit    %s (buffer=%d)\n", cfg.Audit.Level, cfg.Audit.BufferSize))
	b.WriteString(fmt.Sprintf(" Pool     max=%d idle=%d\n", cfg.Pool.MaxConnectionsPerTarget, cfg.Pool.MinIdleConnections))
	b.WriteString(fmt.Sprintf(" Session  idle=%s max=%s\n", cfg.Session.IdleTimeout, cfg.Session.MaxDuration))
	b.WriteString("\n")

	return b.String()
}
