package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// applyEnvOverrides applies ARGUS_ prefixed environment variables.
func applyEnvOverrides(cfg *Config) {
	envMap := map[string]func(string){
		"ARGUS_AUDIT_LEVEL": func(v string) { cfg.Audit.Level = v },
		"ARGUS_AUDIT_BUFFER_SIZE": func(v string) {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Audit.BufferSize = n
			}
		},
		"ARGUS_METRICS_ENABLED": func(v string) {
			cfg.Metrics.Enabled = v == "true" || v == "1"
		},
		"ARGUS_METRICS_ADDRESS": func(v string) { cfg.Metrics.Address = v },
		"ARGUS_ADMIN_ENABLED": func(v string) {
			cfg.Admin.Enabled = v == "true" || v == "1"
		},
		"ARGUS_ADMIN_ADDRESS":    func(v string) { cfg.Admin.Address = v },
		"ARGUS_ADMIN_AUTH_TOKEN": func(v string) { cfg.Admin.AuthToken = v },
		"ARGUS_POOL_MAX_CONNECTIONS_PER_TARGET": func(v string) {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Pool.MaxConnectionsPerTarget = n
			}
		},
		"ARGUS_SESSION_IDLE_TIMEOUT": func(v string) {
			if d, err := time.ParseDuration(v); err == nil {
				cfg.Session.IdleTimeout = d
			}
		},
		"ARGUS_SESSION_MAX_DURATION": func(v string) {
			if d, err := time.ParseDuration(v); err == nil {
				cfg.Session.MaxDuration = d
			}
		},
		"ARGUS_ROUTING_DEFAULT_TARGET": func(v string) { cfg.Routing.DefaultTarget = v },
	}

	for key, setter := range envMap {
		if v := os.Getenv(key); v != "" {
			setter(v)
		}
	}

	// Dynamic target overrides: ARGUS_TARGETS_0_HOST, ARGUS_TARGETS_0_PORT, etc.
	for i := range cfg.Targets {
		prefix := fmt.Sprintf("ARGUS_TARGETS_%d_", i)
		if v := os.Getenv(prefix + "HOST"); v != "" {
			cfg.Targets[i].Host = v
		}
		if v := os.Getenv(prefix + "PORT"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Targets[i].Port = n
			}
		}
	}

	// Dynamic listener overrides
	for i := range cfg.Server.Listeners {
		prefix := fmt.Sprintf("ARGUS_SERVER_LISTENERS_%d_", i)
		if v := os.Getenv(prefix + "ADDRESS"); v != "" {
			cfg.Server.Listeners[i].Address = v
		}
	}
}

// expandEnvInConfig expands $ENV{VAR} patterns in all string config fields.
func expandEnvInConfig(cfg *Config) {
	for i := range cfg.Server.Listeners {
		cfg.Server.Listeners[i].Address = ExpandEnvValue(cfg.Server.Listeners[i].Address)
		cfg.Server.Listeners[i].TLS.CertFile = ExpandEnvValue(cfg.Server.Listeners[i].TLS.CertFile)
		cfg.Server.Listeners[i].TLS.KeyFile = ExpandEnvValue(cfg.Server.Listeners[i].TLS.KeyFile)
		cfg.Server.Listeners[i].TLS.CAFile = ExpandEnvValue(cfg.Server.Listeners[i].TLS.CAFile)
		cfg.Server.Listeners[i].TLS.ClientCAFile = ExpandEnvValue(cfg.Server.Listeners[i].TLS.ClientCAFile)
	}
	for i := range cfg.Targets {
		cfg.Targets[i].Host = ExpandEnvValue(cfg.Targets[i].Host)
		cfg.Targets[i].TLS.CertFile = ExpandEnvValue(cfg.Targets[i].TLS.CertFile)
		cfg.Targets[i].TLS.KeyFile = ExpandEnvValue(cfg.Targets[i].TLS.KeyFile)
		cfg.Targets[i].TLS.CAFile = ExpandEnvValue(cfg.Targets[i].TLS.CAFile)
		cfg.Targets[i].TLS.ClientCAFile = ExpandEnvValue(cfg.Targets[i].TLS.ClientCAFile)
	}
	cfg.Routing.DefaultTarget = ExpandEnvValue(cfg.Routing.DefaultTarget)
	for i := range cfg.Routing.Rules {
		cfg.Routing.Rules[i].Database = ExpandEnvValue(cfg.Routing.Rules[i].Database)
		cfg.Routing.Rules[i].Target = ExpandEnvValue(cfg.Routing.Rules[i].Target)
	}
	for i := range cfg.Policy.Files {
		cfg.Policy.Files[i] = ExpandEnvValue(cfg.Policy.Files[i])
	}
	cfg.Audit.Level = ExpandEnvValue(cfg.Audit.Level)
	cfg.Audit.RecordFile = ExpandEnvValue(cfg.Audit.RecordFile)
	cfg.Audit.WebhookURL = ExpandEnvValue(cfg.Audit.WebhookURL)
	for i := range cfg.Audit.Outputs {
		cfg.Audit.Outputs[i].Path = ExpandEnvValue(cfg.Audit.Outputs[i].Path)
	}
	cfg.Admin.Address = ExpandEnvValue(cfg.Admin.Address)
	cfg.Admin.AuthToken = ExpandEnvValue(cfg.Admin.AuthToken)
	cfg.Metrics.Address = ExpandEnvValue(cfg.Metrics.Address)
	cfg.Rewrite.ForceWhere = ExpandEnvValue(cfg.Rewrite.ForceWhere)
	cfg.SlowQuery.Threshold = ExpandEnvValue(cfg.SlowQuery.Threshold)
	cfg.PlanAnalysis.Timeout = ExpandEnvValue(cfg.PlanAnalysis.Timeout)
	cfg.Gateway.WebhookURL = ExpandEnvValue(cfg.Gateway.WebhookURL)
	for i := range cfg.Gateway.APIKeys {
		cfg.Gateway.APIKeys[i].Key = ExpandEnvValue(cfg.Gateway.APIKeys[i].Key)
		for j := range cfg.Gateway.APIKeys[i].PreviousKeys {
			cfg.Gateway.APIKeys[i].PreviousKeys[j] = ExpandEnvValue(cfg.Gateway.APIKeys[i].PreviousKeys[j])
		}
	}
}

// ExpandEnvValue replaces $ENV{VAR} and $FILE{PATH} patterns with their values.
//
//   $ENV{VAR}  — replaced by the value of environment variable VAR.
//                If VAR is unset, the pattern is replaced with an empty string
//                and a warning is logged.
//
//   $FILE{PATH} — replaced by the contents of the file at PATH (trailing
//                 newlines trimmed). If PATH does not exist or cannot be read,
//                 the pattern is replaced with an empty string and a warning
//                 is logged. This is designed for Docker secrets, K8s mounted
//                 secrets, and Vault agent files.
func ExpandEnvValue(s string) string {
	// Expand $ENV{VAR} patterns
	s = expandEnvPattern(s)
	// Expand $FILE{PATH} patterns
	s = expandFilePattern(s)
	return s
}

// expandEnvPattern replaces $ENV{VAR} with the environment variable value.
func expandEnvPattern(s string) string {
	for {
		start := strings.Index(s, "$ENV{")
		if start == -1 {
			break
		}
		end := strings.Index(s[start:], "}")
		if end == -1 {
			break
		}
		varName := s[start+5 : start+end]
		envVal, ok := os.LookupEnv(varName)
		if !ok {
			slog.Warn("$ENV{} references unset environment variable", "var", varName)
		}
		s = s[:start] + envVal + s[start+end+1:]
	}
	return s
}

// expandFilePattern replaces $FILE{PATH} with the contents of the file.
// The file content has trailing newlines trimmed.
func expandFilePattern(s string) string {
	for {
		start := strings.Index(s, "$FILE{")
		if start == -1 {
			break
		}
		end := strings.Index(s[start:], "}")
		if end == -1 {
			break
		}
		path := s[start+6 : start+end]
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("$FILE{} references unreadable file", "path", path, "error", err)
			s = s[:start] + s[start+end+1:]
		} else {
			val := strings.TrimRight(string(data), "\n\r")
			s = s[:start] + val + s[start+end+1:]
		}
	}
	return s
}
