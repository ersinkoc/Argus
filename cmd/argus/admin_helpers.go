package main

import (
	"encoding/json"
	"fmt"

	"github.com/ersinkoc/argus/internal/admin"
	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/classify"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/plugin"
	"github.com/ersinkoc/argus/internal/policy"
)

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
		for i := range safe.Gateway.APIKeys {
			if safe.Gateway.APIKeys[i].Key != "" {
				safe.Gateway.APIKeys[i].Key = "***REDACTED***"
			}
			for j := range safe.Gateway.APIKeys[i].PreviousKeys {
				safe.Gateway.APIKeys[i].PreviousKeys[j] = "***REDACTED***"
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
