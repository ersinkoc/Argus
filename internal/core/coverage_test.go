package core

import (
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/config"
	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/session"
)

func TestStartupBanner(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Targets = []config.Target{{Name: "pg", Host: "localhost", Port: 5432, Protocol: "postgresql"}}
	cfg.Audit.PIIAutoDetect = true
	cfg.Metrics.Enabled = true

	banner := StartupBanner(cfg, "v1.0.0-test")
	if banner == "" {
		t.Error("banner should not be empty")
	}
	if len(banner) < 100 {
		t.Error("banner should include feature summary")
	}
}

func TestStartupBannerWithTLS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.Listeners[0].TLS.Enabled = true
	cfg.Targets = []config.Target{{Name: "pg", Host: "h", Port: 5432, TLS: config.TLSConfig{Enabled: true}}}

	banner := StartupBanner(cfg, "test")
	if banner == "" {
		t.Error("banner should not be empty")
	}
}

func TestProxySetters(t *testing.T) {
	cfg := config.DefaultConfig()
	ps := &policy.PolicySet{Defaults: policy.DefaultsConfig{Action: "allow"}, Roles: map[string]policy.Role{}}
	loader := policy.NewLoader(nil, 0)
	loader.SetCurrent(ps)
	engine := policy.NewEngine(loader)
	logger := audit.NewLogger(10, audit.LevelMinimal, 4096)

	proxy := NewProxy(cfg, engine, logger)

	// Test all setters — should not panic
	proxy.SetOnEvent(func(any) {})
	proxy.SetSlowQueryLogger(audit.NewSlowQueryLogger(time.Second, logger))
	proxy.SetRewriter(inspection.NewRewriter())
	proxy.SetSessionLimiter(session.NewConcurrencyLimiter(5))
	proxy.SetQueryRecorder(nil)

	if proxy.ApprovalManager() == nil {
		t.Error("ApprovalManager should not be nil")
	}
	if proxy.SessionManager() == nil {
		t.Error("SessionManager should not be nil")
	}

	stats := proxy.PoolStats()
	if stats == nil {
		t.Error("PoolStats should return non-nil map")
	}
}

func TestApprovalManagerCount(t *testing.T) {
	am := NewApprovalManager(time.Second)
	if am.Count() != 0 {
		t.Errorf("initial count = %d, want 0", am.Count())
	}
}

func TestApprovalManagerApproveNonexistent(t *testing.T) {
	am := NewApprovalManager(time.Second)
	err := am.Approve("nonexistent", "admin")
	if err == nil {
		t.Error("should error for nonexistent request")
	}
}

func TestApprovalManagerDenyNonexistent(t *testing.T) {
	am := NewApprovalManager(time.Second)
	err := am.Deny("nonexistent", "admin", "reason")
	if err == nil {
		t.Error("should error for nonexistent request")
	}
}

func TestApprovalManagerDefaultTimeout(t *testing.T) {
	am := NewApprovalManager(0) // should default
	if am.timeout != 5*time.Minute {
		t.Errorf("default timeout = %v, want 5m", am.timeout)
	}
}

func TestRouterRegister(t *testing.T) {
	r := NewRouter()

	// All 3 protocols registered
	if r.GetHandler("postgresql") == nil {
		t.Error("should have postgresql")
	}
	if r.GetHandler("mysql") == nil {
		t.Error("should have mysql")
	}
	if r.GetHandler("mssql") == nil {
		t.Error("should have mssql")
	}
	if r.GetHandler("oracle") != nil {
		t.Error("should not have oracle")
	}
}
