package config

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the main Argus configuration.
type Config struct {
	Server       ServerConfig       `json:"server"`
	Targets      []Target           `json:"targets"`
	Routing      RoutingConfig      `json:"routing"`
	Policy       PolicyConfig       `json:"policy"`
	Pool         PoolConfig         `json:"pool"`
	Session      SessionConfig      `json:"session"`
	Audit        AuditConfig        `json:"audit"`
	Admin        AdminConfig        `json:"admin"`
	Metrics      MetricsConfig      `json:"metrics"`
	Rewrite      RewriteConfig      `json:"rewrite,omitempty"`
	SlowQuery    SlowQueryConfig    `json:"slow_query,omitempty"`
	PlanAnalysis PlanAnalysisConfig `json:"plan_analysis,omitempty"`
	Gateway      GatewayConfig      `json:"gateway,omitempty"`
}

// GatewayConfig configures the SQL Gateway HTTP API.
type GatewayConfig struct {
	Enabled         bool               `json:"enabled"`
	APIKeys         []APIKeyConfig     `json:"api_keys,omitempty"`
	MaxResultRows   int64              `json:"max_result_rows,omitempty"`
	ApprovalTimeout string             `json:"approval_timeout,omitempty"`
	WebhookURL      string             `json:"webhook_url,omitempty"`
	WebhookHeaders  map[string]string  `json:"webhook_headers,omitempty"`
	RequireApproval RequireApprovalCfg `json:"require_approval,omitempty"`
}

// APIKeyConfig defines an API key for gateway authentication.
type APIKeyConfig struct {
	Key       string   `json:"key"`
	Username  string   `json:"username"`
	Roles     []string `json:"roles,omitempty"`
	Database  string   `json:"database,omitempty"`
	RateLimit float64  `json:"rate_limit,omitempty"`
	Enabled   bool     `json:"enabled"`
}

// RequireApprovalCfg defines which queries need approval in gateway mode.
type RequireApprovalCfg struct {
	RiskLevelGTE string   `json:"risk_level_gte,omitempty"`
	Commands     []string `json:"commands,omitempty"`
}

type ServerConfig struct {
	Listeners []ListenerConfig `json:"listeners"`
}

type ListenerConfig struct {
	Address  string    `json:"address"`
	Protocol string    `json:"protocol"`
	TLS      TLSConfig `json:"tls"`
}

type TLSConfig struct {
	Enabled        bool   `json:"enabled"`
	CertFile       string `json:"cert_file"`
	KeyFile        string `json:"key_file"`
	CAFile         string `json:"ca_file"`
	Verify         bool   `json:"verify"`
	ClientAuth     bool   `json:"client_auth"`      // require client certificate (mTLS)
	ClientCAFile   string `json:"client_ca_file"`   // CA to verify client certs
}

type Target struct {
	Name     string    `json:"name"`
	Protocol string    `json:"protocol"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	TLS      TLSConfig `json:"tls"`
}

func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

type RoutingConfig struct {
	DefaultTarget string        `json:"default_target"`
	Rules         []RoutingRule `json:"rules"`
}

type RoutingRule struct {
	Database string `json:"database"`
	Target   string `json:"target"`
}

type PolicyConfig struct {
	Files          []string      `json:"files"`
	ReloadInterval time.Duration `json:"reload_interval"`
}

func (p *PolicyConfig) UnmarshalJSON(data []byte) error {
	type Alias struct {
		Files          []string `json:"files"`
		ReloadInterval string   `json:"reload_interval"`
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	p.Files = a.Files
	if a.ReloadInterval != "" {
		d, err := time.ParseDuration(a.ReloadInterval)
		if err != nil {
			return fmt.Errorf("invalid reload_interval: %w", err)
		}
		p.ReloadInterval = d
	} else {
		p.ReloadInterval = 5 * time.Second
	}
	return nil
}

type PoolConfig struct {
	MaxConnectionsPerTarget    int           `json:"max_connections_per_target"`
	MinIdleConnections         int           `json:"min_idle_connections"`
	ConnectionMaxLifetime      time.Duration `json:"connection_max_lifetime"`
	ConnectionTimeout          time.Duration `json:"connection_timeout"`
	HealthCheckInterval        time.Duration `json:"health_check_interval"`
	CircuitBreakerThreshold    int           `json:"circuit_breaker_threshold,omitempty"`    // failures before open, default 5
	CircuitBreakerResetTimeout time.Duration `json:"circuit_breaker_reset_timeout,omitempty"` // default 30s
}

func (p *PoolConfig) UnmarshalJSON(data []byte) error {
	type Alias struct {
		MaxConnectionsPerTarget    int    `json:"max_connections_per_target"`
		MinIdleConnections         int    `json:"min_idle_connections"`
		ConnectionMaxLifetime      string `json:"connection_max_lifetime"`
		ConnectionTimeout          string `json:"connection_timeout"`
		HealthCheckInterval        string `json:"health_check_interval"`
		CircuitBreakerThreshold    int    `json:"circuit_breaker_threshold"`
		CircuitBreakerResetTimeout string `json:"circuit_breaker_reset_timeout"`
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	p.MaxConnectionsPerTarget = a.MaxConnectionsPerTarget
	p.MinIdleConnections = a.MinIdleConnections
	p.CircuitBreakerThreshold = a.CircuitBreakerThreshold
	var err error
	if a.ConnectionMaxLifetime != "" {
		p.ConnectionMaxLifetime, err = time.ParseDuration(a.ConnectionMaxLifetime)
		if err != nil {
			return fmt.Errorf("invalid connection_max_lifetime: %w", err)
		}
	}
	if a.ConnectionTimeout != "" {
		p.ConnectionTimeout, err = time.ParseDuration(a.ConnectionTimeout)
		if err != nil {
			return fmt.Errorf("invalid connection_timeout: %w", err)
		}
	}
	if a.HealthCheckInterval != "" {
		p.HealthCheckInterval, err = time.ParseDuration(a.HealthCheckInterval)
		if err != nil {
			return fmt.Errorf("invalid health_check_interval: %w", err)
		}
	}
	if a.CircuitBreakerResetTimeout != "" {
		p.CircuitBreakerResetTimeout, err = time.ParseDuration(a.CircuitBreakerResetTimeout)
		if err != nil {
			return fmt.Errorf("invalid circuit_breaker_reset_timeout: %w", err)
		}
	}
	return nil
}

type SessionConfig struct {
	IdleTimeout       time.Duration `json:"idle_timeout"`
	MaxDuration       time.Duration `json:"max_duration"`
	MaxPerUser        int           `json:"max_per_user,omitempty"` // 0 = unlimited
}

type RewriteConfig struct {
	MaxLimit   int    `json:"max_limit,omitempty"`   // auto-add LIMIT N to SELECT
	ForceWhere string `json:"force_where,omitempty"` // inject WHERE condition
}

type PlanAnalysisConfig struct {
	Enabled  bool   `json:"enabled"`            // run EXPLAIN before policy eval for SELECT
	Timeout  string `json:"timeout,omitempty"`  // max time per EXPLAIN, default 500ms
	Protocol string `json:"protocol,omitempty"` // "postgresql" (only PG supported)
}

type SlowQueryConfig struct {
	Threshold string `json:"threshold,omitempty"` // duration string e.g. "1s"
}

func (s *SessionConfig) UnmarshalJSON(data []byte) error {
	type Alias struct {
		IdleTimeout string `json:"idle_timeout"`
		MaxDuration string `json:"max_duration"`
		MaxPerUser  int    `json:"max_per_user"`
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	s.MaxPerUser = a.MaxPerUser
	var err error
	if a.IdleTimeout != "" {
		s.IdleTimeout, err = time.ParseDuration(a.IdleTimeout)
		if err != nil {
			return fmt.Errorf("invalid idle_timeout: %w", err)
		}
	}
	if a.MaxDuration != "" {
		s.MaxDuration, err = time.ParseDuration(a.MaxDuration)
		if err != nil {
			return fmt.Errorf("invalid max_duration: %w", err)
		}
	}
	return nil
}

type AuditConfig struct {
	Level        string         `json:"level"`
	Outputs      []AuditOutput  `json:"outputs"`
	BufferSize   int            `json:"buffer_size"`
	SQLMaxLength int            `json:"sql_max_length"`
	RecordFile   string         `json:"record_file,omitempty"` // forensic query recording
	PIIAutoDetect bool          `json:"pii_auto_detect"`       // auto-detect PII columns
	WebhookURL   string         `json:"webhook_url,omitempty"` // SIEM webhook endpoint
}

type AuditOutput struct {
	Type     string         `json:"type"`
	Path     string         `json:"path,omitempty"`
	Rotation *RotationConfig `json:"rotation,omitempty"`
}

type RotationConfig struct {
	MaxSizeMB int `json:"max_size_mb"`
	MaxFiles  int `json:"max_files"`
}

type AdminConfig struct {
	Enabled   bool   `json:"enabled"`
	Address   string `json:"address"`
	AuthToken string `json:"auth_token"`
}

type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Listeners: []ListenerConfig{
				{Address: ":15432", Protocol: "postgresql"},
			},
		},
		Pool: PoolConfig{
			MaxConnectionsPerTarget: 100,
			MinIdleConnections:      5,
			ConnectionMaxLifetime:   1 * time.Hour,
			ConnectionTimeout:       10 * time.Second,
			HealthCheckInterval:     30 * time.Second,
		},
		Session: SessionConfig{
			IdleTimeout: 30 * time.Minute,
			MaxDuration: 8 * time.Hour,
		},
		Audit: AuditConfig{
			Level:        "standard",
			BufferSize:   10000,
			SQLMaxLength: 4096,
			Outputs: []AuditOutput{
				{Type: "stdout"},
			},
		},
		Policy: PolicyConfig{
			ReloadInterval: 5 * time.Second,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Address: ":9091",
		},
	}
}

// Load reads configuration from a JSON file and applies environment overrides.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file: %w", err)
		}
	}

	expandEnvInConfig(cfg)
	applyEnvOverrides(cfg)

	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// ResolvePolicyPaths resolves policy file paths relative to the config file directory.
func ResolvePolicyPaths(cfg *Config, configPath string) {
	if configPath == "" {
		return
	}
	dir := filepath.Dir(configPath)
	for i, f := range cfg.Policy.Files {
		if !filepath.IsAbs(f) {
			cfg.Policy.Files[i] = filepath.Join(dir, f)
		}
	}
}

// applyEnvOverrides applies ARGUS_ prefixed environment variables.
func applyEnvOverrides(cfg *Config) {
	envMap := map[string]func(string){
		"ARGUS_AUDIT_LEVEL":    func(v string) { cfg.Audit.Level = v },
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
		"ARGUS_ADMIN_ADDRESS":   func(v string) { cfg.Admin.Address = v },
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
	}
}

// ExpandEnvValue replaces $ENV{VAR} patterns with environment variable values.
func ExpandEnvValue(s string) string {
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
			log.Printf("[argus] WARNING: $ENV{%s} references unset environment variable", varName)
		}
		s = s[:start] + envVal + s[start+end+1:]
	}
	return s
}

// Validate checks the configuration for errors.
func Validate(cfg *Config) error {
	if len(cfg.Server.Listeners) == 0 {
		return fmt.Errorf("at least one listener is required")
	}

	for i, l := range cfg.Server.Listeners {
		if l.Address == "" {
			return fmt.Errorf("listener[%d]: address is required", i)
		}
		validProtocols := map[string]bool{"postgresql": true, "mysql": true, "mssql": true, "auto": true}
		if l.Protocol != "" && !validProtocols[l.Protocol] {
			return fmt.Errorf("listener[%d]: unsupported protocol %q", i, l.Protocol)
		}
		if l.TLS.Enabled {
			if l.TLS.CertFile == "" || l.TLS.KeyFile == "" {
				return fmt.Errorf("listener[%d]: TLS enabled but cert_file or key_file missing", i)
			}
			if l.TLS.ClientAuth && l.TLS.ClientCAFile == "" {
				return fmt.Errorf("listener[%d]: client_auth requires client_ca_file", i)
			}
		}
	}

	for i, t := range cfg.Targets {
		if t.Name == "" {
			return fmt.Errorf("target[%d]: name is required", i)
		}
		if t.Host == "" {
			return fmt.Errorf("target[%d] %q: host is required", i, t.Name)
		}
		if t.Port <= 0 || t.Port > 65535 {
			return fmt.Errorf("target[%d] %q: invalid port %d", i, t.Name, t.Port)
		}
	}

	validLevels := map[string]bool{"minimal": true, "standard": true, "verbose": true}
	if cfg.Audit.Level != "" && !validLevels[cfg.Audit.Level] {
		return fmt.Errorf("audit: invalid level %q", cfg.Audit.Level)
	}

	if cfg.Pool.MaxConnectionsPerTarget <= 0 {
		return fmt.Errorf("pool: max_connections_per_target must be positive")
	}

	// Cross-reference validation
	// Check routing default target exists
	if cfg.Routing.DefaultTarget != "" && len(cfg.Targets) > 0 {
		if cfg.FindTarget(cfg.Routing.DefaultTarget) == nil {
			return fmt.Errorf("routing: default_target %q does not match any target", cfg.Routing.DefaultTarget)
		}
	}

	// Check routing rules reference valid targets
	for i, rule := range cfg.Routing.Rules {
		if rule.Target != "" && len(cfg.Targets) > 0 {
			if cfg.FindTarget(rule.Target) == nil {
				return fmt.Errorf("routing.rules[%d]: target %q does not match any target", i, rule.Target)
			}
		}
	}

	// Check listener protocols match available targets
	targetProtocols := make(map[string]bool)
	for _, t := range cfg.Targets {
		targetProtocols[t.Protocol] = true
	}
	for i, l := range cfg.Server.Listeners {
		if l.Protocol != "" && l.Protocol != "auto" && len(cfg.Targets) > 0 {
			if !targetProtocols[l.Protocol] {
				return fmt.Errorf("listener[%d]: protocol %q has no matching target", i, l.Protocol)
			}
		}
	}

	// Check policy files exist
	for i, f := range cfg.Policy.Files {
		if f != "" {
			if _, err := os.Stat(f); os.IsNotExist(err) {
				return fmt.Errorf("policy.files[%d]: file %q does not exist", i, f)
			}
		}
	}

	// Gateway validation
	if cfg.Gateway.Enabled {
		if len(cfg.Targets) == 0 {
			return fmt.Errorf("gateway: enabled but no targets configured")
		}
		seenKeys := make(map[string]int)
		for i, key := range cfg.Gateway.APIKeys {
			if key.Key == "" {
				return fmt.Errorf("gateway.api_keys[%d]: key is required", i)
			}
			if key.Username == "" {
				return fmt.Errorf("gateway.api_keys[%d]: username is required", i)
			}
			if prev, exists := seenKeys[key.Key]; exists {
				return fmt.Errorf("gateway.api_keys[%d]: duplicate key (same as api_keys[%d])", i, prev)
			}
			seenKeys[key.Key] = i
		}
	}

	return nil
}

// FindTarget finds a target by name.
func (c *Config) FindTarget(name string) *Target {
	for i := range c.Targets {
		if c.Targets[i].Name == name {
			return &c.Targets[i]
		}
	}
	return nil
}

// ResolveTarget determines the target for a given database name.
func (c *Config) ResolveTarget(database string) *Target {
	for _, rule := range c.Routing.Rules {
		if matchPattern(rule.Database, database) {
			return c.FindTarget(rule.Target)
		}
	}
	if c.Routing.DefaultTarget != "" {
		return c.FindTarget(c.Routing.DefaultTarget)
	}
	return nil
}

// matchPattern supports simple wildcard matching with *.
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(value, pattern[1:])
	}
	return pattern == value
}

// String returns a summary (hiding sensitive fields).
func (c *Config) String() string {
	return fmt.Sprintf("Config{listeners=%d, targets=%d, audit=%s}",
		len(c.Server.Listeners), len(c.Targets), c.Audit.Level)
}
