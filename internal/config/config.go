package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the main Argus configuration.
type Config struct {
	Server  ServerConfig  `json:"server"`
	Targets []Target      `json:"targets"`
	Routing RoutingConfig `json:"routing"`
	Policy  PolicyConfig  `json:"policy"`
	Pool    PoolConfig    `json:"pool"`
	Session SessionConfig `json:"session"`
	Audit   AuditConfig   `json:"audit"`
	Admin   AdminConfig   `json:"admin"`
	Metrics MetricsConfig `json:"metrics"`
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
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
	Verify   bool   `json:"verify"`
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
	MaxConnectionsPerTarget int           `json:"max_connections_per_target"`
	MinIdleConnections      int           `json:"min_idle_connections"`
	ConnectionMaxLifetime   time.Duration `json:"connection_max_lifetime"`
	ConnectionTimeout       time.Duration `json:"connection_timeout"`
	HealthCheckInterval     time.Duration `json:"health_check_interval"`
}

func (p *PoolConfig) UnmarshalJSON(data []byte) error {
	type Alias struct {
		MaxConnectionsPerTarget int    `json:"max_connections_per_target"`
		MinIdleConnections      int    `json:"min_idle_connections"`
		ConnectionMaxLifetime   string `json:"connection_max_lifetime"`
		ConnectionTimeout       string `json:"connection_timeout"`
		HealthCheckInterval     string `json:"health_check_interval"`
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	p.MaxConnectionsPerTarget = a.MaxConnectionsPerTarget
	p.MinIdleConnections = a.MinIdleConnections
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
	return nil
}

type SessionConfig struct {
	IdleTimeout time.Duration `json:"idle_timeout"`
	MaxDuration time.Duration `json:"max_duration"`
}

func (s *SessionConfig) UnmarshalJSON(data []byte) error {
	type Alias struct {
		IdleTimeout string `json:"idle_timeout"`
		MaxDuration string `json:"max_duration"`
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
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

// expandEnvValue replaces $ENV{VAR} patterns with environment variable values.
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
		envVal := os.Getenv(varName)
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
