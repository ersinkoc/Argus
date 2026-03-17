package policy

import (
	"net"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

// Action represents a policy decision action.
type Action int

const (
	ActionAllow Action = iota
	ActionBlock
	ActionMask
	ActionAudit // allow but with enhanced logging
)

var actionNames = map[Action]string{
	ActionAllow: "allow",
	ActionBlock: "block",
	ActionMask:  "mask",
	ActionAudit: "audit",
}

func (a Action) String() string {
	if s, ok := actionNames[a]; ok {
		return s
	}
	return "unknown"
}

// ParseAction parses an action string.
func ParseAction(s string) Action {
	for a, name := range actionNames {
		if name == s {
			return a
		}
	}
	return ActionAllow
}

// Context is the policy evaluation context.
type Context struct {
	// Who
	Username   string
	Roles      []string
	ClientIP   net.IP
	AuthMethod string

	// Where
	Database string
	Schema   string
	Tables   []string
	Columns  []string

	// When
	Timestamp   time.Time
	DayOfWeek   time.Weekday
	IsWorkHours bool

	// What
	CommandType inspection.CommandType
	RiskLevel   inspection.RiskLevel
	RawSQL      string
	Confidence  float64
	HasWhere    bool
}

// Decision is the result of policy evaluation.
type Decision struct {
	Action       Action
	MaskingRules []MaskingRule
	Reason       string
	PolicyName   string
	RiskScore    int
	LogLevel     string
	MaxRows      int64
}

// MaskingRule defines how a column should be masked.
type MaskingRule struct {
	Column      string `json:"column"`
	Transformer string `json:"transformer"`
}

// PolicySet is a collection of loaded policies.
type PolicySet struct {
	Version  string          `json:"version"`
	Defaults DefaultsConfig  `json:"defaults"`
	Roles    map[string]Role `json:"roles"`
	Policies []PolicyRule    `json:"policies"`
}

// DefaultsConfig is the global default settings.
type DefaultsConfig struct {
	Action         string `json:"action"`
	LogLevel       string `json:"log_level"`
	MaxRows        int64  `json:"max_rows"`
	SessionTimeout string `json:"session_timeout"`
}

// Role defines role membership.
type Role struct {
	Users  []string `json:"users"`
	Groups []string `json:"groups"`
}

// PolicyRule is a single policy rule.
type PolicyRule struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Match       MatchConfig     `json:"match"`
	Condition   *ConditionConfig `json:"condition,omitempty"`
	Action      string          `json:"action,omitempty"`
	Masking     []MaskingRule   `json:"masking,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	LogLevel    string          `json:"log_level,omitempty"`
	MaxRows     int64           `json:"max_rows,omitempty"`
}

// MatchConfig defines what a policy rule matches.
type MatchConfig struct {
	Roles     []string `json:"roles,omitempty"`
	Commands  []string `json:"commands,omitempty"`
	Databases []string `json:"databases,omitempty"`
	Tables    []string `json:"tables,omitempty"`
}

// ConditionConfig defines additional conditions.
type ConditionConfig struct {
	SQLContains    []string `json:"sql_contains,omitempty"`
	RiskLevelGTE   string   `json:"risk_level_gte,omitempty"`
	WorkHours      string   `json:"work_hours,omitempty"`
	WorkDays       []string `json:"work_days,omitempty"`
	SourceIPIn     []string `json:"source_ip_in,omitempty"`
	SourceIPNotIn  []string `json:"source_ip_not_in,omitempty"`
}
