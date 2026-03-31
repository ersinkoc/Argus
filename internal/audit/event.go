package audit

import "time"

// EventType represents the type of audit event.
type EventType int

const (
	ConnectionOpen   EventType = iota // client connected
	ConnectionClose                   // client disconnected
	AuthSuccess                       // authentication succeeded
	AuthFailure                       // authentication failed
	CommandExecuted                   // command was forwarded to backend
	CommandBlocked                    // command was blocked by policy
	ResultMasked                      // result had masking applied
	ResultTruncated                   // result was truncated by row limit
	PolicyViolation                   // policy violation detected
	SessionTimeout                    // session timed out
	SessionKilled                     // session killed by admin
	PolicyReloaded                    // policy files reloaded
	GatewayQuery                      // query submitted via gateway API
	ApprovalCreated                   // approval request created
	ApprovalResolved                  // approval approved or denied
	AllowlistAdded                    // allowlist entry created
	AllowlistUsed                     // allowlist entry consumed
)

var eventTypeNames = map[EventType]string{
	ConnectionOpen:  "connection_open",
	ConnectionClose: "connection_close",
	AuthSuccess:     "auth_success",
	AuthFailure:     "auth_failure",
	CommandExecuted: "command_executed",
	CommandBlocked:  "command_blocked",
	ResultMasked:    "result_masked",
	ResultTruncated: "result_truncated",
	PolicyViolation: "policy_violation",
	SessionTimeout:  "session_timeout",
	SessionKilled:    "session_killed",
	PolicyReloaded:   "policy_reloaded",
	GatewayQuery:     "gateway_query",
	ApprovalCreated:  "approval_created",
	ApprovalResolved: "approval_resolved",
	AllowlistAdded:   "allowlist_added",
	AllowlistUsed:    "allowlist_used",
}

func (e EventType) String() string {
	if s, ok := eventTypeNames[e]; ok {
		return s
	}
	return "unknown"
}

// Event represents a single audit event.
type Event struct {
	ID          string        `json:"id"`
	Timestamp   time.Time     `json:"timestamp"`
	EventType   string        `json:"event_type"`
	SessionID   string        `json:"session_id"`
	Username    string        `json:"username"`
	Roles       []string      `json:"roles,omitempty"`
	ClientIP    string        `json:"client_ip"`
	Database    string        `json:"database,omitempty"`
	Command     string        `json:"command,omitempty"`
	CommandType string        `json:"command_type,omitempty"`
	Tables      []string      `json:"tables,omitempty"`
	RiskLevel   string        `json:"risk_level,omitempty"`
	PolicyName  string        `json:"policy_name,omitempty"`
	Action      string        `json:"action"`
	RowCount    int64         `json:"row_count,omitempty"`
	ByteCount   int64         `json:"byte_count,omitempty"`
	Duration    time.Duration `json:"duration,omitempty"`
	MaskedCols  []string      `json:"masked_cols,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Error       string        `json:"error,omitempty"`
}

// LogLevel controls audit detail.
type LogLevel int

const (
	LevelMinimal  LogLevel = iota // connection events and blocked commands only
	LevelStandard                 // + executed commands, policy decisions
	LevelVerbose                  // + row counts, byte counts, durations
)

func ParseLogLevel(s string) LogLevel {
	switch s {
	case "minimal":
		return LevelMinimal
	case "verbose":
		return LevelVerbose
	default:
		return LevelStandard
	}
}
