# Argus — Database Access Proxy

## SPECIFICATION

**Version:** 1.0.0-draft
**Author:** Ersin Koç / ECOSTACK TECHNOLOGY OÜ
**Date:** 2026-03-17
**Language:** Go
**License:** TBD (MIT or dual MIT/Enterprise)
**Repository:** github.com/ersinkoc/argus

---

## 1. Project Overview

### 1.1 What Is Argus

Argus is a protocol-aware database access proxy written in Go.
It sits between applications and databases.
All database connections flow through Argus.
Direct database access is eliminated.

Argus inspects every connection, every command, and every result.
It enforces access policies in real time.
It masks sensitive data at the result level.
It logs everything for audit and compliance.

### 1.2 What Problem Does It Solve

Traditional PAM tools manage credentials.
They answer "who connected."
They do not answer "what did they do" or "what did they see."

Argus answers all three questions:
- Who connected → session-level identity
- What did they do → command-level inspection
- What did they see → result-level filtering

### 1.3 Core Principles

- **Zero external dependencies.** Standard library only. No CGO. Single binary.
- **Protocol-native.** Speaks each database's wire protocol natively. No JDBC/ODBC wrapping.
- **Modular architecture.** Each database protocol is an independent adapter. Core engine is protocol-agnostic.
- **Streaming-first.** Results are processed in streaming mode. No full buffering by default.
- **Policy-driven.** Every decision comes from a policy engine. No hardcoded rules.
- **Observable.** Every connection, command, and decision is logged with structured audit trail.

### 1.4 Design Philosophy

The proxy must be invisible to applications.
An application connects to Argus exactly as it would connect to the real database.
Same protocol, same port convention, same authentication flow.
The only change is the connection target address.

This means Argus must implement each database's wire protocol faithfully.
Authentication handshakes, SSL negotiation, query execution, result streaming — all protocol-native.

---

## 2. Architecture

### 2.1 High-Level Flow

```
┌──────────┐         ┌──────────────────────────────────────────┐         ┌──────────┐
│          │   TCP    │                 Argus                  │   TCP    │          │
│  Client  │────────▶│  ┌─────────┐  ┌────────┐  ┌──────────┐  │────────▶│ Database │
│  (App)   │◀────────│  │Protocol │  │ Policy │  │ Masking  │  │◀────────│ Server   │
│          │         │  │ Handler │  │ Engine │  │ Pipeline │  │         │          │
└──────────┘         │  └─────────┘  └────────┘  └──────────┘  │         └──────────┘
                     │  ┌─────────┐  ┌────────┐  ┌──────────┐  │
                     │  │Session  │  │ Audit  │  │Connection│  │
                     │  │Manager  │  │ Logger │  │  Pool    │  │
                     │  └─────────┘  └────────┘  └──────────┘  │
                     └──────────────────────────────────────────┘
```

### 2.2 Module Overview

```
argus/
├── cmd/
│   └── argus/              # main binary entry point
├── internal/
│   ├── core/                  # core proxy engine
│   │   ├── listener.go        # TCP listener, accepts client connections
│   │   ├── router.go          # routes connections to correct protocol handler
│   │   └── pipeline.go        # request/response pipeline orchestrator
│   ├── protocol/              # database wire protocol implementations
│   │   ├── handler.go         # ProtocolHandler interface definition
│   │   ├── pg/                # PostgreSQL protocol (Phase 1)
│   │   │   ├── codec.go       # message encode/decode
│   │   │   ├── auth.go        # authentication handshake
│   │   │   ├── query.go       # query message handling
│   │   │   ├── result.go      # result set handling
│   │   │   └── handler.go     # ProtocolHandler implementation
│   │   ├── mysql/             # MySQL protocol (Phase 2)
│   │   │   └── ...
│   │   └── mssql/             # MSSQL TDS protocol (Phase 3)
│   │       └── ...
│   ├── inspection/            # SQL command analysis
│   │   ├── tokenizer.go       # lightweight SQL tokenizer
│   │   ├── classifier.go      # command type classifier
│   │   └── extractor.go       # table/column name extractor
│   ├── policy/                # policy engine
│   │   ├── engine.go          # policy evaluator
│   │   ├── loader.go          # YAML policy loader
│   │   ├── types.go           # policy types and structs
│   │   ├── matcher.go         # rule matching logic
│   │   └── cache.go           # decision cache
│   ├── masking/               # result set masking
│   │   ├── pipeline.go        # streaming masking pipeline
│   │   ├── rules.go           # masking rule definitions
│   │   ├── patterns.go        # PII detection patterns
│   │   └── transformers.go    # masking transformers (redact, partial, hash)
│   ├── session/               # session lifecycle
│   │   ├── manager.go         # session create/track/destroy
│   │   ├── identity.go        # session identity resolution
│   │   └── store.go           # active session store
│   ├── pool/                  # backend connection pool
│   │   ├── pool.go            # pool manager
│   │   ├── conn.go            # pooled connection wrapper
│   │   └── health.go          # backend health checking
│   ├── audit/                 # audit logging
│   │   ├── logger.go          # structured audit logger
│   │   ├── event.go           # audit event types
│   │   └── writer.go          # output writers (file, stdout, syslog)
│   ├── config/                # configuration
│   │   ├── config.go          # main config struct
│   │   ├── loader.go          # YAML config loader
│   │   └── validate.go        # config validation
│   └── admin/                 # admin API (Phase 2)
│       ├── server.go          # HTTP admin API
│       └── handlers.go        # admin endpoints
├── configs/
│   ├── argus.yaml          # main configuration
│   └── policies/              # policy files
│       ├── default.yaml
│       └── examples/
└── docs/
    ├── IMPLEMENTATION.md
    └── TASKS.md
```

### 2.3 Component Interactions

1. **Listener** accepts a TCP connection from client.
2. **Router** detects the database protocol from the first bytes (or from listener port config).
3. **Protocol Handler** performs the authentication handshake with the client.
4. **Session Manager** creates a session record with client identity.
5. **Pool Manager** provides (or creates) a backend connection to the target database.
6. **Protocol Handler** forwards the authentication to the backend (with proxy credentials or passthrough).
7. Client sends a command.
8. **Protocol Handler** decodes the command from wire format.
9. **Inspection** tokenizes and classifies the command.
10. **Policy Engine** evaluates the command against loaded policies.
11. If ALLOW → command is forwarded to backend.
12. If BLOCK → error response is sent to client. Audit event logged.
13. If MASK → command is forwarded, but result goes through **Masking Pipeline**.
14. **Protocol Handler** reads the result from backend.
15. **Masking Pipeline** applies column-level transformations in streaming mode.
16. **Protocol Handler** encodes the masked result and sends to client.
17. **Audit Logger** records the full event asynchronously.

---

## 3. Protocol Layer

### 3.1 Protocol Handler Interface

Every database adapter implements this interface:

```go
type ProtocolHandler interface {
    // Name returns the protocol identifier (e.g., "postgresql", "mysql")
    Name() string

    // DetectProtocol checks if the initial bytes match this protocol
    DetectProtocol(peek []byte) bool

    // Handshake performs the full authentication exchange with the client
    // Returns session metadata (username, database, client info)
    Handshake(ctx context.Context, client net.Conn, backend net.Conn) (*SessionInfo, error)

    // ReadCommand reads and decodes the next command from the client
    ReadCommand(ctx context.Context, client net.Conn) (*Command, error)

    // ForwardCommand sends a command to the backend and returns raw result
    ForwardCommand(ctx context.Context, cmd *Command, backend net.Conn) error

    // ReadResult reads the result from backend
    // Returns a ResultReader for streaming access
    ReadResult(ctx context.Context, backend net.Conn) (ResultReader, error)

    // WriteResult writes a (possibly masked) result to the client
    WriteResult(ctx context.Context, result ResultReader, client net.Conn) error

    // WriteError sends a protocol-native error message to the client
    WriteError(ctx context.Context, client net.Conn, code string, message string) error

    // Close performs any cleanup for the protocol handler
    Close() error
}
```

### 3.2 Result Reader Interface

```go
type ResultReader interface {
    // Columns returns column metadata (name, type, index)
    Columns() []ColumnInfo

    // Next advances to the next row. Returns false when done.
    Next() bool

    // ScanRow returns the current row's values
    ScanRow() ([]FieldValue, error)

    // Close releases resources
    Close() error
}
```

This interface enables streaming. The masking pipeline wraps a ResultReader and transforms values without buffering the entire result set.

### 3.3 PostgreSQL Protocol (Phase 1)

PostgreSQL uses a message-based protocol documented at:
https://www.postgresql.org/docs/current/protocol.html

**Supported message types (MVP):**

Startup phase:
- StartupMessage (client → server)
- AuthenticationOk / AuthenticationCleartext / AuthenticationMD5 / AuthenticationSASL
- ParameterStatus
- BackendKeyData
- ReadyForQuery

Simple Query protocol:
- Query (client → server, contains SQL string)
- RowDescription (column metadata)
- DataRow (result rows)
- CommandComplete
- ErrorResponse
- NoticeResponse

Connection lifecycle:
- Terminate
- SSLRequest / SSLResponse

**Deferred to Phase 2:**
- Extended Query protocol (Parse, Bind, Describe, Execute, Sync)
- COPY protocol (CopyInResponse, CopyOutResponse, CopyData)
- Function Call protocol
- Notification protocol (LISTEN/NOTIFY)

**Why Simple Query first:** Simple Query sends the full SQL string in a single message. This is the easiest to inspect. Extended Query uses prepared statements where the SQL is sent in Parse and parameters in Bind — inspection requires correlating multiple messages. This adds complexity that can wait.

### 3.4 MySQL Protocol (Phase 2)

MySQL protocol documented at:
https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html

Key differences from PostgreSQL:
- Packet-based with 4-byte header (3 bytes length + 1 byte sequence ID)
- Capability flags negotiation
- COM_QUERY for text protocol (equivalent to Simple Query)
- COM_STMT_PREPARE / COM_STMT_EXECUTE for binary protocol

MySQL's text protocol is simpler than PostgreSQL's in some ways. The result set format (column count → column definitions → rows → EOF) is straightforward to parse.

### 3.5 MSSQL TDS Protocol (Phase 3)

TDS (Tabular Data Stream) protocol.
Spec available via [MS-TDS] from Microsoft Open Specifications.

Key characteristics:
- Token-based streaming protocol
- Pre-login handshake → Login7 → SQL Batch
- COLMETADATA + ROW tokens for result sets
- TDS 7.4+ for modern SQL Server versions

More complex than PostgreSQL/MySQL but fully documented.

### 3.6 Oracle TNS Protocol (Phase 4 — Optional)

Oracle Net Services / TNS.
Limited public documentation. Community reverse-engineered specs exist.
May require Oracle Instant Client as the **sole external dependency exception.**
Decision deferred to Phase 4 based on demand.

### 3.7 Protocol Detection

When a single listener port is used, protocol detection is performed by inspecting the first bytes:

| Protocol   | First Bytes Pattern                              |
|-----------|--------------------------------------------------|
| PostgreSQL | Bytes 4-7: `0x00 0x03 0x00 0x00` (version 3.0)  |
| PostgreSQL | `0x04 0xd2 0x16 0x2f` (SSLRequest)               |
| MySQL      | Server sends greeting first (proxy initiates)     |
| MSSQL/TDS  | `0x12` (Pre-login packet type)                    |

Alternatively, separate listener ports per protocol (recommended for production):
- `:15432` → PostgreSQL
- `:13306` → MySQL
- `:11433` → MSSQL

---

## 4. SQL Inspection

### 4.1 Approach

Argus does NOT implement a full SQL parser.
A full parser is unnecessary for access control decisions.

Instead, Argus uses a **lightweight tokenizer + command classifier.**
This is fast, predictable, and sufficient for policy evaluation.

### 4.2 Tokenizer

The tokenizer breaks a SQL string into tokens:
- Keywords (SELECT, INSERT, UPDATE, DELETE, DROP, TRUNCATE, CREATE, ALTER, GRANT, REVOKE, etc.)
- Identifiers (table names, column names, schema names)
- Operators
- Literals (strings, numbers)
- Comments (block `/* */` and line `--`)
- Whitespace (skipped)

The tokenizer handles:
- Quoted identifiers (`"table_name"`, `` `table_name` ``, `[table_name]`)
- String literals with escape sequences
- Multi-line statements
- Semicolons (statement separators)

### 4.3 Command Classifier

Based on the first meaningful token(s), the command is classified:

```go
type CommandType int

const (
    CommandSELECT    CommandType = iota  // SELECT queries
    CommandINSERT                        // INSERT statements
    CommandUPDATE                        // UPDATE statements
    CommandDELETE                        // DELETE statements
    CommandDDL                           // CREATE, ALTER, DROP, TRUNCATE
    CommandDCL                           // GRANT, REVOKE
    CommandTCL                           // BEGIN, COMMIT, ROLLBACK, SAVEPOINT
    CommandADMIN                         // SET, SHOW, EXPLAIN, ANALYZE
    CommandUTILITY                       // COPY, LOAD, VACUUM, REINDEX
    CommandUNKNOWN                       // unrecognized
)
```

### 4.4 Table/Column Extractor

After classification, the extractor identifies:
- Target table(s) from FROM, INTO, UPDATE, JOIN clauses
- Referenced columns from SELECT list, WHERE, SET clauses
- Schema qualification if present (e.g., `public.users`)

This extraction is **best-effort.** Complex subqueries, CTEs, and dynamic SQL may not be fully resolved. The policy engine accounts for this with a `confidence` field.

### 4.5 Dangerous Pattern Detection

Specific patterns are flagged regardless of policy:
- `DROP TABLE`, `DROP DATABASE`
- `TRUNCATE TABLE`
- `DELETE` without WHERE clause (bulk delete)
- `UPDATE` without WHERE clause (bulk update)
- `GRANT` / `REVOKE` statements
- Multiple statements separated by `;` (potential injection)
- Comment-embedded commands (`SELECT /* DROP TABLE users */ *`)

These patterns produce a `risk_level` field on the command:

```go
type RiskLevel int

const (
    RiskNone     RiskLevel = iota  // normal read operations
    RiskLow                        // standard write operations
    RiskMedium                     // DDL, bulk operations
    RiskHigh                       // destructive operations, privilege changes
    RiskCritical                   // multi-statement, potential injection patterns
)
```

---

## 5. Policy Engine

### 5.1 Overview

The policy engine is the brain of Argus.
It receives a context (who, where, when, what) and returns a decision.

Phase 1: YAML-based local policies.
Phase 2: Remote Policy API with local YAML as fallback.

### 5.2 Policy Evaluation Context

```go
type PolicyContext struct {
    // Who
    Username    string
    Roles       []string
    ClientIP    net.IP
    AuthMethod  string

    // Where
    Database    string
    Schema      string
    Tables      []string
    Columns     []string

    // When
    Timestamp   time.Time
    DayOfWeek   time.Weekday
    IsWorkHours bool

    // What
    CommandType CommandType
    RiskLevel   RiskLevel
    RawSQL      string    // available for logging, not for policy matching
    Confidence  float64   // how confident is the inspection result
}
```

### 5.3 Policy Decision

```go
type PolicyDecision struct {
    Action       Action          // Allow, Block, Mask, Audit
    MaskingRules []MaskingRule   // if Action is Mask, which columns how
    Reason       string          // human-readable explanation
    PolicyName   string          // which policy produced this decision
    RiskScore    int             // 0-100
    LogLevel     LogLevel        // what detail level to audit
}

type Action int

const (
    ActionAllow Action = iota
    ActionBlock
    ActionMask
    ActionAudit    // allow but with enhanced logging
)
```

### 5.4 YAML Policy Format

```yaml
# argus-policies.yaml
version: "1"

# Global defaults
defaults:
  action: audit              # default: allow and log
  log_level: standard        # minimal | standard | verbose
  max_rows: 100000           # result set row limit
  session_timeout: 30m       # idle session timeout

# Role definitions (mapped from DB users or external identity)
roles:
  dba:
    users: ["admin", "postgres_admin"]
  developer:
    users: ["dev_*"]         # wildcard matching
    groups: ["engineering"]
  support:
    users: ["support_*"]
    groups: ["customer_success"]
  finance:
    groups: ["finance_team"]

# Policy rules (evaluated top-to-bottom, first match wins)
policies:

  - name: "block-destructive-ddl"
    description: "Only DBA can run destructive DDL"
    match:
      roles: ["!dba"]                   # everyone except dba
      commands: [DDL]
    condition:
      sql_contains: ["DROP", "TRUNCATE"]
    action: block
    reason: "Destructive DDL requires DBA role"

  - name: "block-bulk-writes-production"
    description: "No bulk writes to production without WHERE"
    match:
      databases: ["production", "prod_*"]
      commands: [DELETE, UPDATE]
    condition:
      risk_level_gte: medium             # bulk delete/update without WHERE
    action: block
    reason: "Bulk write operations on production require WHERE clause"

  - name: "mask-pii-for-support"
    description: "Support sees masked PII"
    match:
      roles: ["support"]
      commands: [SELECT]
    masking:
      - column: "email"
        transformer: "partial_email"     # j***@example.com
      - column: "phone"
        transformer: "partial_phone"     # ***-***-1234
      - column: "tc_kimlik"
        transformer: "redact"            # ***********
      - column: "card_number"
        transformer: "partial_card"      # ****-****-****-5678
      - column: "salary"
        transformer: "redact"
      - column: "iban"
        transformer: "partial_iban"      # TR**-****-****-****-**89

  - name: "mask-salary-non-finance"
    description: "Only finance sees salary data"
    match:
      roles: ["!finance", "!dba"]
      tables: ["salaries", "payroll", "compensation"]
    masking:
      - column: "*"                      # all columns in these tables
        transformer: "redact"
    action: mask
    reason: "Financial data restricted to finance team"

  - name: "office-hours-contractors"
    description: "Contractors can only connect during office hours"
    match:
      roles: ["contractor"]
    condition:
      work_hours: "08:00-19:00"
      work_days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
    action: block
    reason: "Contractor access outside office hours"

  - name: "ip-restriction-production"
    description: "Production access only from office network"
    match:
      databases: ["production", "prod_*"]
    condition:
      source_ip_not_in: ["10.0.0.0/8", "172.16.0.0/12"]
    action: block
    reason: "Production access restricted to office network"

  - name: "row-limit-large-queries"
    description: "Limit result sets for non-DBA users"
    match:
      roles: ["!dba"]
      commands: [SELECT]
    max_rows: 50000

  - name: "default-allow-read"
    description: "Allow reads with standard logging"
    match:
      commands: [SELECT]
    action: allow
    log_level: standard

  - name: "default-allow-write"
    description: "Allow writes with verbose logging"
    match:
      commands: [INSERT, UPDATE, DELETE]
    action: allow
    log_level: verbose
```

### 5.5 Policy Evaluation Order

1. Connection-level policies (IP, time, role) evaluated at connect time.
2. Command-level policies evaluated per query.
3. First matching policy wins (top-to-bottom).
4. If no policy matches, `defaults.action` applies.
5. Masking rules are cumulative — multiple policies can add masking rules.

### 5.6 Policy Hot-Reload

Policy files are watched for changes.
On file change:
1. New policy set is parsed and validated.
2. If valid, atomically swapped with the current set.
3. Existing sessions continue with the new policy set on their next command.
4. If invalid, the current policy set remains active and an error is logged.

Implementation: polling-based (check mtime every 5 seconds). No external dependency needed.

### 5.7 Decision Cache

Policy decisions for identical contexts can be cached:
- Cache key: hash of (username, role, database, command_type, table_list)
- Cache TTL: configurable, default 60 seconds
- Cache invalidated on policy reload
- Cache size: bounded LRU, default 10,000 entries

The cache avoids re-evaluating the same policy rules for repeated query patterns.

---

## 6. Result Masking

### 6.1 Streaming Architecture

Masking operates in streaming mode.
No full result set buffering.
Each row is processed independently.

```
Backend ResultReader
    │
    ▼
MaskingResultReader (wraps original)
    │ for each row:
    │   read row from backend
    │   apply column transformers
    │   yield masked row
    ▼
Protocol Handler writes to client
```

Memory usage per session: O(single_row_size), not O(result_set_size).

### 6.2 Masking Decision Timing

The masking decision is made **once** at query time, not per row:

1. Client sends `SELECT name, email, salary FROM employees`
2. Policy engine returns masking rules: `email → partial_email, salary → redact`
3. Backend returns column metadata: `[name=col0, email=col1, salary=col2]`
4. Masking pipeline maps: `col1 → partial_email, col2 → redact`
5. For every subsequent row: apply transforms at col1 and col2.

Cost per row: one map lookup per masked column + transform function. **O(1) per row.**

### 6.3 Masking Transformers

```go
type Transformer interface {
    Transform(value []byte, metadata ColumnInfo) []byte
}
```

Built-in transformers:

| Name            | Input                      | Output                     |
|----------------|---------------------------|---------------------------|
| `redact`        | `anything`                 | `***`                      |
| `partial_email` | `john@example.com`         | `j***@example.com`         |
| `partial_phone` | `+905321234567`            | `***-***-4567`             |
| `partial_card`  | `4532123456785678`         | `****-****-****-5678`      |
| `partial_iban`  | `TR330006100519786457841326` | `TR**-****-****-****-**26` |
| `partial_tc`    | `12345678901`              | `*********01`              |
| `hash`          | `anything`                 | `sha256_prefix_8chars`     |
| `null`          | `anything`                 | `NULL`                     |
| `static`        | `anything`                 | configured static value    |

Custom transformers can be registered at startup.

### 6.4 Row Count Enforcement

If a policy sets `max_rows`, the streaming pipeline counts rows:
- After reaching the limit, remaining rows are discarded.
- A protocol-native notice/warning is sent to the client.
- The audit log records the truncation event.
- The backend query is NOT cancelled (to avoid connection state issues). Remaining data is read and discarded.

### 6.5 Column Auto-Detection (Phase 2)

Phase 1: Masking rules are column-name based (explicit configuration).
Phase 2: Automatic PII detection using pattern matching on column names and values:
- Column names matching patterns: `*email*`, `*phone*`, `*ssn*`, `*tc_kimlik*`, `*card*`, `*iban*`
- Value patterns: email regex, phone regex, credit card Luhn check
- This adds per-row computation cost. Opt-in per policy.

---

## 7. Session Management

### 7.1 Session Lifecycle

```
Client connects
    │
    ▼
Protocol handshake (auth exchange)
    │
    ▼
Session created {id, user, db, client_ip, start_time}
    │
    ▼
Session active — commands flow through pipeline
    │
    ▼
Session ends (client disconnect / timeout / admin kill)
    │
    ▼
Session record finalized {end_time, command_count, bytes_transferred}
```

### 7.2 Session Identity

Session identity is resolved from the protocol authentication:
- Username from the database login
- Client IP from the TCP connection
- Target database from the connection request

Role mapping is done by the policy engine:
- Username → role mapping defined in policy YAML
- Wildcard matching supported (`dev_*` matches `dev_john`)

Phase 2: External identity provider integration (LDAP, SSO token in connection metadata).

### 7.3 Session Store

Active sessions are stored in an in-memory concurrent map:

```go
type SessionStore struct {
    sessions sync.Map  // sessionID → *Session
}
```

The session store provides:
- List active sessions (for admin API)
- Get session by ID
- Kill session by ID (closes client and backend connections)
- Session metrics (count, duration histogram)

### 7.4 Session Timeout

- Idle timeout: configurable, default 30 minutes. If no command is received, session is closed.
- Max duration: configurable, default 8 hours. Absolute session lifetime limit.
- Timeout check runs every 30 seconds via a background goroutine.

---

## 8. Connection Pool

### 8.1 Pool Strategy

Argus maintains backend connection pools per target database.

Pool mode: **session-dedicated.**
Each client session gets a dedicated backend connection.
This preserves session state (transactions, SET variables, temp tables).

Why not shared pooling: Shared pooling requires resetting session state between uses. This is complex and error-prone. Session-dedicated is simpler and more correct for a security proxy where session isolation matters.

### 8.2 Pool Configuration

```yaml
pool:
  max_connections_per_target: 100    # max backend connections per DB target
  min_idle_connections: 5            # keep warm connections ready
  connection_max_lifetime: 1h        # recycle connections after this duration
  connection_timeout: 10s            # timeout for establishing backend connection
  health_check_interval: 30s         # backend health check frequency
```

### 8.3 Backend Health Check

Each pool periodically checks backend health:
- Sends a lightweight query (`SELECT 1` for PostgreSQL/MySQL, `SELECT 1` for MSSQL)
- If health check fails, marks target as unhealthy
- Unhealthy targets reject new connections with a clear error message
- Continues checking; marks healthy again when check passes

### 8.4 Connection Lifecycle

1. Client session established → pool.Acquire(target) called
2. If idle connection available → reuse (after health check)
3. If no idle connection and under max → create new backend connection
4. If at max → wait with timeout, then reject with "connection limit reached"
5. Client session ends → pool.Release(conn) called
6. Released connection is reset (if supported by protocol) and returned to idle pool
7. Connections exceeding max_lifetime are closed instead of returned

---

## 9. Audit Logging

### 9.1 Audit Event Types

```go
type AuditEventType int

const (
    AuditConnectionOpen    AuditEventType = iota  // client connected
    AuditConnectionClose                          // client disconnected
    AuditAuthSuccess                              // authentication succeeded
    AuditAuthFailure                              // authentication failed
    AuditCommandExecuted                          // command was forwarded to backend
    AuditCommandBlocked                           // command was blocked by policy
    AuditResultMasked                             // result had masking applied
    AuditResultTruncated                          // result was truncated by row limit
    AuditPolicyViolation                          // policy violation detected
    AuditSessionTimeout                           // session timed out
    AuditSessionKilled                            // session killed by admin
    AuditPolicyReloaded                           // policy files reloaded
)
```

### 9.2 Audit Event Structure

```go
type AuditEvent struct {
    ID          string          `json:"id"`           // unique event ID (ULID)
    Timestamp   time.Time       `json:"timestamp"`
    EventType   AuditEventType  `json:"event_type"`
    SessionID   string          `json:"session_id"`
    Username    string          `json:"username"`
    Roles       []string        `json:"roles"`
    ClientIP    string          `json:"client_ip"`
    Database    string          `json:"database"`
    Command     string          `json:"command,omitempty"`     // SQL (if log_level >= standard)
    CommandType string          `json:"command_type,omitempty"`
    Tables      []string        `json:"tables,omitempty"`
    RiskLevel   string          `json:"risk_level,omitempty"`
    PolicyName  string          `json:"policy_name,omitempty"`
    Action      string          `json:"action"`                // allow, block, mask
    RowCount    int64           `json:"row_count,omitempty"`   // rows returned
    ByteCount   int64           `json:"byte_count,omitempty"`  // bytes transferred
    Duration    time.Duration   `json:"duration,omitempty"`    // query execution time
    MaskedCols  []string        `json:"masked_cols,omitempty"` // which columns were masked
    Reason      string          `json:"reason,omitempty"`      // block/mask reason
    Error       string          `json:"error,omitempty"`
}
```

### 9.3 Log Levels

- **minimal:** connection open/close, auth events, blocked commands only
- **standard:** all of minimal + executed commands (SQL included), policy decisions
- **verbose:** all of standard + result row counts, byte counts, durations, masked column list

Configurable globally and per-policy.

### 9.4 Audit Output

Phase 1:
- JSON lines to file (rotated by size/time)
- JSON lines to stdout (for container deployments)

Phase 2:
- Syslog output (RFC 5424)
- SIEM webhook (HTTP POST batched events)
- Kafka producer

### 9.5 Audit Performance

Audit logging is **asynchronous.**
Events are sent to a buffered channel.
A dedicated goroutine reads from the channel and writes to output.
If the buffer is full, events are dropped with a counter (not blocking the proxy pipeline).

```go
auditChan := make(chan AuditEvent, 10000)
```

---

## 10. Configuration

### 10.1 Main Configuration File

```yaml
# argus.yaml

server:
  listeners:
    - address: ":15432"
      protocol: postgresql
      tls:
        enabled: true
        cert_file: "/etc/argus/server.crt"
        key_file: "/etc/argus/server.key"
    - address: ":13306"
      protocol: mysql
      tls:
        enabled: false

targets:
  - name: "production-pg"
    protocol: postgresql
    host: "db-prod.internal"
    port: 5432
    tls:
      enabled: true
      ca_file: "/etc/argus/db-ca.crt"
      verify: true

  - name: "staging-pg"
    protocol: postgresql
    host: "db-staging.internal"
    port: 5432

  - name: "production-mysql"
    protocol: mysql
    host: "mysql-prod.internal"
    port: 3306

routing:
  default_target: "production-pg"
  rules:
    - database: "staging_*"
      target: "staging-pg"
    - database: "mysql_*"
      target: "production-mysql"

policy:
  files:
    - "/etc/argus/policies/default.yaml"
    - "/etc/argus/policies/production.yaml"
  reload_interval: 5s

pool:
  max_connections_per_target: 100
  min_idle_connections: 5
  connection_max_lifetime: 1h
  connection_timeout: 10s
  health_check_interval: 30s

session:
  idle_timeout: 30m
  max_duration: 8h

audit:
  level: standard
  outputs:
    - type: file
      path: "/var/log/argus/audit.jsonl"
      rotation:
        max_size_mb: 100
        max_files: 10
    - type: stdout

  buffer_size: 10000
  sql_max_length: 4096       # truncate long SQL in logs

admin:
  enabled: false              # Phase 2
  address: ":9090"
  auth_token: ""

metrics:
  enabled: true
  address: ":9091"            # Prometheus metrics endpoint
```

### 10.2 Environment Variable Override

All config values can be overridden via environment variables:

```
ARGUS_SERVER_LISTENERS_0_ADDRESS=":15432"
ARGUS_TARGETS_0_HOST="db-prod.internal"
ARGUS_AUDIT_LEVEL="verbose"
```

Pattern: `ARGUS_` + YAML path in SCREAMING_SNAKE_CASE.

### 10.3 Routing Logic

When a client connects and authenticates with a specific database name:
1. Router checks routing rules in order.
2. First matching rule determines the target.
3. If no rule matches, `default_target` is used.
4. If no default target and no match, connection is rejected.

---

## 11. TLS / Security

### 11.1 Two-Segment TLS

```
Client ──[TLS Segment 1]──▶ Argus ──[TLS Segment 2]──▶ Database
```

- Segment 1: Client trusts Argus's certificate.
- Segment 2: Argus trusts the database's certificate.
- These are independent TLS sessions. Argus terminates and re-initiates.

### 11.2 Client-Side TLS

Argus presents its own certificate to clients.
Clients must be configured to trust this certificate (or use a shared CA).
This is the primary migration requirement: update client connection config to point to Argus and trust its CA.

### 11.3 Backend TLS

Argus connects to backends with TLS when configured.
Certificate verification is recommended for production.
CA certificate path is specified per target.

### 11.4 Authentication Passthrough vs Proxy Auth

**Passthrough mode (default):**
Client credentials are forwarded to the backend.
Argus sees the username but does not store passwords.
Backend performs the actual authentication.
Argus observes the auth result.

**Proxy auth mode (Phase 2):**
Argus authenticates the client independently (own user registry or external IdP).
Argus uses a shared service account to connect to the backend.
This decouples client identity from database credentials.
Enables just-in-time access: backend credentials are managed by Argus, not by users.

### 11.5 Credential Security

- No plaintext credentials in config files. Environment variables or secrets manager integration (Phase 2).
- Backend connection credentials can use `$ENV{VARIABLE}` syntax in config.
- Audit logs never contain passwords or credentials.
- SQL in audit logs is sanitized: string literals are replaced with `$1`, `$2`, etc.

---

## 12. Metrics and Observability

### 12.1 Prometheus Metrics

Argus exposes metrics at the configured metrics endpoint:

**Connection metrics:**
- `argus_active_sessions` (gauge) — current active sessions
- `argus_connections_total` (counter) — total connections, label: {status: success|failed|rejected}
- `argus_connection_duration_seconds` (histogram) — session durations

**Command metrics:**
- `argus_commands_total` (counter) — labels: {type, action, database}
- `argus_command_duration_seconds` (histogram) — query execution time
- `argus_commands_blocked_total` (counter) — labels: {policy, reason}

**Result metrics:**
- `argus_result_rows_total` (counter) — total rows returned
- `argus_result_masked_total` (counter) — total rows with masking applied
- `argus_result_truncated_total` (counter) — queries truncated by row limit

**Pool metrics:**
- `argus_pool_active_connections` (gauge) — per target
- `argus_pool_idle_connections` (gauge) — per target
- `argus_pool_wait_duration_seconds` (histogram) — time waiting for connection

**Policy metrics:**
- `argus_policy_evaluations_total` (counter) — labels: {policy, decision}
- `argus_policy_cache_hits_total` (counter)
- `argus_policy_cache_misses_total` (counter)

### 12.2 Health Endpoint

`GET /healthz` on the admin port returns:
- Overall status (healthy/degraded/unhealthy)
- Per-target backend health
- Active session count
- Policy load status

---

## 13. Development Phases

### Phase 1 — MVP

**Goal:** Working PostgreSQL proxy with policy enforcement and audit logging.
**Scope:**

Core:
- TCP listener with TLS support
- PostgreSQL Simple Query protocol (auth + query + result)
- Auth passthrough mode
- Session lifecycle management

Inspection:
- SQL tokenizer
- Command classifier (SELECT/INSERT/UPDATE/DELETE/DDL/DCL)
- Table name extraction
- Risk level assignment
- Dangerous pattern detection

Policy:
- YAML policy loader with hot-reload
- Role-based rule matching
- Command-type rules
- Time-based rules
- IP-based rules
- First-match evaluation

Masking:
- Streaming result masking
- Column-name-based masking rules
- Built-in transformers (redact, partial_email, partial_phone, partial_card, partial_tc, partial_iban)
- Row count enforcement

Audit:
- Structured JSON audit log
- File and stdout output
- Async buffered writing
- Three log levels (minimal, standard, verbose)

Pool:
- Session-dedicated backend connections
- Max connection limit per target
- Health checking
- Connection timeout

Config:
- YAML configuration
- Environment variable override
- Multi-target routing

Observability:
- Prometheus metrics endpoint
- Health check endpoint

**Deliverable:** Single `argus` binary. Zero external dependencies.

### Phase 2 — Production Hardening

- MySQL wire protocol support
- PostgreSQL Extended Query protocol (prepared statements)
- PostgreSQL COPY protocol
- Remote Policy API (HTTP) with YAML fallback
- Proxy auth mode (decouple client identity from DB credentials)
- Admin REST API (list sessions, kill session, view audit, manage policies)
- SIEM export (webhook, syslog)
- Column auto-detection for PII
- Connection pooling improvements (shared mode option)
- Graceful shutdown and connection draining
- Signal handling (SIGHUP for config reload)

### Phase 3 — Enterprise Features

- MSSQL TDS protocol support
- LDAP/SSO identity integration
- Approval workflows for high-risk commands
- Live session monitoring (WebSocket stream)
- Query replay and forensics
- Rate limiting per user/role
- Multi-instance clustering (shared session store)
- Certificate rotation without downtime

### Phase 4 — Extended Platform

- Oracle TNS support (may require Oracle Instant Client)
- MongoDB wire protocol support
- Web dashboard UI
- Terraform provider for policy-as-code
- Kubernetes operator
- Plugin system for custom transformers and policy providers
- Data classification engine (auto-tag PII columns)

---

## 14. Non-Goals (MVP)

These are explicitly out of scope for Phase 1:
- Query rewriting or query optimization
- Load balancing across database replicas
- Database migration or schema management
- Full SQL parsing or semantic analysis
- Query caching or result caching
- Database failover or high availability
- User management UI
- Multi-tenancy
- Extended Query protocol (prepared statements)
- COPY protocol
- Stored procedure content inspection
- Dynamic SQL analysis inside stored procedures

---

## 15. Migration Path

### 15.1 Application Migration

For existing applications to use Argus:
1. Deploy Argus with target database configuration.
2. Change application connection string: point to Argus address and port.
3. If TLS is enabled, configure application to trust Argus's CA.
4. No application code changes required. Protocol-native compatibility.

### 15.2 Gradual Rollout

Argus can be deployed in **audit-only mode** first:
- All policies set to `action: audit`
- No blocking, no masking
- All commands are logged
- Teams review audit logs to understand access patterns
- Policies are tuned based on real data
- Blocking and masking enabled incrementally

This is the recommended deployment strategy.

---

## 16. Performance Targets

| Metric                        | Target                        |
|------------------------------|-------------------------------|
| Added latency per query       | < 1ms for allow decisions     |
| Added latency with masking    | < 5ms per 1000 rows masked    |
| Max concurrent sessions       | 10,000+                       |
| Memory per session            | < 64KB baseline               |
| Audit throughput              | 100,000 events/sec            |
| Policy evaluation time        | < 100μs (cached)              |
| Startup time                  | < 2 seconds                   |
| Binary size                   | < 20MB                        |

---

## 17. Testing Strategy

### 17.1 Unit Tests

Every module has unit tests:
- Protocol codec: encode/decode roundtrip for every message type
- Tokenizer: SQL parsing edge cases (comments, quotes, multi-statement)
- Policy engine: rule matching, first-match semantics, edge cases
- Masking transformers: each transformer with various inputs
- Session store: concurrent access patterns

### 17.2 Integration Tests

- Full proxy pipeline: client → proxy → test PostgreSQL → response
- Authentication flows: cleartext, MD5, SCRAM-SHA-256
- Policy enforcement: connect, send blocked query, verify error response
- Masking: send SELECT, verify masked columns in response
- Audit: verify audit events are written for each action

### 17.3 Protocol Conformance Tests

- Use standard database client libraries (pgx, lib/pq) as test clients
- Verify that the proxy is transparent to client libraries
- Test with ORMs (GORM, sqlx) to ensure compatibility
- Test with GUI tools (pgAdmin, DBeaver) to ensure usability

### 17.4 Performance Tests

- Benchmark: queries per second through proxy vs direct connection
- Benchmark: latency distribution (p50, p95, p99)
- Benchmark: memory usage under sustained load
- Benchmark: 10,000 concurrent connections

---

## 18. Naming and Branding

**Project name:** Argus
**Full name:** Argus — The Hundred-Eyed Database Guardian
**Origin:** Argus Panoptes (Ἄργος Πανόπτης) — the all-seeing giant of Greek mythology. He never sleeps. He sees everything.
**Tagline:** "Know who connects. Control what they do. Protect what they see."
**Binary name:** `argus`
**Config file:** `argus.yaml`
**Default ports:** 15432 (PG), 13306 (MySQL), 11433 (MSSQL)
**Log prefix:** `[argus]`
**Repo:** `github.com/ersinkoc/argus`

---

*This specification is the foundation for IMPLEMENTATION.md and TASKS.md.*
*No code is written before this spec is reviewed and approved.*
