# Argus — Architecture Document

> Database Firewall & Access Proxy — Zero external dependencies, single binary, 4 protocols

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Component Wiring (main.go)](#3-component-wiring)
4. [Core Proxy Engine](#4-core-proxy-engine)
5. [Protocol Layer](#5-protocol-layer)
6. [Inspection & Classification](#6-inspection--classification)
7. [Policy Engine](#7-policy-engine)
8. [Masking Pipeline](#8-masking-pipeline)
9. [Audit System](#9-audit-system)
10. [Session Management](#10-session-management)
11. [Connection Pooling](#11-connection-pooling)
12. [Rate Limiting](#12-rate-limiting)
13. [Metrics & Observability](#13-metrics--observability)
14. [Admin API](#14-admin-api)
15. [Authentication Providers](#15-authentication-providers)
16. [Configuration System](#16-configuration-system)
17. [Kubernetes Deployment](#17-kubernetes-deployment)
18. [Package Dependency Graph](#18-package-dependency-graph)

---

## 1. System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ARGUS PROXY                                 │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │PostgreSQL│  │  MySQL   │  │  MSSQL   │  │ MongoDB  │  Listeners│
│  │ :15432   │  │ :13306   │  │ :11433   │  │ :17017   │           │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       │              │              │              │                 │
│       └──────────────┴──────┬───────┴──────────────┘                │
│                             │                                       │
│  ┌──────────────────────────▼──────────────────────────────────┐    │
│  │                    PROXY PIPELINE                            │    │
│  │                                                              │    │
│  │  Handshake → Classify → Cost → Policy → Rate Limit          │    │
│  │    → Anomaly → [Rewrite] → Forward → Mask → Audit           │    │
│  └──────────────────────────┬──────────────────────────────────┘    │
│                             │                                       │
│  ┌──────────┐  ┌──────────┐│ ┌──────────┐  ┌──────────┐           │
│  │ Pool(PG) │  │Pool(MySQL││ │Pool(MSSQL│  │  Direct  │  Backends │
│  └────┬─────┘  └────┬─────┘│ └────┬─────┘  └────┬─────┘           │
│       │              │      │      │              │                 │
└───────┼──────────────┼──────┼──────┼──────────────┼─────────────────┘
        │              │      │      │              │
   ┌────▼────┐   ┌────▼────┐ │ ┌────▼────┐   ┌────▼────┐
   │ Postgres│   │  MySQL  │ │ │  MSSQL  │   │ MongoDB │
   │ Server  │   │ Server  │ │ │ Server  │   │ Server  │
   └─────────┘   └─────────┘ │ └─────────┘   └─────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Admin API :9091   │
                    │  /metrics /ui /api │
                    └───────────────────┘
```

### Key Characteristics

- **Zero external dependencies** — stdlib only, no CGO, single ~8MB binary
- **4 database protocols** — PostgreSQL, MySQL, MSSQL, MongoDB
- **15 policy condition types** including SQL injection detection
- **8 masking transformers** with PII auto-detection
- **Streaming architecture** — O(1) memory per row for masking
- **Async audit logging** — buffered channel, drops on overflow
- **Policy caching** — LRU with 60s TTL, SHA256 cache keys

---

## 2. High-Level Architecture

### Request Flow (per command)

```
                          ┌──────────────┐
                          │   Client     │
                          └──────┬───────┘
                                 │
                    ┌────────────▼────────────┐
                    │   1. READ COMMAND       │  ReadCommand()
                    │   Parse protocol msg    │  Extract SQL
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   2. INSPECT            │  Classify()
                    │   Command type, tables  │  Risk level
                    │   HasWhere, columns     │  Confidence
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   3. COST ESTIMATE      │  EstimateCost()
                    │   Heuristic 0-100       │  Subquery, JOIN,
                    │   Table count, SELECT * │  GROUP BY, etc.
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   4. EXPLAIN (optional)  │  ExplainPG()
                    │   Real planner cost     │  ExplainMySQL()
                    │   PostgreSQL + MySQL    │  500ms timeout
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   5. POLICY EVALUATE    │  Engine.Evaluate()
                    │   15 condition types    │  LRU cache (60s)
                    │   Role-based matching   │  First match wins
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   6. RATE LIMIT         │  Limiter.Allow()
                    │   Token bucket          │  Per-policy key
                    │   Per-user tracking     │  Auto-cleanup 5m
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   7. ANOMALY CHECK      │  AnomalyDetector
                    │   Behavioral profiling  │  Record + Check
                    │   Per-user statistics   │
                    └────────────┬────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │         DECISION             │
                  ├──────┬──────┬──────┬────────┤
                  │BLOCK │ MASK │ALLOW │ AUDIT  │
                  └──┬───┴──┬───┴──┬───┴────┬───┘
                     │      │      │        │
              ┌──────▼──┐   │   ┌──▼────────▼──┐
              │  Error   │   │   │  8. REWRITE  │
              │  to      │   │   │  Auto-LIMIT  │
              │  Client  │   │   │  WHERE inject│
              └──────────┘   │   └──────┬───────┘
                             │          │
                    ┌────────▼──────────▼──┐
                    │  9. FORWARD TO       │  ForwardCommand()
                    │     BACKEND          │
                    └────────────┬─────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  10. READ & FORWARD     │  ReadAndForwardResult()
                    │      RESULT             │
                    │  ┌───────────────────┐  │
                    │  │  Masking Pipeline │  │  Policy rules +
                    │  │  PII Auto-detect  │  │  PII patterns
                    │  │  Row limit check  │  │  8 transformers
                    │  └───────────────────┘  │
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
  ┌──────▼──────┐  ┌────────────▼────────┐  ┌──────────▼──────┐
  │ 11. METRICS │  │ 12. AUDIT LOG       │  │ 13. BROADCAST   │
  │ Per-DB stats│  │ Async buffered      │  │ WebSocket       │
  │ Latency     │  │ File + Webhook      │  │ Live events     │
  │ Protocol    │  │ Level filtering     │  │                 │
  └─────────────┘  └─────────────────────┘  └─────────────────┘
```

---

## 3. Component Wiring

### Startup Sequence (`cmd/argus/main.go`)

```
1.  Parse flags (--config, --version, --validate)
2.  Load config → expandEnvInConfig → applyEnvOverrides → Validate
3.  Resolve policy file paths (relative → absolute)
4.  Create audit logger (async, buffered channel)
5.  Add file/stdout writers with rotation
6.  Start audit logger goroutine
7.  Create policy loader (file watcher, 5s interval)
8.  Load initial policies
9.  Create policy engine (with LRU cache)
10. Create proxy (pools, listeners, session manager)
11. Set query recorder (forensic recording)
12. Set SIEM webhook writer (batched HTTP POST)
13. Set session limiter (per-user concurrency)
14. Set query rewriter (auto-LIMIT, WHERE injection)
15. Set slow query logger
16. Start proxy (pools → listeners → session manager)
17. Create admin/metrics server
18. Wire callbacks: policy reload, dry-run, config export,
    policy validate, classify, plugin list, session kill
19. Start admin server
20. Wait for signals (SIGINT → shutdown, SIGHUP → reload)
```

### Shutdown Sequence

```
1.  Receive SIGINT/SIGTERM
2.  Stop rate limiter cleanup goroutine
3.  Stop accepting new connections (close listeners)
4.  Drain active sessions (10s timeout, then force-close)
5.  Stop session manager (timeout checker goroutine)
6.  Close connection pools
7.  Stop admin server
8.  Stop policy file watcher
9.  Flush webhook writer (pending events)
10. Close audit logger (drain event channel)
```

---

## 4. Core Proxy Engine

### Package: `internal/core/`

```
internal/core/
├── pipeline.go     Proxy struct, connection handling, command loop
├── listener.go     TCP listener with TLS support
├── router.go       Protocol handler dispatch
├── tls.go          TLS config builder (server + client)
├── approval.go     Approval workflow manager
├── certreload.go   TLS certificate hot-reloading
└── banner.go       Startup banner
```

### Proxy Struct

```go
type Proxy struct {
    cfg             *config.Config
    router          *Router                       // protocol dispatch
    sessionManager  *session.Manager              // session lifecycle
    policyEngine    *policy.Engine                // policy evaluation
    auditLogger     *audit.Logger                 // async audit
    pools           map[string]*pool.Pool         // per-target pools
    rateLimiters    map[string]*ratelimit.Limiter // per-policy limiters
    listeners       []*Listener                   // TCP listeners
    piiDetector     *masking.PIIDetector          // PII auto-detect
    anomalyDetector *inspection.AnomalyDetector   // behavioral analysis
    approvalManager *ApprovalManager              // approval workflow
    queryRecorder   *audit.QueryRecorder          // forensic recording
    slowQueryLogger *audit.SlowQueryLogger        // latency tracking
    rewriter        *inspection.Rewriter          // query transformation
    sessionLimiter  *session.ConcurrencyLimiter   // per-user limits
    onEvent         func(any)                     // WebSocket broadcast
    rlCleanupStop   chan struct{}                  // cleanup signal
}
```

### Connection Lifecycle

```
Client TCP Connect
       │
       ▼
┌─ handleConnection(clientConn, protocolName) ──────────────┐
│                                                            │
│  1. Resolve target (protocol match or routing rules)       │
│  2. Log ConnectionOpen audit event                         │
│  3. Acquire backend connection:                            │
│     ├─ PostgreSQL → pool.Acquire()                         │
│     └─ MySQL/MSSQL → net.Dial() (server-speaks-first)     │
│  4. handler.Handshake(client, backend) → session.Info      │
│  5. Re-resolve target by database name (if routing rules)  │
│  6. Check concurrent session limit                         │
│  7. Create session in manager                              │
│  8. Resolve user roles from policy                         │
│  9. Enter commandLoop()                                    │
│  10. Remove session, log ConnectionClose                   │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### Router

```go
type Router struct {
    handlers map[string]protocol.Handler
}
// Registers: "postgresql", "mysql", "mssql", "mongodb"
// GetHandler(name) → Handler
// DetectHandler(peek) → Handler  (auto-detect, not wired)
```

---

## 5. Protocol Layer

### Package: `internal/protocol/`

```
internal/protocol/
├── handler.go          Handler interface + ResultStats
├── pg/
│   ├── handler.go      PostgreSQL handler (client-speaks-first)
│   ├── codec.go        Wire format: ReadMessage, WriteMessage, EncodeMessage
│   ├── query.go        ReadQueryCommand (Simple + Extended Query)
│   ├── result.go       ForwardResult with masking pipeline
│   ├── auth.go         Auth passthrough (cleartext, MD5, SASL)
│   ├── extended.go     Parse/Bind/Execute decoding
│   └── copy.go         COPY IN/OUT relay
├── mysql/
│   ├── handler.go      MySQL handler (server-speaks-first)
│   ├── codec.go        Packet format: ReadPacket, WritePacket
│   ├── prepared.go     PreparedStatement store (ID → SQL mapping)
│   └── result.go       Result set forwarding with masking
├── mssql/
│   ├── handler.go      MSSQL TDS handler (server-speaks-first)
│   ├── codec.go        TDS packets: ReadAllPackets, token types
│   └── result.go       Token-stream result masking
└── mongodb/
    ├── handler.go      MongoDB handler (OP_MSG)
    └── codec.go        BSON extraction, OP_MSG wire format
```

### Handler Interface

```go
type Handler interface {
    Name() string
    DetectProtocol(peek []byte) bool
    Handshake(ctx, client, backend) (*session.Info, error)
    ReadCommand(ctx, client) (*inspection.Command, []byte, error)
    ForwardCommand(ctx, rawMsg, backend) error
    ReadAndForwardResult(ctx, backend, client, *masking.Pipeline) (*ResultStats, error)
    WriteError(ctx, client, code, message) error
    RebuildQuery(rawMsg []byte, newSQL string) []byte
    Close() error
}

type ResultStats struct {
    RowCount   int64
    ByteCount  int64
    Truncated  bool
    MaskedCols []string
}
```

### Protocol Comparison

```
┌─────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
│             │  PostgreSQL  │    MySQL     │    MSSQL     │   MongoDB    │
├─────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
│ First speak │ Client       │ Server       │ Server       │ Client       │
│ Pooling     │ Pool (reuse) │ Fresh conn   │ Fresh conn   │ Fresh conn   │
│ Encoding    │ Big-endian   │ Little-end   │ Big-endian   │ BSON (LE)    │
│ Auth        │ MD5/SASL     │ SHA2/native  │ TDS7 Login   │ In-band SASL │
│ Query msg   │ 'Q' or Parse │ COM_QUERY    │ SQLBatch     │ OP_MSG find  │
│ Prep stmt   │ Parse/Bind   │ COM_PREPARE  │ RPC          │ N/A          │
│ COPY        │ Yes          │ No           │ No           │ No           │
│ SSL         │ SSLRequest   │ N/A          │ Pre-Login    │ N/A          │
│ Masking     │ Full         │ Full         │ Token-based  │ Passthrough  │
│ Error fmt   │ ErrorResp    │ ERR packet   │ ERROR token  │ BSON error   │
└─────────────┴──────────────┴──────────────┴──────────────┴──────────────┘
```

### PostgreSQL Wire Format

```
Frontend Messages (Client → Server):
  Q  (0x51)  Simple Query      : Q + len(4) + sql\0
  P  (0x50)  Parse             : P + len(4) + stmt\0 + query\0 + params
  B  (0x42)  Bind              : B + len(4) + portal\0 + stmt\0 + ...
  E  (0x45)  Execute           : E + len(4) + portal\0 + max_rows(4)
  S  (0x53)  Sync              : S + len(4)
  X  (0x58)  Terminate         : X + len(4)
  p  (0x70)  Password          : p + len(4) + password\0

Backend Messages (Server → Client):
  R  (0x52)  AuthRequest       : R + len(4) + type(4) [+ salt/data]
  T  (0x54)  RowDescription    : T + len(4) + ncols(2) + [col_def]*
  D  (0x44)  DataRow           : D + len(4) + ncols(2) + [len(4)+data]*
  C  (0x43)  CommandComplete   : C + len(4) + tag\0
  Z  (0x5A)  ReadyForQuery     : Z + len(4) + status(1)  [I/T/E]
  E  (0x45)  ErrorResponse     : E + len(4) + fields\0
  G  (0x47)  CopyInResponse    : G + len(4) + ...
  H  (0x48)  CopyOutResponse   : H + len(4) + ...
```

### MySQL Wire Format

```
Packet: length(3 LE) + seq_id(1) + payload

Commands:
  0x01  COM_QUIT           : close connection
  0x02  COM_INIT_DB        : USE database
  0x03  COM_QUERY          : text query (payload[1:] = SQL)
  0x0E  COM_PING           : keepalive
  0x16  COM_STMT_PREPARE   : prepare (payload[1:] = SQL)
  0x17  COM_STMT_EXECUTE   : execute (payload[1:5] = stmtID LE)
  0x19  COM_STMT_CLOSE     : close statement

Responses:
  0x00  OK      : affected_rows + last_insert_id + status + warnings
  0xFF  ERR     : error_code(2 LE) + '#' + state(5) + message
  0xFE  EOF     : warnings(2 LE) + status(2 LE)
  N     ResultSet: column_count → col_defs → EOF → rows → EOF
```

### MSSQL TDS Format

```
TDS Header (8 bytes):
  type(1) + status(1) + length(2 BE) + spid(2) + seq(1) + window(1)

Packet Types:
  0x01  SQLBatch    : ALL_HEADERS(4 LE) + SQL_UTF16LE
  0x04  Reply       : token stream
  0x10  TDS7Login   : credentials
  0x12  PreLogin    : version negotiation

Token Stream:
  0x81  COLMETADATA : column definitions
  0xD1  ROW         : typed column values
  0xFD  DONE        : batch complete + row count(8 LE)
  0xAA  ERROR       : error_number(4 LE) + state + class + message
  0xAD  LOGINACK    : login successful
  0xE3  ENVCHANGE   : database/charset change
```

### MongoDB OP_MSG Format

```
Header (16 bytes LE):
  messageLength(4) + requestID(4) + responseTo(4) + opCode(4)

OP_MSG (opCode = 2013):
  flagBits(4) + sections...
  Section Kind 0: body BSON document
  Section Kind 1: document sequence

BSON Element: type(1) + key\0 + value
  0x01 Double    0x02 String    0x03 Document
  0x04 Array     0x10 Int32     0x12 Int64

Command detection: first key in body BSON = command name
  find, aggregate → SELECT    insert → INSERT
  update → UPDATE             delete → DELETE
  drop, createIndexes → DDL   ping, hello → ADMIN
```

---

## 6. Inspection & Classification

### Package: `internal/inspection/`

```
internal/inspection/
├── classifier.go    Command type detection, table/column extraction
├── tokenizer.go     SQL tokenizer (keywords, identifiers, strings, numbers)
├── cost.go          Heuristic cost estimation (0-100 score)
├── anomaly.go       Behavioral anomaly detection (per-user profiling)
├── fingerprint.go   Query fingerprint hashing (normalize → SHA256)
├── splitter.go      Multi-statement SQL splitting
├── rewrite.go       Query rewriting (auto-LIMIT, WHERE injection)
└── extractor.go     Table/column name extraction
```

### Command Classification

```go
type CommandType int
const (
    CommandUNKNOWN CommandType = iota
    CommandSELECT       // read
    CommandINSERT       // write
    CommandUPDATE       // write
    CommandDELETE       // write
    CommandDDL          // CREATE, ALTER, DROP, TRUNCATE
    CommandDCL          // GRANT, REVOKE
    CommandTCL          // BEGIN, COMMIT, ROLLBACK
    CommandADMIN        // SET, SHOW, EXPLAIN
    CommandUTILITY      // COPY, VACUUM, ANALYZE
)

type RiskLevel int
const (
    RiskNone RiskLevel = iota
    RiskLow         // simple reads
    RiskMedium      // writes with WHERE
    RiskHigh        // DDL, bulk writes, no WHERE
    RiskCritical    // DROP, TRUNCATE, multi-table DELETE
)

type Command struct {
    Type       CommandType
    Raw        string        // original SQL
    Tables     []string      // extracted table names
    Columns    []string      // extracted column names
    RiskLevel  RiskLevel
    HasWhere   bool
    Confidence float64       // 0.0-1.0 classification confidence
}
```

### Cost Estimation

```
Input: Command → Tokenize → Analyze structural features

Scoring factors:
  +10 per table (if >1)    +15 JOIN
  +20 subquery (SELECT     +10 ORDER BY
      inside parens)       +15 GROUP BY
  +10 DISTINCT             +15 UNION
  +5  SELECT *             +20 no WHERE clause

Output: CostEstimate {Score: 0-100, Factors: [...], Has*: bool}
```

### Anomaly Detection

```go
type AnomalyDetector struct {
    profiles map[string]*UserProfile  // per-user stats
    // ...
}
// Record(username, commandType, tables) — update profile
// Check(username, commandType, tables) — detect deviation
```

### Query Fingerprinting

```
"SELECT * FROM users WHERE id = 42"
  → normalize: "SELECT * FROM users WHERE id = ?"
  → SHA256 hash → "a3f2b1c..."
```

---

## 7. Policy Engine

### Package: `internal/policy/`

```
internal/policy/
├── engine.go       Engine struct, Evaluate(), cache
├── types.go        PolicySet, Context, Decision, Action
├── matcher.go      15 condition matchers + SQL injection detection
├── loader.go       File watcher, hot-reload, SetCurrent()
├── dryrun.go       Dry-run simulation (DryRun, DryRunJSON)
├── validator.go    Policy validation (structure + cross-reference)
└── cache.go        LRU decision cache (10K entries, 60s TTL)
```

### Evaluation Flow

```
Context ──► Cache Lookup (SHA256 key)
               │
          ┌────┴────┐
          │hit      │miss
          ▼         ▼
       Return   Resolve User Roles
                    │
                Iterate Policies (top → bottom)
                    │
                For each policy:
                ├── Match roles?      (wildcard, negation with !)
                ├── Match commands?   (SELECT, INSERT, DDL, ...)
                ├── Match databases?  (wildcard patterns)
                ├── Match tables?     (wildcard patterns)
                └── Match conditions? (15 condition types)
                    │
                First match wins → Decision
                    │
                Cache decision (60s TTL)
                    │
                Return Decision {Action, MaskingRules, Reason, ...}
```

### 15 Condition Types

```
┌────┬───────────────────┬───────────┬──────────────────────────────────┐
│ #  │ Condition         │ Type      │ Matching Logic                   │
├────┼───────────────────┼───────────┼──────────────────────────────────┤
│  1 │ sql_contains      │ []string  │ ALL strings in SQL (AND)         │
│  2 │ sql_not_contains  │ []string  │ ANY string missing (OR)          │
│  3 │ sql_regex         │ []string  │ ALL patterns match               │
│  4 │ sql_injection     │ bool      │ Detect 8 SQLi pattern categories │
│  5 │ risk_level_gte    │ string    │ Risk ≥ threshold                 │
│  6 │ max_cost_gte      │ int       │ Heuristic cost ≥ threshold       │
│  7 │ plan_cost_gte     │ float64   │ EXPLAIN cost ≥ threshold         │
│  8 │ max_query_length  │ int       │ SQL bytes ≥ limit                │
│  9 │ max_tables        │ int       │ Table count ≥ limit              │
│ 10 │ max_joins         │ int       │ JOIN count ≥ limit               │
│ 11 │ require_where     │ bool      │ Write ops must have WHERE        │
│ 12 │ work_hours        │ string    │ Outside HH:MM-HH:MM = match     │
│ 13 │ work_days         │ []string  │ Not on listed days = match       │
│ 14 │ source_ip_in      │ []string  │ Client IP in CIDR ranges         │
│ 15 │ source_ip_not_in  │ []string  │ Client IP in blocked ranges      │
└────┴───────────────────┴───────────┴──────────────────────────────────┘
```

### SQL Injection Detection Patterns

```
Category          │ Examples
──────────────────┼──────────────────────────────────
Tautology         │ OR 1=1, OR 'a'='a', OR TRUE
UNION-based       │ UNION SELECT, UNION ALL SELECT
Comment-based     │ '; --, '; #, /* ... */
Stacked queries   │ ; DROP TABLE, ; DELETE FROM
Blind injection   │ SLEEP(), PG_SLEEP(), WAITFOR DELAY
Encoding tricks   │ CHAR(), CHR() with suspicious context
System commands   │ XP_CMDSHELL, INTO OUTFILE, LOAD_FILE()
Schema probing    │ information_schema, pg_catalog, sys.objects
```

### Policy JSON Structure

```json
{
  "version": "1",
  "defaults": {
    "action": "audit",
    "log_level": "standard",
    "max_rows": 100000
  },
  "roles": {
    "admin": { "users": ["admin", "postgres"] },
    "support": { "users": ["support_*"] }
  },
  "policies": [
    {
      "name": "block-destructive-ddl",
      "match": {
        "roles": ["!admin"],
        "commands": ["DDL"]
      },
      "condition": {
        "sql_contains": ["DROP", "TRUNCATE"]
      },
      "action": "block",
      "reason": "Destructive DDL requires admin role"
    }
  ]
}
```

---

## 8. Masking Pipeline

### Package: `internal/masking/`

```
internal/masking/
├── pipeline.go       Pipeline struct, ProcessRow(), streaming
├── transformers.go   8 built-in transformers
└── pii.go            PII auto-detection (column name patterns)
```

### Pipeline Architecture

```
RowDescription (column names)
       │
       ▼
┌──────────────────────┐
│  1. Column Matching  │  Match policy masking rules
│     by name/pattern  │  to column indices
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  2. PII Auto-Detect  │  Pattern-based column name
│     (optional)       │  analysis (email, phone, etc.)
└──────────┬───────────┘
           │
           ▼
For each DataRow:
┌──────────────────────┐
│  3. Parse Fields     │  Protocol-specific field
│     from wire format │  extraction
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  4. Apply Transform  │  Per-column transformer
│     per column       │  (skip NULLs)
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  5. Row Limit Check  │  MaxRows enforcement
│                      │  (truncation)
└──────────┬───────────┘
           │
           ▼
Rebuild DataRow in wire format
```

### 8 Transformers

```
┌─────────────────┬──────────────────────────────────────────┐
│ Transformer     │ Example                                  │
├─────────────────┼──────────────────────────────────────────┤
│ redact          │ "John Doe" → "████████"                  │
│ partial_email   │ "john@example.com" → "j***@e***.com"     │
│ partial_phone   │ "+905551234567" → "+90555***4567"         │
│ partial_card    │ "4111111111111111" → "411111******1111"   │
│ partial_iban    │ "TR330006100519..." → "TR33****...19"     │
│ hash            │ "sensitive" → "a3f2b1c4d5..."  (SHA256)  │
│ truncate        │ "long text here" → "long..."             │
│ noise           │ "42.50" → "41.87" (±5% random)          │
└─────────────────┴──────────────────────────────────────────┘
```

### PII Auto-Detection Patterns

```
Column patterns → Transformer:
  *email*          → partial_email
  *phone*, *tel*   → partial_phone
  *card*, *credit* → partial_card
  *iban*           → partial_iban
  *ssn*, *tc_*     → redact
  *password*       → redact
  *salary*, *wage* → redact
  *address*        → truncate
```

---

## 9. Audit System

### Package: `internal/audit/`

```
internal/audit/
├── event.go        Event struct, EventType enum, LogLevel
├── logger.go       Async logger (buffered channel + writers)
├── rotation.go     Log file rotation (size-based)
├── webhook.go      SIEM webhook (batched HTTP POST)
├── recorder.go     Forensic query recording (JSONL)
├── search.go       Audit log search (text scan)
├── replay.go       Session replay from recordings
├── compaction.go   Log compaction (remove old entries)
└── slowlog.go      Slow query detection & logging
```

### Event Types

```go
const (
    ConnectionOpen   // client connected (logged at minimal level)
    ConnectionClose  // client disconnected
    AuthSuccess      // authentication succeeded
    AuthFailure      // authentication failed
    CommandExecuted  // command forwarded to backend
    CommandBlocked   // command blocked by policy
    ResultMasked     // result had masking applied
    ResultTruncated  // result hit row limit
    PolicyViolation  // policy violation detected
    SessionTimeout   // session timed out (idle or max duration)
    SessionKilled    // session killed by admin API
    PolicyReloaded   // policy files hot-reloaded
)
```

### Log Level Filtering

```
┌──────────┬───────────────────────────────────────────────────┐
│ Level    │ Events Logged                                     │
├──────────┼───────────────────────────────────────────────────┤
│ minimal  │ connection_open/close, auth_*, command_blocked,   │
│          │ session_timeout/killed, policy_reloaded           │
├──────────┼───────────────────────────────────────────────────┤
│ standard │ All events (default)                              │
├──────────┼───────────────────────────────────────────────────┤
│ verbose  │ All events (same as standard; Event struct        │
│          │ carries RowCount/ByteCount/Duration regardless)   │
└──────────┴───────────────────────────────────────────────────┘
```

### Logger Architecture

```
Log(event)
    │
    ├── Check closed flag
    ├── Check level filter (minimal = skip non-essential events)
    ├── Generate ID (crypto/rand hex)
    ├── Set timestamp
    ├── Truncate long SQL
    │
    ▼
eventCh (buffered channel, default 10000)
    │                         ▲
    │ [channel full]          │ dropped counter++
    ▼
writeLoop() goroutine
    │
    ├── JSON marshal
    ├── Write to all writers (file, stdout, webhook)
    └── Repeat until closed
```

---

## 10. Session Management

### Package: `internal/session/`

```
internal/session/
├── manager.go     Manager struct, Session struct, Create/Remove/Kill
└── limiter.go     ConcurrencyLimiter (per-user session limits)
```

### Session Struct

```go
type Session struct {
    ID           string
    Username     string
    Database     string
    ClientIP     net.IP
    Roles        []string
    AuthMethod   string            // cleartext, md5, sasl, tds7, mongodb
    StartTime    time.Time
    LastActivity time.Time
    CommandCount int64
    BytesIn      int64             // tracked in pipeline
    BytesOut     int64             // tracked in pipeline
    ClientConn   net.Conn
    BackendConn  net.Conn
    Parameters   map[string]string // protocol handshake params
}
```

### Manager Lifecycle

```
Create(info, clientConn) → Session
    │
    ├── Generate random ID (16 bytes hex)
    ├── Store in sync.Map
    │
    ▼
Start() → background goroutine
    │
    ├── checkTimeouts() every 1s
    │   ├── IdleDuration > idleTimeout → kill (reason: "idle_timeout")
    │   └── Duration > maxDuration → kill (reason: "max_duration")
    │
    └── OnTimeout callback → audit event with reason
```

---

## 11. Connection Pooling

### Package: `internal/pool/`

```
internal/pool/
├── pool.go             Dedicated pool (per-target)
├── conn.go             Wrapped net.Conn with metadata
├── circuitbreaker.go   Circuit breaker (closed → open → half-open)
├── histogram.go        Latency histogram (acquire wait times)
└── shared.go           Shared pool (transaction-mode, not wired)
```

### Pool Architecture

```
┌──────────────────────────────────────────────────┐
│                    Pool                           │
│                                                   │
│  ┌──────────────┐  ┌──────────────┐              │
│  │  Idle Conns   │  │ Active Conns  │              │
│  │  (channel)    │  │ (tracking)    │              │
│  └──────┬───────┘  └──────┬───────┘              │
│         │                  │                      │
│  Acquire() ─────────────── │                      │
│  │ 1. Try idle channel     │                      │
│  │ 2. Check circuit breaker│                      │
│  │ 3. Dial new connection  │                      │
│  │ 4. Record wait latency  │                      │
│         │                  │                      │
│  Release(conn) ◄────────── │                      │
│  │ Return to idle or close │                      │
│                                                   │
│  Health check: periodic Acquire+Release probe     │
│  Circuit breaker: 5 failures → open → 30s reset   │
│                                                   │
│  Stats: Active, Idle, Total, Healthy, WaitCount   │
└──────────────────────────────────────────────────┘
```

---

## 12. Rate Limiting

### Package: `internal/ratelimit/`

```go
type Limiter struct {
    rate    float64              // tokens per second
    burst   int                  // max burst size
    buckets map[string]*bucket   // per-user token buckets
    cleanup time.Duration        // stale bucket TTL (5m)
}
// Allow(key) bool  — consume token or reject
// Cleanup()        — evict stale buckets (called every 5m by proxy)
```

---

## 13. Metrics & Observability

### Package: `internal/metrics/`

```
internal/metrics/
├── metrics.go      Global counters (connections, commands, rows)
├── protocol.go     Per-protocol counters (PG/MySQL/MSSQL/MongoDB)
├── database.go     Per-database counters (queries, writes, blocked, rows)
└── histogram.go    Query latency histogram
```

### Prometheus Metrics

```
# Global counters
argus_connections_total{status="success|failed"}
argus_commands_total{action="allowed|blocked|masked"}
argus_result_rows_total
argus_policy_evaluations_total
argus_policy_cache_hits_total{result="hit|miss"}

# Per-protocol
argus_protocol_commands_total{protocol="postgresql",type="query|extended|copy"}
argus_protocol_commands_total{protocol="mysql",type="query|prepared"}
argus_protocol_commands_total{protocol="mssql",type="batch"}
argus_protocol_commands_total{protocol="mongodb",type="command"}

# Per-database
argus_database_queries_total{database="..."}
argus_database_writes_total{database="..."}
argus_database_blocked_total{database="..."}
argus_database_rows_total{database="..."}

# Pool
argus_pool_connections{target="...",state="active|idle|total"}
argus_pool_healthy{target="..."}

# Histograms
argus_query_duration_microseconds{le="..."}
argus_pool_acquire_wait_microseconds{le="..."}

# Runtime
argus_go_goroutines
argus_go_alloc_bytes
argus_go_sys_bytes
argus_go_gc_runs_total
```

---

## 14. Admin API

### Package: `internal/admin/`

```
internal/admin/
├── server.go           29 HTTP endpoints + server lifecycle
├── auth.go             Bearer token middleware + public paths
├── websocket.go        WebSocket event stream (RFC 6455)
├── dashboard_ui.go     HTML/CSS/JS dashboard (embedded)
├── testrunner_ui.go    Test runner HTML (embedded)
└── testrunner_api.go   Test execution API (PG + MySQL)
```

### Endpoints

```
Health & Readiness:
  GET  /healthz                    Basic health (public)
  GET  /ready, /readyz             K8s readiness (public)
  GET  /livez                      K8s liveness (public)
  GET  /api/health/deep            Deep health with pool probes
  GET  /api/pool/health            Connection pool status

Sessions:
  GET  /api/sessions               List active sessions
  POST /api/sessions/kill?id=      Kill session + audit event

Policies:
  POST /api/policies/reload        Hot-reload policy files
  POST /api/policies/dryrun        Simulate policy evaluation
  GET  /api/policies/validate      Validate loaded policies

Audit:
  GET  /api/audit/search           Search audit logs
  GET  /api/audit/replay           Replay recorded sessions
  GET  /api/audit/fingerprints     Query fingerprint analysis
  GET  /api/audit/export           Export as CSV
  POST /api/audit/compact          Compact old entries

Approvals:
  GET  /api/approvals              List pending approvals
  POST /api/approvals/approve      Approve request
  POST /api/approvals/deny         Deny request

Configuration:
  GET  /api/config/export          Export config as JSON

Statistics:
  GET  /api/stats                  Aggregate statistics
  GET  /api/dashboard              Dashboard data
  GET  /metrics                    Prometheus format (public)

WebSocket:
  WS   /api/events/ws             Live event stream

UI:
  GET  /ui                         Admin dashboard
  GET  /ui/test                    Test runner

Classification:
  GET  /api/classify               Data classification
  GET  /api/plugins                Plugin registry
  POST /api/test/run               Execute test query
```

---

## 15. Authentication Providers

### Package: `internal/auth/` (implemented, not yet wired)

```
internal/auth/
├── provider.go     IdentityProvider interface, ChainProvider
├── ldap.go         LDAP/Active Directory (BER encoding, group resolution)
└── sso.go          JWT/SSO (HMAC-SHA256, claim extraction)
```

### Interfaces

```go
type IdentityProvider interface {
    Authenticate(username, password string) (*IdentityResult, error)
    Name() string
}

type IdentityResult struct {
    Username string
    Roles    []string
    Metadata map[string]string
}

// ChainProvider tries providers in order (fallback pattern)
// LDAPProvider: bind auth, group resolution, TLS support
// SSOProvider: JWT validation, HMAC-SHA256, claim extraction
```

---

## 16. Configuration System

### Package: `internal/config/`

### Loading Pipeline

```
JSON File
    │
    ▼
json.Unmarshal → Config struct (with defaults)
    │
    ▼
expandEnvInConfig()    ← Replace $ENV{VAR} patterns
    │                     in ALL string fields
    ▼
applyEnvOverrides()    ← Override from ARGUS_* env vars
    │
    ▼
Validate()             ← Cross-reference checks
    │                     (targets exist, protocols match, etc.)
    ▼
ResolvePolicyPaths()   ← Relative → absolute paths
    │
    ▼
Ready to use
```

### Environment Variable Support

```
Two mechanisms:

1. $ENV{VAR} in JSON values:
   "host": "$ENV{DB_HOST}"  →  expanded during Load()

2. ARGUS_* overrides (take precedence):
   ARGUS_ADMIN_AUTH_TOKEN=secret  →  cfg.Admin.AuthToken = "secret"
   ARGUS_POOL_MAX_CONNECTIONS_PER_TARGET=200
   ARGUS_SESSION_IDLE_TIMEOUT=30m
   ARGUS_TARGETS_0_HOST=db.example.com
```

---

## 17. Kubernetes Deployment

### Manifest Structure

```
k8s/
├── namespace.yaml         Namespace: argus
├── secret.yaml            DB credentials, auth tokens
├── configmap.yaml         argus.json + base-policy.json
├── serviceaccount.yaml    No auto-mount token
├── deployment.yaml        2 replicas, rolling update
├── service.yaml           4 services (PG, MySQL, Admin, Metrics)
├── hpa.yaml               Auto-scale 2-8 replicas
├── pdb.yaml               Min 1 available during disruption
└── kustomization.yaml     Kustomize orchestration
```

### Deployment Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Kubernetes Cluster                    │
│                                                       │
│  ┌─ Namespace: argus ──────────────────────────────┐ │
│  │                                                  │ │
│  │  ┌─── Deployment (2-8 replicas) ─────────────┐  │ │
│  │  │                                            │  │ │
│  │  │  ┌──────────┐  ┌──────────┐               │  │ │
│  │  │  │ Pod 1    │  │ Pod 2    │  ...          │  │ │
│  │  │  │ argus    │  │ argus    │               │  │ │
│  │  │  │ :15432   │  │ :15432   │  PG proxy     │  │ │
│  │  │  │ :13306   │  │ :13306   │  MySQL proxy  │  │ │
│  │  │  │ :9090    │  │ :9090    │  Admin API    │  │ │
│  │  │  │ :9091    │  │ :9091    │  Metrics      │  │ │
│  │  │  └──────────┘  └──────────┘               │  │ │
│  │  │                                            │  │ │
│  │  │  Resources: 100m-1000m CPU, 64-256Mi RAM   │  │ │
│  │  │  Security: non-root, read-only FS, no caps │  │ │
│  │  └────────────────────────────────────────────┘  │ │
│  │                                                  │ │
│  │  Services:                                       │ │
│  │    argus-pg      ClusterIP  5432  → 15432       │ │
│  │    argus-mysql   ClusterIP  3306  → 13306       │ │
│  │    argus-admin   ClusterIP  9090  → 9090        │ │
│  │    argus-metrics ClusterIP  9091  → 9091        │ │
│  │      └── prometheus.io/scrape: "true"           │ │
│  │                                                  │ │
│  │  HPA: CPU 70%, Memory 80%                       │ │
│  │  PDB: minAvailable: 1                           │ │
│  │                                                  │ │
│  │  Probes:                                        │ │
│  │    Liveness:  GET /livez:9091  (10s period)     │ │
│  │    Readiness: GET /readyz:9091 (5s period)      │ │
│  │                                                  │ │
│  └──────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
```

---

## 18. Package Dependency Graph

```
cmd/argus/main.go
  │
  ├── internal/config        Config loading, validation, env expansion
  ├── internal/audit         Async logger, webhook, recorder, rotation
  ├── internal/policy        Engine, loader, matcher, cache, dry-run
  ├── internal/core          Proxy, pipeline, listener, router, TLS
  │     ├── internal/protocol/pg       PostgreSQL handler
  │     ├── internal/protocol/mysql    MySQL handler
  │     ├── internal/protocol/mssql    MSSQL handler
  │     ├── internal/protocol/mongodb  MongoDB handler
  │     ├── internal/inspection        Classifier, cost, anomaly, rewrite
  │     ├── internal/masking           Pipeline, transformers, PII
  │     ├── internal/session           Manager, limiter
  │     ├── internal/pool              Pools, circuit breaker, histogram
  │     ├── internal/ratelimit         Token bucket limiter
  │     ├── internal/metrics           Counters, protocol stats, DB stats
  │     └── internal/plan              EXPLAIN cost analysis (PG + MySQL)
  ├── internal/admin         HTTP server, WebSocket, dashboard, test runner
  │     ├── internal/session           (via SessionProvider interface)
  │     └── internal/pool              (for pool stats)
  ├── internal/classify      Data classification engine
  └── internal/plugin        Plugin registry (transformer + audit writer)

Standalone packages (not imported by main binary):
  ├── internal/auth          LDAP + SSO providers (planned integration)
  └── internal/cluster       Multi-instance session store (planned)
```

### Package Statistics

```
┌────────────────────────┬───────┬──────────┬──────────┐
│ Package                │ Files │ Tests    │ Coverage │
├────────────────────────┼───────┼──────────┼──────────┤
│ cmd/argus              │   1   │    0     │   N/A    │
│ internal/core          │   6   │  ~200    │  ~90%    │
│ internal/protocol/pg   │   7   │  ~150    │  ~92%    │
│ internal/protocol/mysql│   4   │  ~100    │  ~91%    │
│ internal/protocol/mssql│   3   │  ~80     │  ~90%    │
│ internal/protocol/mongo│   2   │  ~40     │  ~88%    │
│ internal/inspection    │   7   │  ~120    │  ~95%    │
│ internal/policy        │   6   │  ~150    │  ~93%    │
│ internal/masking       │   3   │  ~80     │  ~94%    │
│ internal/audit         │   8   │  ~100    │  ~91%    │
│ internal/admin         │   6   │  ~120    │  ~88%    │
│ internal/session       │   2   │  ~60     │  ~92%    │
│ internal/pool          │   5   │  ~80     │  ~90%    │
│ internal/ratelimit     │   1   │  ~20     │  ~95%    │
│ internal/metrics       │   4   │  ~30     │  ~96%    │
│ internal/config        │   1   │  ~40     │  ~93%    │
│ internal/plan          │   1   │  ~20     │  ~90%    │
│ internal/classify      │   1   │  ~20     │  ~94%    │
│ internal/auth          │   3   │  ~60     │  ~91%    │
│ internal/cluster       │   1   │  ~15     │  ~95%    │
│ internal/plugin        │   1   │  ~20     │  ~92%    │
├────────────────────────┼───────┼──────────┼──────────┤
│ TOTAL                  │  ~72  │  ~1304   │  ~92.2%  │
└────────────────────────┴───────┴──────────┴──────────┘
```

---

*Generated from source code analysis — Argus v0.1.0*
