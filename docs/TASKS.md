# Task Tracking

## Phase 1 — MVP

### Core Infrastructure
- [x] Go module initialization
- [x] Project directory structure
- [x] Configuration system (JSON, env overrides, validation)
- [x] TCP listener with TLS support
- [x] Protocol router
- [x] Pipeline orchestrator (command loop)
- [x] Makefile (build, test, cover, cross-compile)
- [x] Dockerfile
- [x] .gitignore, .editorconfig

### PostgreSQL Protocol
- [x] Wire protocol codec (encode/decode)
- [x] Message types (Query, RowDescription, DataRow, CommandComplete, ErrorResponse, etc.)
- [x] Startup message parsing
- [x] Authentication passthrough (cleartext, MD5, SCRAM relay)
- [x] SSL request handling (respond N, use transport-level TLS)
- [x] Simple Query protocol
- [x] ReadyForQuery state tracking
- [x] Protocol detection from initial bytes

### SQL Inspection
- [x] Lightweight SQL tokenizer
- [x] Keyword recognition (50+ SQL keywords)
- [x] Quoted identifier support (`"name"`, `` `name` ``, `[name]`)
- [x] String literal handling (with escape sequences)
- [x] Comment handling (line `--` and block `/* */`)
- [x] Dollar-quoted string support (PostgreSQL)
- [x] Command classifier (SELECT, INSERT, UPDATE, DELETE, DDL, DCL, TCL, ADMIN, UTILITY)
- [x] Table name extraction (FROM, INTO, UPDATE, JOIN, TABLE)
- [x] Column name extraction (SELECT list, SET clause, INSERT columns)
- [x] Risk level assessment (none → critical)
- [x] Dangerous pattern detection (DROP, TRUNCATE, bulk operations)
- [x] Multi-statement detection
- [x] Comment-embedded command detection

### Policy Engine
- [x] JSON policy file loader
- [x] Policy hot-reload (file mtime polling)
- [x] Role definition and user-to-role mapping (wildcard support)
- [x] Role negation (`!dba`)
- [x] Command-type matching
- [x] Database name matching (wildcards)
- [x] Table name matching
- [x] SQL content matching (`sql_contains`)
- [x] Risk level threshold matching
- [x] Time-based rules (work hours, work days)
- [x] IP-based rules (CIDR ranges, inclusion/exclusion)
- [x] First-match evaluation order
- [x] Decision cache (LRU, TTL, invalidation on reload)
- [x] Default action fallback

### Data Masking
- [x] Streaming masking pipeline
- [x] Column-name-based rule matching
- [x] Wildcard column matching (`*`)
- [x] Transformer: redact
- [x] Transformer: partial_email
- [x] Transformer: partial_phone
- [x] Transformer: partial_card
- [x] Transformer: partial_iban
- [x] Transformer: partial_tc
- [x] Transformer: hash (SHA-256)
- [x] Transformer: null
- [x] Row count enforcement
- [x] NULL value pass-through
- [x] Custom transformer registration

### Session Management
- [x] Session creation and tracking
- [x] Session identity resolution
- [x] Idle timeout
- [x] Max duration timeout
- [x] Background timeout checker
- [x] Session kill capability
- [x] Active session listing
- [x] Command counting
- [x] Byte counting

### Connection Pool
- [x] Session-dedicated backend connections
- [x] Max connection limit per target
- [x] Idle connection reuse
- [x] Connection lifetime expiry
- [x] Connection timeout
- [x] Backend health checking
- [x] TLS backend connections

### Audit Logging
- [x] 12 audit event types
- [x] Structured JSON event format
- [x] File output with append
- [x] Stdout output
- [x] Async buffered channel
- [x] Drop-on-overflow (never block proxy)
- [x] Dropped event counter
- [x] SQL truncation for long queries
- [x] Three log levels (minimal, standard, verbose)
- [x] Auto-generated event IDs

### Observability
- [x] Prometheus metrics endpoint (/metrics)
- [x] Health endpoint (/healthz)
- [x] Active sessions API (/api/sessions)
- [x] Connection metrics (total, failed)
- [x] Command metrics (total, blocked, masked)
- [x] Pool metrics (active, idle per target)
- [x] Go runtime metrics (goroutines, memory)

### Testing
- [x] Tokenizer unit tests
- [x] Command classifier tests
- [x] Table extraction tests
- [x] Dangerous pattern detection tests
- [x] Masking transformer tests
- [x] Masking pipeline tests (including row limits, NULL handling)
- [x] Policy engine tests (role matching, action decisions)
- [x] Wildcard matching tests
- [x] IP matching tests
- [x] Config loading tests
- [x] Config validation tests
- [x] Environment override tests
- [x] Routing/target resolution tests
- [x] PG codec tests (startup, error, row description, data row)
- [x] PG protocol detection test
- [x] PG integration test (full query cycle with masking)
- [x] Audit logger tests (write, truncation, drop)
- [x] Session manager tests
- [x] Connection pool tests

### Documentation
- [x] SPECIFICATION.md
- [x] README.md
- [x] CLAUDE.md
- [x] IMPLEMENTATION.md
- [x] TASKS.md

---

## Phase 2 — Production Hardening (Planned)

### Protocol
- [ ] MySQL wire protocol support
- [ ] PostgreSQL Extended Query protocol (Parse, Bind, Execute)
- [ ] PostgreSQL COPY protocol
- [ ] Native SSL negotiation (SSLRequest → TLS upgrade)

### Security
- [ ] Proxy auth mode (own user registry)
- [ ] External IdP integration
- [ ] Just-in-time credential provisioning
- [ ] SQL literal sanitization in audit logs ($1, $2 replacement)

### Operations
- [ ] Admin REST API (manage sessions, view audit, manage policies)
- [ ] Remote policy API (HTTP) with local fallback
- [ ] SIEM export (syslog, webhook)
- [ ] Graceful shutdown with connection draining
- [ ] Signal handling (SIGHUP for config reload)
- [ ] Audit log file rotation (size/time based)
- [ ] Kafka audit producer

### Intelligence
- [ ] PII auto-detection (column name patterns, value patterns)
- [ ] Query fingerprinting
- [ ] Anomaly detection baseline

---

## Phase 3 — Enterprise (Planned)

- [ ] MSSQL TDS protocol
- [ ] LDAP/SSO identity integration
- [ ] Approval workflows for high-risk commands
- [ ] Live session monitoring (WebSocket stream)
- [ ] Query replay and forensics
- [ ] Rate limiting per user/role
- [ ] Multi-instance clustering (shared session store)
- [ ] Certificate rotation without downtime

---

## Phase 4 — Extended Platform (Planned)

- [ ] Oracle TNS support
- [ ] MongoDB wire protocol
- [ ] Web dashboard UI
- [ ] Terraform provider for policy-as-code
- [ ] Kubernetes operator
- [ ] Plugin system for custom transformers and policy providers
- [ ] Data classification engine
