# Task Tracking

## Phase 1 — MVP (Complete)

### Core Infrastructure
- [x] Go module initialization
- [x] Project directory structure
- [x] Configuration system (JSON, env overrides, validation, cross-reference)
- [x] TCP listener with TLS support
- [x] Protocol router (auto-detect PG, MSSQL; port-based MySQL)
- [x] Pipeline orchestrator (command loop)
- [x] Makefile (build, test, cover, cross-compile, lint, benchmark)
- [x] Dockerfile (multi-stage, non-root, health check)
- [x] Docker Compose (PG + Argus)
- [x] .gitignore, .editorconfig
- [x] GitHub Actions CI (test, build matrix, Docker)

### PostgreSQL Protocol
- [x] Wire protocol codec (encode/decode)
- [x] Startup message parsing + building
- [x] Authentication passthrough (cleartext, MD5, SCRAM relay)
- [x] Native SSL negotiation (SSLRequest → TLS upgrade)
- [x] Simple Query protocol
- [x] Extended Query protocol (Parse/Bind/Describe/Execute/Sync)
- [x] COPY protocol (CopyIn/CopyOut passthrough)
- [x] Protocol detection from initial bytes
- [x] ReadyForQuery state tracking

### MySQL Protocol
- [x] Handshake V10 authentication passthrough
- [x] COM_QUERY text protocol with SQL inspection
- [x] COM_STMT_PREPARE/EXECUTE/CLOSE (prepared statements)
- [x] COM_PING, COM_INIT_DB, COM_QUIT
- [x] Result set forwarding with streaming masking
- [x] Text row parsing and rebuilding

### MSSQL TDS Protocol
- [x] TDS packet codec (read/write)
- [x] Pre-Login handshake passthrough
- [x] Login7 authentication passthrough
- [x] SQL Batch command handling
- [x] COLMETADATA token parsing (column names, types)
- [x] ROW token masking for text columns
- [x] Protocol detection (0x12 pre-login byte)
- [x] UTF-16LE encoding/decoding
- [x] Error token builder

### SQL Inspection
- [x] Lightweight SQL tokenizer (50+ keywords)
- [x] Quoted identifier support (`"name"`, `` `name` ``, `[name]`)
- [x] String literal handling (with escape sequences)
- [x] Dollar-quoted string support (PostgreSQL)
- [x] Comment handling (line `--` and block `/* */`)
- [x] Command classifier (10 types: SELECT, INSERT, UPDATE, DELETE, DDL, DCL, TCL, ADMIN, UTILITY, UNKNOWN)
- [x] Table name extraction (FROM, INTO, UPDATE, JOIN, TABLE)
- [x] Column name extraction (SELECT list, SET clause, INSERT columns)
- [x] Risk level assessment (none → critical, 5 levels)
- [x] Dangerous pattern detection (DROP, TRUNCATE, bulk operations)
- [x] Multi-statement detection and splitting
- [x] Comment-embedded command detection
- [x] Query fingerprinting (normalize + hash)
- [x] Query cost estimation (0-100 heuristic)
- [x] Anomaly detection (baseline learning, frequency spike)

### Policy Engine
- [x] JSON policy file loader
- [x] Policy hot-reload (file mtime polling, configurable interval)
- [x] Role definition and user-to-role mapping (wildcard support)
- [x] Role negation (`!dba`)
- [x] Command-type matching
- [x] Database name matching (wildcards)
- [x] Table name matching (wildcards)
- [x] SQL content matching (`sql_contains`)
- [x] Risk level threshold matching (`risk_level_gte`)
- [x] Query cost threshold (`max_cost_gte`)
- [x] Time-based rules (work hours, work days)
- [x] IP-based rules (CIDR ranges, inclusion/exclusion)
- [x] First-match evaluation order
- [x] Decision cache (LRU, TTL, invalidation on reload)
- [x] Default action fallback
- [x] Rate limiting (token bucket per user, policy-driven)
- [x] Policy inheritance (base + overlay merge)
- [x] Policy dry-run mode (test without enforcement)
- [x] Policy validator (duplicate names, shadows, undefined roles, block-all)

### Data Masking
- [x] Streaming masking pipeline (O(1) memory per row)
- [x] Column-name-based rule matching
- [x] Wildcard column matching (`*`)
- [x] 8 built-in transformers: redact, partial_email, partial_phone, partial_card, partial_iban, partial_tc, hash, null
- [x] Row count enforcement
- [x] NULL value pass-through
- [x] Custom transformer registration
- [x] PII auto-detection (10 column patterns + 5 value patterns)
- [x] Luhn check for credit cards
- [x] TC Kimlik number validation
- [x] PII → masking pipeline integration (auto-mask on RowDescription)

### Session Management
- [x] Session creation and tracking
- [x] Session identity resolution
- [x] Idle timeout + max duration timeout
- [x] Background timeout checker
- [x] Session kill capability
- [x] Active session listing
- [x] Command/byte counting
- [x] Session tagging (custom key-value metadata)

### Connection Pool
- [x] Session-dedicated backend connections
- [x] Shared pool (transaction-mode with waiter queue)
- [x] Max connection limit per target
- [x] Idle connection reuse with lifetime expiry
- [x] Connection timeout
- [x] Backend health checking
- [x] TLS backend connections
- [x] Pool warmup (pre-create min idle connections)
- [x] Circuit breaker (closed/open/half-open state machine)
- [x] Wait time histogram (p50/p95/p99)

### Audit Logging
- [x] 12+ audit event types
- [x] Structured JSON event format
- [x] File output with rotation (size-based)
- [x] Stdout output
- [x] Async buffered channel (drop on overflow, never block)
- [x] Dropped event counter
- [x] SQL truncation for long queries
- [x] SQL literal sanitization ($1, $2 replacement)
- [x] Three log levels (minimal, standard, verbose)
- [x] Auto-generated event IDs
- [x] SIEM webhook (batched HTTP POST)
- [x] Query recording (forensic full SQL preservation)
- [x] Audit log search API (filter by user, session, time, action, type)
- [x] Session replay (reconstruct query timeline)
- [x] Top fingerprints (most common query patterns)
- [x] Log compaction (age + count based cleanup, dry-run)
- [x] Slow query log (configurable threshold)

### Observability
- [x] Prometheus metrics endpoint (/metrics)
- [x] Health endpoint (/healthz)
- [x] Kubernetes readiness probe (/ready)
- [x] Kubernetes liveness probe (/livez)
- [x] Query latency histogram (p50/p95/p99)
- [x] Connection metrics, command metrics, pool metrics
- [x] Go runtime metrics (goroutines, memory)
- [x] Pool wait time histogram
- [x] Startup banner with feature summary

### Admin API (23 endpoints + WebSocket)
- [x] GET /healthz — health status
- [x] GET /metrics — Prometheus metrics
- [x] GET /ready — K8s readiness
- [x] GET /livez — K8s liveness
- [x] GET /api/sessions — list sessions
- [x] POST /api/sessions/kill — kill session
- [x] POST /api/policies/reload — hot-reload policies
- [x] POST /api/policies/dryrun — test policy
- [x] GET /api/policies/validate — validate policy rules
- [x] GET /api/stats — runtime stats
- [x] GET /api/dashboard — aggregated dashboard
- [x] GET /api/approvals — pending approvals
- [x] POST /api/approvals/approve — approve command
- [x] POST /api/approvals/deny — deny command
- [x] GET /api/audit/search — search audit logs
- [x] GET /api/audit/replay — replay session
- [x] GET /api/audit/fingerprints — top patterns
- [x] POST /api/audit/compact — clean old logs
- [x] GET /api/config/export — export config
- [x] WS /api/events/ws — live event stream
- [x] Bearer token authentication middleware
- [x] Public paths exempt from auth

### Enterprise Features
- [x] Approval workflow (hold/approve/deny/timeout for critical commands)
- [x] Anomaly detection (baseline + frequency spike + unusual table/command/hour)
- [x] Rate limiting (token bucket per user, policy-driven)
- [x] Connection draining on shutdown (10s timeout)
- [x] Certificate rotation without restart
- [x] SIGHUP signal for policy reload

### Security
- [x] TLS for listeners (client-facing)
- [x] TLS for backend connections
- [x] PostgreSQL native SSL negotiation
- [x] SQL sanitization in audit logs
- [x] Admin API token authentication
- [x] No credentials in config (env var expansion)

### Testing
- [x] 316 tests across 14 packages
- [x] 60.6% total coverage (5 packages > 90%)
- [x] 16 benchmark tests
- [x] End-to-end proxy test with fake PostgreSQL backend
- [x] MySQL handshake + query E2E test
- [x] Protocol detection tests (PG, MySQL, MSSQL)
- [x] Integration test with masking pipeline
- [x] Policy engine tests (cache, IP, cost, defaults, rate limit)
- [x] PII auto-detection tests
- [x] Circuit breaker state machine tests
- [x] Admin API endpoint tests (22 endpoints)

### Documentation
- [x] SPECIFICATION.md (original spec)
- [x] README.md (badges, quick start, API table, roadmap)
- [x] CLAUDE.md (build commands, architecture, conventions)
- [x] IMPLEMENTATION.md (architecture decisions, wire protocol details)
- [x] TASKS.md (comprehensive task tracking)
- [x] LICENSE (MIT)
- [x] Example configs (default, docker, production, development)

---

## Phase 2 — Production Hardening (Complete)
All Phase 2 items have been implemented.

## Phase 3 — Enterprise Features (Complete)
All major Phase 3 items have been implemented.

## Phase 4 — Extended Platform (Planned)
- [ ] Oracle TNS support
- [ ] MongoDB wire protocol
- [ ] Web dashboard UI
- [ ] Terraform provider for policy-as-code
- [ ] Kubernetes operator
- [ ] Plugin system for custom transformers and policy providers
- [ ] Data classification engine
