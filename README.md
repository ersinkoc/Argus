# Argus

[![CI](https://github.com/ersinkoc/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/ersinkoc/argus/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-green.svg)](#)

**The Hundred-Eyed Database Guardian**

> *Know who connects. Control what they do. Protect what they see.*

Argus is a protocol-aware database firewall and access proxy written in Go. It sits between applications and databases — inspecting every query, blocking SQL injection and dangerous operations, enforcing access policies in real time, masking sensitive data at the result level, and logging everything for audit and compliance.

```
┌──────────┐         ┌──────────────────────────────────────────────────┐         ┌──────────┐
│          │   TCP   │                     Argus                        │   TCP   │          │
│  Client  │────────>│  ┌─────────┐  ┌─────────┐  ┌────────────────┐   │────────>│ Database │
│  (App)   │<────────│  │Protocol │  │  WAF /  │  │   Masking /    │   │<────────│ Server   │
│          │         │  │ Handler │  │ Policy  │  │ PII Protection │   │         │          │
└──────────┘         │  └─────────┘  └─────────┘  └────────────────┘   │         └──────────┘
                     │  ┌─────────┐  ┌─────────┐  ┌────────────────┐   │
                     │  │Session  │  │ Audit / │  │ Connection     │   │
                     │  │Manager  │  │ SIEM    │  │ Pool + CB      │   │
                     │  └─────────┘  └─────────┘  └────────────────┘   │
                     └──────────────────────────────────────────────────┘
```

---

## Why Argus?

Traditional PAM tools manage credentials. They answer **"who connected."**
They do not answer **"what did they do"** or **"what did they see."**

Argus answers all three — and blocks what shouldn't happen:

| Layer | Capability |
|-------|-----------|
| **Identity** | Session-level identity, role mapping, LDAP/SSO, IP tracking |
| **Inspection** | SQL parsing, classification, risk scoring, anomaly detection |
| **Protection** | SQL injection blocking, query cost limits, WHERE enforcement |
| **Access Control** | Role/time/IP-based policies, rate limiting, approval workflows |
| **Data Protection** | Column masking, PII auto-detection, row limits, sensitive table lockdown |
| **Audit** | Structured JSON logs, SIEM webhook, session replay, query fingerprinting |

---

## Features

### Database WAF (Web Application Firewall for Databases)
- **SQL injection detection** — tautology (`OR 1=1`), UNION-based, stacked queries, blind injection (`SLEEP`, `BENCHMARK`, `WAITFOR DELAY`), comment termination, encoding tricks (`CHAR()` obfuscation)
- **Schema enumeration blocking** — `information_schema`, `pg_catalog`, `sys.*`, `mysql.user` access detection
- **System command blocking** — `xp_cmdshell`, `INTO OUTFILE`, `LOAD_FILE`, `pg_read_file`, `lo_export`
- **Privilege escalation detection** — `CREATE USER`, `GRANT`, `SET ROLE`, `SET SESSION AUTHORIZATION`
- **Query complexity limits** — max query length, max tables, max JOINs, cost threshold
- **Bulk operation protection** — `require_where` enforces WHERE on UPDATE/DELETE
- **Sensitive table lockdown** — block non-DBA access to credential, audit, and secret tables
- **Audit log tamper protection** — prevent modification of audit/log tables

### Protocol Support
- **4 database protocols** — PostgreSQL, MySQL, MSSQL TDS, and MongoDB wire protocols
- **Protocol-native proxy** — speaks each database's wire protocol natively, not JDBC/ODBC wrapping
- **Zero external dependencies** — standard library only, no CGO, single binary (~7.8MB)

### Policy Engine (14 Condition Types)

| Condition | Purpose | Example |
|-----------|---------|---------|
| `sql_contains` | Substring match (case-insensitive) | `["DROP", "TRUNCATE"]` |
| `sql_not_contains` | Block when SQL lacks required pattern | `["WHERE"]` |
| `sql_regex` | Full regex pattern matching | `["(?i)information_schema\\."]` |
| `sql_injection` | Enable built-in SQLi signature detection | `true` |
| `risk_level_gte` | Minimum risk level threshold | `"medium"`, `"high"`, `"critical"` |
| `max_cost_gte` | Query cost estimation threshold (0-100) | `80` |
| `max_query_length` | Max SQL length in bytes | `8192` |
| `max_tables` | Max tables accessed in one query | `10` |
| `max_joins` | Max JOIN operations | `8` |
| `require_where` | Enforce WHERE clause on write ops | `true` |
| `work_hours` | Time range (blocks outside range) | `"08:00-19:00"` |
| `work_days` | Day restriction (blocks outside days) | `["monday", "friday"]` |
| `source_ip_in` | IP whitelist (CIDR) | `["10.0.0.0/8"]` |
| `source_ip_not_in` | IP blacklist (CIDR) | `["203.0.113.0/24"]` |

Plus: role-based matching (`!dba`), command-type filtering, database/table wildcards, rate limiting per policy, row count limits, and masking rules.

### Data Masking
- **Column-level masking** — per-column transformer rules with wildcard support
- **PII auto-detection** — 17 patterns, Luhn validation, TC Kimlik check
- **8 built-in transformers:**

| Transformer | Input | Output |
|------------|-------|--------|
| `redact` | `anything` | `***` |
| `partial_email` | `john@example.com` | `j***@example.com` |
| `partial_phone` | `+905321234567` | `***-***-4567` |
| `partial_card` | `4532123456785678` | `****-****-****-5678` |
| `partial_iban` | `TR330006100519786457841326` | `TR**-****-****-****-**26` |
| `partial_tc` | `12345678901` | `*********01` |
| `hash` | `anything` | `a1b2c3d4` (SHA-256 prefix) |
| `null` | `anything` | `NULL` |

- **Row count enforcement** — configurable limits per policy
- **Streaming** — masking applied per-row, O(1) memory

### Audit & Observability
- **Structured JSON audit logs** — every connection, command, and decision
- **Three log levels** — minimal, standard, verbose
- **Async logging** — buffered channel, never blocks the proxy pipeline
- **SIEM webhook** — batched HTTP POST to external systems
- **Prometheus metrics** — connections, commands, masking, pool stats, Go runtime
- **Query fingerprinting** — top query patterns, slow query logging
- **Session replay** — reconstruct full query timeline for any session
- **Audit search & CSV export** — filter by user, time, action, command type
- **Log rotation + compaction** — size-based rotation, age-based cleanup
- **Health endpoints** — `/healthz`, `/ready`, `/livez` with per-target backend health

### Authentication
- **Auth passthrough** — observes username without storing passwords
- **LDAP/Active Directory** — bind authentication with group resolution
- **SSO/JWT** — HMAC-SHA256 verification, claim extraction, expiry validation

### Enterprise Features
- **Approval workflows** — hold critical commands for manual approve/deny with timeout
- **Anomaly detection** — behavioral baseline learning, unusual command/table/hour/frequency spike alerts
- **Query cost estimation** — heuristic scoring (0-100) based on JOINs, subqueries, missing WHERE
- **Query rewriting** — auto-LIMIT injection, WHERE clause enforcement for multi-tenant isolation
- **Rate limiting** — per-policy token bucket (configurable rate/burst per role)
- **Connection pool** — dedicated + shared modes, circuit breaker, warmup, wait histogram
- **Certificate rotation** — TLS cert reload without restart
- **Data classification** — 5 sensitivity levels, 17 rules, confidence scoring
- **Plugin system** — custom transformers, audit writers, auth providers
- **Web dashboard** — embedded real-time UI at `/ui` with auto-refresh + interactive test runner at `/ui/test`

---

## Quick Start

### Build

```bash
go build -o argus ./cmd/argus/
# Or with Makefile
make build
```

### Configure

Create `argus.json`:

```json
{
  "server": {
    "listeners": [
      {"address": ":15432", "protocol": "postgresql"}
    ]
  },
  "targets": [
    {
      "name": "my-postgres",
      "protocol": "postgresql",
      "host": "localhost",
      "port": 5432
    }
  ],
  "routing": {
    "default_target": "my-postgres"
  },
  "policy": {
    "files": ["policies/waf.json"],
    "reload_interval": "5s"
  },
  "audit": {
    "level": "verbose",
    "outputs": [{"type": "stdout"}],
    "pii_auto_detect": true
  },
  "metrics": {
    "enabled": true,
    "address": ":9091"
  }
}
```

### Run

```bash
./argus -config argus.json
```

### Connect

Point your application to Argus instead of the database:

```bash
# Before: direct to database
psql -h localhost -p 5432 -U myuser mydb

# After: through Argus
psql -h localhost -p 15432 -U myuser mydb
```

No application code changes required. Same protocol, same tools.

### Docker Multi-Database Setup

```bash
# Start all services
make docker-up

# Services:
#   PostgreSQL direct → localhost:35432
#   MySQL direct      → localhost:33306
#   MSSQL direct      → localhost:31433
#   Argus PG proxy    → localhost:30100
#   Argus MySQL proxy → localhost:30101
#   Argus MSSQL proxy → localhost:30102
#   Admin/Metrics     → localhost:30200

# Connect via Argus proxy
psql -h localhost -p 30100 -U argus_test -d testdb
mysql -h 127.0.0.1 -P 30101 -u argus_test -pargus_pass testdb

# Run E2E tests
make e2e

# Dashboard
open http://localhost:30200/ui
```

---

## WAF Policy Examples

### Block SQL injection

```json
{
  "name": "waf-sqli-detection",
  "match": {},
  "condition": { "sql_injection": true },
  "action": "block",
  "reason": "SQL injection pattern detected"
}
```

Detects: `OR 1=1`, `UNION SELECT`, `; DROP TABLE`, `SLEEP(5)`, `xp_cmdshell`, `' OR '--`, `CHAR(68,82,79,80)`, `INTO OUTFILE`, `LOAD_FILE()`, `WAITFOR DELAY`, `BENCHMARK()`.

### Block DELETE/UPDATE without WHERE

```json
{
  "name": "waf-require-where",
  "match": { "commands": ["DELETE", "UPDATE"] },
  "condition": { "require_where": true },
  "action": "block",
  "reason": "WHERE clause required for write operations"
}
```

### Block schema enumeration

```json
{
  "name": "waf-block-schema-scan",
  "match": { "roles": ["!dba"] },
  "condition": {
    "sql_regex": ["(?i)information_schema\\.", "(?i)pg_catalog\\.", "(?i)sys\\."]
  },
  "action": "block",
  "reason": "Schema metadata access restricted to DBA"
}
```

### Block oversized queries (anti-injection payload)

```json
{
  "name": "waf-max-query-length",
  "match": { "roles": ["!dba"] },
  "condition": { "max_query_length": 8192 },
  "action": "block",
  "reason": "Query exceeds 8KB — possible injection payload"
}
```

### Block excessive JOINs (anti-resource exhaustion)

```json
{
  "name": "waf-max-joins",
  "match": { "roles": ["!dba"] },
  "condition": { "max_joins": 8 },
  "action": "block",
  "reason": "Too many JOINs — possible resource exhaustion"
}
```

### Protect sensitive tables

```json
{
  "name": "waf-protect-credentials",
  "match": {
    "roles": ["!dba"],
    "tables": ["credentials", "passwords", "secrets", "api_keys"]
  },
  "action": "block",
  "reason": "Access to credential tables requires DBA role"
}
```

### Block system-level commands

```json
{
  "name": "waf-block-system-commands",
  "match": { "roles": ["!dba"] },
  "condition": {
    "sql_regex": [
      "(?i)xp_cmdshell", "(?i)INTO\\s+OUTFILE", "(?i)LOAD_FILE\\s*\\(",
      "(?i)LOAD\\s+DATA\\s+INFILE", "(?i)pg_read_file", "(?i)lo_export"
    ]
  },
  "action": "block",
  "reason": "System-level operations are prohibited"
}
```

### Mask PII for support team

```json
{
  "name": "mask-pii-for-support",
  "match": { "roles": ["support"], "commands": ["SELECT"] },
  "masking": [
    {"column": "email", "transformer": "partial_email"},
    {"column": "phone", "transformer": "partial_phone"},
    {"column": "tc_kimlik", "transformer": "redact"},
    {"column": "card_number", "transformer": "partial_card"},
    {"column": "salary", "transformer": "redact"},
    {"column": "password_hash", "transformer": "redact"},
    {"column": "date_of_birth", "transformer": "redact"}
  ]
}
```

### Rate limit + office hours for contractors

```json
{
  "name": "contractor-rate-limit",
  "match": { "roles": ["contractor"] },
  "rate_limit": { "rate": 5, "burst": 10 }
}
```

```json
{
  "name": "contractor-office-hours",
  "match": { "roles": ["contractor"] },
  "condition": {
    "work_hours": "08:00-19:00",
    "work_days": ["monday", "tuesday", "wednesday", "thursday", "friday"]
  },
  "action": "block",
  "reason": "Contractor access outside business hours"
}
```

### Restrict production to internal network

```json
{
  "name": "production-ip-restriction",
  "match": { "databases": ["production", "prod_*"] },
  "condition": {
    "source_ip_not_in": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  },
  "action": "block",
  "reason": "Production access restricted to internal network"
}
```

### Ready-to-use WAF policy

A comprehensive WAF policy with 30+ rules is included at `configs/policies/waf.json`. It covers all the above plus audit log tamper protection, privilege escalation blocking, data exfiltration limits, and role-specific masking for 8 predefined roles.

---

## Configuration

### Environment Variable Override

All config values can be overridden via `ARGUS_` prefixed environment variables:

```bash
ARGUS_AUDIT_LEVEL=verbose
ARGUS_METRICS_ADDRESS=:8080
ARGUS_POOL_MAX_CONNECTIONS_PER_TARGET=200
ARGUS_SESSION_IDLE_TIMEOUT=1h
ARGUS_TARGETS_0_HOST=db-prod.internal
```

### Credential Security

Use `$ENV{VAR}` syntax in config for secrets:

```json
{
  "host": "$ENV{DB_HOST}",
  "port": 5432
}
```

### Policy Files

Three built-in policy profiles:

| File | Use Case | Rules |
|------|----------|-------|
| `configs/policies/default.json` | Minimal — basic DDL/bulk protection | 8 rules |
| `configs/policies/production.json` | Production — RBAC, IP, time, rate limiting | 13 rules |
| `configs/policies/waf.json` | Full WAF — SQLi, exfiltration, masking, everything | 30+ rules |

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Health status, per-target backend health, session count |
| `/metrics` | GET | Prometheus-format metrics |
| `/api/sessions` | GET | List active sessions with details |
| `/api/sessions/kill?id=` | POST | Kill a session by ID |
| `/api/policies/reload` | POST | Hot-reload policy files |
| `/api/policies/dryrun?username=&sql=` | POST | Test policy without enforcing |
| `/api/policies/validate` | GET | Validate policy rules for conflicts |
| `/api/stats` | GET | Runtime statistics (memory, goroutines, counters) |
| `/api/approvals` | GET | List pending approval requests |
| `/api/approvals/approve?id=` | POST | Approve a pending command |
| `/api/approvals/deny?id=` | POST | Deny a pending command |
| `/api/audit/search?username=&action=` | GET | Search audit logs |
| `/api/audit/replay?session_id=` | GET | Replay a session's queries |
| `/api/audit/fingerprints?limit=` | GET | Top query patterns |
| `/api/audit/compact` | POST | Clean up old audit log files |
| `/api/audit/export?username=` | GET | CSV export of audit events |
| `/api/config/export` | GET | Export current configuration |
| `/api/pool/health` | GET | Per-target pool health summary |
| `/api/health/deep` | GET | Deep TCP health check with latency |
| `/api/dashboard` | GET | Aggregated dashboard data |
| `/api/classify` | POST | Data classification engine |
| `/api/plugins` | GET | List registered plugins |
| `/api/gateway/query` | POST | SQL Gateway — submit query with full policy evaluation |
| `/api/gateway/approve` | POST | Approve pending query (one-time or time-window) |
| `/api/gateway/allowlist` | GET/DELETE | Manage pre-approved query allowlist |
| `/api/gateway/status` | GET | Poll approval status |
| `/ready` | GET | Kubernetes readiness probe |
| `/livez` | GET | Kubernetes liveness probe |
| `/api/events/ws` | WebSocket | Live event stream |
| `/ui` | GET | Web dashboard |
| `/ui/test` | GET | Interactive test runner |

---

## Architecture

```
argus/
├── cmd/argus/              # Binary entry point, signal handling
├── internal/
│   ├── core/               # Listener, TLS, router, pipeline, approval workflow
│   ├── protocol/
│   │   ├── handler.go      # ProtocolHandler interface
│   │   ├── pg/             # PostgreSQL (Simple + Extended + COPY + SSL)
│   │   ├── mysql/          # MySQL (COM_QUERY, prepared statements, masking)
│   │   ├── mssql/          # MSSQL TDS (Pre-Login, Login7, SQL Batch, masking)
│   │   └── mongodb/        # MongoDB (OP_MSG, BSON command extraction)
│   ├── inspection/         # Tokenizer, classifier, fingerprint, anomaly, cost, splitter
│   ├── policy/             # Engine, matcher (14 conditions), WAF rules, decision cache
│   ├── masking/            # Streaming pipeline, 8 transformers, PII auto-detection
│   ├── ratelimit/          # Token bucket rate limiter
│   ├── session/            # Lifecycle, identity, timeout, tagging, concurrency
│   ├── pool/               # Dedicated + shared pool, circuit breaker, histogram, health
│   ├── audit/              # Logger, rotation, webhook, recorder, search, replay, compaction
│   ├── admin/              # 26 REST endpoints + WebSocket, auth middleware, dashboard UI
│   ├── auth/               # LDAP (BER encoding, group resolution) + SSO (JWT/HMAC-SHA256)
│   ├── classify/           # Data classification engine (5 levels, 17 rules)
│   ├── cluster/            # Multi-instance shared session store
│   ├── config/             # Loading, validation, env overrides
│   ├── metrics/            # Counters, query latency histogram
│   ├── plugin/             # Plugin registry (transformer, audit writer, auth provider)
│   └── gateway/            # SQL Gateway HTTP API, query executor, allowlist, approval
├── configs/
│   ├── argus-multidb.json  # Multi-database Docker config
│   └── policies/
│       ├── default.json    # Minimal policy (8 rules)
│       ├── production.json # Production policy (13 rules)
│       └── waf.json        # Full WAF policy (30+ rules)
└── scripts/                # E2E test scripts
```

### Pipeline Flow

```
Client Request
  → Protocol Decode (PG/MySQL/MSSQL/MongoDB)
  → SQL Inspection (tokenize, classify, risk score, fingerprint)
  → Cost Estimation (0-100 heuristic)
  → Policy Evaluation (14 conditions, role/command/table match, cache)
    → SQLi Detection (tautology, UNION, stacked, blind, encoding)
    → Rate Limit Check (token bucket per policy)
    → Anomaly Detection (baseline + frequency spike)
  → Decision:
    ├── BLOCK → return error to client, audit log
    ├── ALLOW → forward to backend
    │   → Query Rewrite (auto-LIMIT, WHERE injection)
    │   → Forward Results (streaming)
    │     → Masking Pipeline (explicit rules + PII auto-detect)
    │     → Row Limit Enforcement
    │   → Latency Measurement → Slow Query Check
    │   → Audit Log + Metrics + Live Broadcast
    └── APPROVAL → hold for manual approve/deny
```

### Design Principles

1. **Invisible to applications** — same protocol, same tools, only connection target changes
2. **Streaming-first** — results processed per-row, never buffered entirely
3. **Policy-driven** — every decision comes from the policy engine, no hardcoded rules
4. **Defense in depth** — SQLi detection + risk scoring + cost limits + rate limiting + anomaly detection
5. **Observable** — every connection, command, and decision is logged and measurable

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Added latency per query | < 1ms (allow decisions) |
| Added latency with masking | < 5ms per 1000 rows |
| Max concurrent sessions | 10,000+ |
| Memory per session | < 64KB baseline |
| Audit throughput | 100,000 events/sec |
| Policy evaluation time | < 100μs (cached) |
| Startup time | < 2 seconds |
| Binary size | < 20MB |

---

## Roadmap

### Phase 1 — Core Proxy (Complete)
- [x] PostgreSQL Simple Query + Extended Query + COPY + SSL
- [x] MySQL wire protocol (handshake, COM_QUERY, prepared statements)
- [x] Auth passthrough mode
- [x] SQL inspection (tokenizer, classifier, risk scoring)
- [x] Policy engine (role, command, time, IP rules)
- [x] Streaming result masking (8 transformers)
- [x] Async audit logging (JSON, file/stdout)
- [x] Connection pooling with health checks
- [x] TLS support (client + backend)
- [x] Prometheus metrics & health endpoints
- [x] Configuration with env overrides

### Phase 2 — Production Hardening (Complete)
- [x] Admin REST API (26 endpoints + WebSocket)
- [x] SQL literal sanitization in audit logs
- [x] SIEM webhook export (batched HTTP POST)
- [x] Audit log file rotation + compaction
- [x] PII auto-detection (17 patterns, Luhn, TC Kimlik)
- [x] Graceful shutdown with connection draining
- [x] GitHub Actions CI/CD
- [x] Kubernetes readiness/liveness probes

### Phase 3 — Enterprise (Complete)
- [x] MSSQL TDS protocol (codec, Login7, SQL Batch, COLMETADATA masking)
- [x] Approval workflows (hold/approve/deny/timeout)
- [x] Live session monitoring (WebSocket)
- [x] Rate limiting per user/role (token bucket)
- [x] Anomaly detection (baseline + frequency spike)
- [x] Query fingerprinting + cost estimation
- [x] Audit search, session replay, top fingerprints
- [x] Policy dry-run, inheritance, validator
- [x] Connection pool circuit breaker + warmup
- [x] Certificate rotation without restart
- [x] LDAP authentication with group resolution
- [x] SSO/JWT authentication (HMAC-SHA256)

### Phase 4 — Database WAF (Complete)
- [x] MongoDB wire protocol (OP_MSG, BSON command extraction)
- [x] Web dashboard UI + interactive test runner
- [x] Plugin system (custom transformers, audit writers)
- [x] Data classification engine (5 sensitivity levels, 17 rules)
- [x] SQL injection detection (tautology, UNION, stacked, blind, encoding, system commands)
- [x] Schema enumeration blocking
- [x] System command blocking (xp_cmdshell, OUTFILE, LOAD_FILE)
- [x] Privilege escalation detection
- [x] Query complexity limits (length, tables, JOINs, cost)
- [x] WHERE clause enforcement
- [x] Sensitive table lockdown
- [x] Comprehensive WAF policy (30+ rules, 8 roles)
- [ ] Oracle TNS protocol support

---

## Testing

```bash
go test ./... -count=1          # Run all tests
go test ./... -v                # Verbose output
make test-cover                 # HTML coverage report
bash scripts/e2e-realworld.sh   # Real-world E2E (45 tests)
bash scripts/e2e-extra-scenarios.sh  # Extra scenarios (63 tests)
```

Current: **1307 unit tests + 171 E2E**, **84%+ coverage** (22 packages).

---

## Naming

**Argus Panoptes** (Argos Panoptes) — the all-seeing giant of Greek mythology. He had a hundred eyes and never slept. He sees everything.

---

## License

MIT

---

*ECOSTACK TECHNOLOGY OU*
