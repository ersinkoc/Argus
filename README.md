# Argus

[![CI](https://github.com/ersinkoc/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/ersinkoc/argus/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-green.svg)](#)

**The Hundred-Eyed Database Guardian**

> *Know who connects. Control what they do. Protect what they see.*

Argus is a protocol-aware database access proxy written in Go. It sits between applications and databases — inspecting every connection, enforcing access policies in real time, masking sensitive data at the result level, and logging everything for audit and compliance.

```
┌──────────┐         ┌──────────────────────────────────────────┐         ┌──────────┐
│          │   TCP   │                 Argus                    │   TCP   │          │
│  Client  │────────>│  ┌─────────┐  ┌────────┐  ┌──────────┐ │────────>│ Database │
│  (App)   │<────────│  │Protocol │  │ Policy │  │ Masking  │ │<────────│ Server   │
│          │         │  │ Handler │  │ Engine │  │ Pipeline │ │         │          │
└──────────┘         │  └─────────┘  └────────┘  └──────────┘ │         └──────────┘
                     │  ┌─────────┐  ┌────────┐  ┌──────────┐ │
                     │  │Session  │  │ Audit  │  │Connection│ │
                     │  │Manager  │  │ Logger │  │  Pool    │ │
                     │  └─────────┘  └────────┘  └──────────┘ │
                     └──────────────────────────────────────────┘
```

---

## Why Argus?

Traditional PAM tools manage credentials. They answer **"who connected."**
They do not answer **"what did they do"** or **"what did they see."**

Argus answers all three:

| Question | Capability |
|----------|-----------|
| **Who connected?** | Session-level identity, role mapping, IP tracking |
| **What did they do?** | Command-level inspection, classification, risk scoring |
| **What did they see?** | Result-level filtering, column masking, row limits |

---

## Features

### Core
- **4 database protocols** — PostgreSQL, MySQL, MSSQL TDS, and MongoDB wire protocols
- **Protocol-native proxy** — speaks each database's wire protocol natively, not JDBC/ODBC wrapping
- **Zero external dependencies** — standard library only, no CGO, single binary (~7.8MB)
- **Web dashboard** — embedded real-time UI at `/ui` with auto-refresh
- **Streaming architecture** — O(1) memory per row, no full result set buffering
- **TLS support** — client-facing and backend connections, two-segment TLS

### Policy Engine
- **Declarative policies** — JSON-based rules, no code changes needed
- **Role-based access** — wildcard user matching, negation support (`!dba`)
- **Command-type rules** — allow/block/mask by SELECT, INSERT, UPDATE, DELETE, DDL, DCL
- **Time-based rules** — office hours, work days enforcement
- **IP-based rules** — CIDR range restrictions
- **Risk scoring** — automatic detection of dangerous patterns (DROP, bulk DELETE, injection)
- **Hot-reload** — policy files watched and reloaded without restart
- **Decision cache** — LRU cache with TTL for repeated query patterns

### Data Masking
- **Column-level masking** — per-column transformer rules
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
- **Streaming** — masking applied per-row without buffering

### Audit & Observability
- **Structured JSON audit logs** — every connection, command, and decision recorded
- **Three log levels** — minimal, standard, verbose
- **Async logging** — buffered channel, never blocks the proxy pipeline
- **Prometheus metrics** — connections, commands, masking, pool stats, Go runtime
- **Health endpoint** — per-target backend health, session count

---

## Quick Start

### Build

```bash
# Build
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
    "files": ["policies/default.json"],
    "reload_interval": "5s"
  },
  "audit": {
    "level": "standard",
    "outputs": [{"type": "stdout"}]
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

Run Argus with PostgreSQL, MySQL, and MSSQL in Docker:

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

# View Argus logs
make docker-logs

# Dashboard
curl http://localhost:30200/api/dashboard | jq

# Stop
make docker-down
```

---

## Policy Examples

### Block destructive DDL for non-DBAs

```json
{
  "name": "block-destructive-ddl",
  "match": {
    "roles": ["!dba"],
    "commands": ["DDL"]
  },
  "condition": {
    "sql_contains": ["DROP", "TRUNCATE"]
  },
  "action": "block",
  "reason": "Destructive DDL requires DBA role"
}
```

### Mask PII for support team

```json
{
  "name": "mask-pii-for-support",
  "match": {
    "roles": ["support"],
    "commands": ["SELECT"]
  },
  "masking": [
    {"column": "email", "transformer": "partial_email"},
    {"column": "phone", "transformer": "partial_phone"},
    {"column": "tc_kimlik", "transformer": "redact"},
    {"column": "card_number", "transformer": "partial_card"},
    {"column": "salary", "transformer": "redact"}
  ]
}
```

### Block bulk writes without WHERE

```json
{
  "name": "block-bulk-writes",
  "match": {
    "commands": ["DELETE", "UPDATE"]
  },
  "condition": {
    "risk_level_gte": "medium"
  },
  "action": "block",
  "reason": "Bulk write operations require WHERE clause"
}
```

### Restrict production access to office network

```json
{
  "name": "ip-restriction-production",
  "match": {
    "databases": ["production", "prod_*"]
  },
  "condition": {
    "source_ip_not_in": ["10.0.0.0/8", "172.16.0.0/12"]
  },
  "action": "block",
  "reason": "Production access restricted to office network"
}
```

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

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Health status, per-target backend health, session count |
| `/metrics` | GET | Prometheus-format metrics |
| `/api/sessions` | GET | List active sessions with details |
| `/api/sessions/kill?id=` | POST | Kill a session by ID |
| `/api/policies/reload` | POST | Hot-reload policy files |
| `/api/stats` | GET | Runtime statistics (memory, goroutines, counters) |
| `/api/approvals` | GET | List pending approval requests |
| `/api/approvals/approve?id=` | POST | Approve a pending command |
| `/api/approvals/deny?id=` | POST | Deny a pending command |
| `/api/audit/search?username=&action=` | GET | Search audit logs |
| `/api/audit/replay?session_id=` | GET | Replay a session's queries |
| `/api/audit/fingerprints?limit=` | GET | Top query patterns |
| `/api/audit/compact` | POST | Clean up old audit log files |
| `/api/policies/dryrun?username=&sql=` | POST | Test policy without enforcing |
| `/api/config/export` | GET | Export current configuration |
| `/api/audit/export?username=` | GET | CSV export of audit events |
| `/api/pool/health` | GET | Per-target pool health summary |
| `/api/health/deep` | GET | Deep TCP health check with latency |
| `/api/policies/validate` | GET | Validate policy rules for conflicts |
| `/api/dashboard` | GET | Aggregated dashboard data |
| `/ready` | GET | Kubernetes readiness probe |
| `/livez` | GET | Kubernetes liveness probe |
| `/api/events/ws` | WebSocket | Live event stream |

---

## Architecture

```
argus/
├── cmd/argus/              # Binary entry point
├── internal/
│   ├── core/               # Listener, TLS, router, pipeline, approval workflow
│   ├── protocol/
│   │   ├── handler.go      # ProtocolHandler interface
│   │   ├── pg/             # PostgreSQL (Simple + Extended + COPY + SSL)
│   │   ├── mysql/          # MySQL (COM_QUERY, handshake, result sets)
│   │   └── mssql/          # MSSQL TDS (Pre-Login, Login7, SQL Batch)
│   ├── inspection/         # Tokenizer, classifier, fingerprint, anomaly, splitter
│   ├── policy/             # Policy engine, rule matching, decision cache
│   ├── masking/            # Streaming pipeline, PII auto-detection
│   ├── ratelimit/          # Token bucket rate limiter
│   ├── session/            # Session lifecycle, identity, timeout
│   ├── pool/               # Connection pool (dedicated + shared), histogram
│   ├── audit/              # Async structured audit logging
│   ├── config/             # Configuration loading, validation
│   └── admin/              # Metrics, health, session API
├── configs/                # Example configuration files
└── docs/                   # Documentation
```

### Design Principles

1. **Invisible to applications** — same protocol, same tools, only connection target changes
2. **Streaming-first** — results processed per-row, never buffered entirely
3. **Policy-driven** — every decision comes from the policy engine, no hardcoded rules
4. **Observable** — every connection, command, and decision is logged
5. **Modular** — each database protocol is an independent adapter

---

## Performance Targets

| Metric | Target |
|--------|--------|
| Added latency per query | < 1ms (allow decisions) |
| Added latency with masking | < 5ms per 1000 rows |
| Max concurrent sessions | 10,000+ |
| Memory per session | < 64KB baseline |
| Audit throughput | 100,000 events/sec |
| Policy evaluation time | < 100us (cached) |
| Startup time | < 2 seconds |
| Binary size | < 20MB |

---

## Roadmap

### Phase 1 — MVP (Current)
- [x] PostgreSQL Simple Query protocol
- [x] Auth passthrough mode
- [x] SQL inspection (tokenizer, classifier, risk scoring)
- [x] Policy engine (role, command, time, IP rules)
- [x] Streaming result masking (8 transformers)
- [x] Async audit logging (JSON, file/stdout)
- [x] Connection pooling with health checks
- [x] TLS support (client + backend)
- [x] Prometheus metrics & health endpoint
- [x] Configuration with env overrides

### Phase 2 — Production Hardening (Complete)
- [x] MySQL wire protocol (handshake, COM_QUERY, prepared statements, masking)
- [x] PostgreSQL Extended Query (Parse/Bind/Describe/Execute/Sync)
- [x] PostgreSQL COPY protocol (CopyIn/CopyOut passthrough)
- [x] Admin REST API (23 endpoints + WebSocket)
- [x] SQL literal sanitization in audit logs
- [x] SIEM webhook export (batched HTTP POST)
- [x] Audit log file rotation + compaction
- [x] PII auto-detection (15 patterns, Luhn, TC Kimlik)
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
- [x] Admin API token authentication
- [x] Session tagging
- [x] Slow query logging
- [x] Query latency histogram (p50/p95/p99)

### Phase 4 — Extended Platform (Complete)
- [x] MongoDB wire protocol (OP_MSG, BSON command extraction)
- [x] Web dashboard UI (embedded HTML/CSS/JS, real-time at `/ui`)
- [x] Plugin system (custom transformers, audit writers, registry)
- [x] Data classification engine (5 sensitivity levels, 17 rules)
- [ ] Oracle TNS support
- [ ] Kubernetes operator
- [ ] Terraform provider

---

## Testing

```bash
make test              # Run all tests
make test-verbose      # Verbose output
make test-cover        # Coverage report (HTML)
```

Current: **760 unit tests + 107 E2E = 867 total**, **85% coverage** (8 packages > 95%).

### Web Dashboard

Access the real-time dashboard at `http://localhost:30200/ui` (or your admin port).
Shows sessions, commands, targets, health status — auto-refreshes every 5s.

---

## Naming

**Argus Panoptes** (Argos Panoptes) — the all-seeing giant of Greek mythology. He had a hundred eyes and never slept. He sees everything.

---

## License

TBD (MIT or dual MIT/Enterprise)

---

*ECOSTACK TECHNOLOGY OU*
