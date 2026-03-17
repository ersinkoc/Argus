# Argus

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
- **Protocol-native proxy** — speaks PostgreSQL wire protocol natively, not JDBC/ODBC wrapping
- **Zero external dependencies** — standard library only, no CGO, single binary (~7MB)
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

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET :9091/healthz` | Health status, per-target backend health, session count |
| `GET :9091/metrics` | Prometheus-format metrics |
| `GET :9091/api/sessions` | List active sessions |

---

## Architecture

```
argus/
├── cmd/argus/              # Binary entry point
├── internal/
│   ├── core/               # TCP listener, TLS, router, pipeline orchestrator
│   ├── protocol/
│   │   ├── handler.go      # ProtocolHandler interface
│   │   └── pg/             # PostgreSQL wire protocol
│   │       ├── codec.go    # Message encode/decode
│   │       ├── auth.go     # Authentication handshake (passthrough)
│   │       ├── query.go    # Query message handling
│   │       └── result.go   # Streaming result forwarding + masking
│   ├── inspection/         # SQL tokenizer, classifier, table extractor
│   ├── policy/             # Policy engine, rule matching, decision cache
│   ├── masking/            # Streaming transformers pipeline
│   ├── session/            # Session lifecycle, identity, timeout
│   ├── pool/               # Backend connection pool, health check
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

### Phase 2 — Production Hardening
- [ ] MySQL wire protocol
- [ ] PostgreSQL Extended Query (prepared statements)
- [ ] PostgreSQL COPY protocol
- [ ] Admin REST API (session management)
- [ ] Proxy auth mode (decouple client/DB credentials)
- [ ] SIEM export (syslog, webhook)
- [ ] PII auto-detection
- [ ] Graceful shutdown with connection draining

### Phase 3 — Enterprise
- [ ] MSSQL TDS protocol
- [ ] LDAP/SSO integration
- [ ] Approval workflows for high-risk commands
- [ ] Live session monitoring (WebSocket)
- [ ] Rate limiting per user/role
- [ ] Multi-instance clustering

### Phase 4 — Platform
- [ ] Oracle TNS support
- [ ] MongoDB wire protocol
- [ ] Web dashboard UI
- [ ] Kubernetes operator
- [ ] Terraform provider

---

## Testing

```bash
make test              # Run all tests
make test-verbose      # Verbose output
make test-cover        # Coverage report (HTML)
```

Current: **45 tests** across 8 packages, **50.6% coverage**.

---

## Naming

**Argus Panoptes** (Argos Panoptes) — the all-seeing giant of Greek mythology. He had a hundred eyes and never slept. He sees everything.

---

## License

TBD (MIT or dual MIT/Enterprise)

---

*ECOSTACK TECHNOLOGY OU*
