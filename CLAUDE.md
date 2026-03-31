# Argus — Database Firewall & Access Proxy

## Build & Test
```bash
go build ./...                          # build all packages
go build -o argus ./cmd/argus/          # build binary
go test ./... -count=1                  # run all tests
go test ./... -v                        # verbose test output
go test ./... -coverprofile=c.out       # coverage report
go test ./internal/inspection/ -bench=. # run benchmarks
go vet ./...                            # static analysis
make build                              # optimized binary with version
make test-cover                         # HTML coverage report
make cross-all                          # cross-compile linux/darwin/windows
./argus -config configs/argus.json      # run with config
./argus --version                       # show version
./argus --validate                      # validate config only
```

## Architecture
- **Zero external dependencies** — stdlib only, no CGO, single binary (~7.8MB)
- Config and policy files use JSON format
- 4 database protocols: PostgreSQL, MySQL, MSSQL, MongoDB
- Database WAF: SQLi detection, schema enumeration blocking, system command blocking
- 15 policy condition types including sql_injection, plan_cost_gte, require_where, max_joins, max_tables
- SQL Gateway: HTTP API for query submission with approval workflow and allowlist
- 1311+ unit tests, 92%+ coverage (22 packages)
- 171 E2E tests across 4 scripts: PG + MySQL CRUD, transactions, bulk data, error resilience, admin API, concurrent burst

### Key Packages (22 packages)
| Package | Purpose |
|---------|---------|
| `cmd/argus/` | Binary entry point, signal handling, component wiring |
| `internal/core/` | Listener, TLS, router, pipeline, approval workflow, cert rotation, banner |
| `internal/protocol/pg/` | PostgreSQL (Simple + Extended + COPY + SSL) |
| `internal/protocol/mysql/` | MySQL (COM_QUERY + prepared statements) |
| `internal/protocol/mssql/` | MSSQL TDS (Pre-Login, Login7, SQL Batch, result masking) |
| `internal/protocol/mongodb/` | MongoDB (OP_MSG + BSON extraction + error response) |
| `internal/inspection/` | Tokenizer, classifier, extractor, fingerprint, anomaly, splitter, cost |
| `internal/policy/` | Engine, matcher (14 conditions), WAF rules, cache, dry-run, validator |
| `internal/masking/` | Streaming pipeline, 8 transformers, PII auto-detection |
| `internal/ratelimit/` | Token bucket rate limiter |
| `internal/session/` | Lifecycle, identity, timeout, concurrency |
| `internal/pool/` | Dedicated + shared pool, circuit breaker, histogram, health |
| `internal/audit/` | Logger, rotation, webhook, recorder, search, replay, compaction, slow query |
| `internal/admin/` | 26 REST endpoints + WebSocket, auth middleware, dashboard UI, test runner |
| `internal/auth/` | LDAP (BER encoding, group resolution) + SSO (JWT/HMAC-SHA256) |
| `internal/cluster/` | Multi-instance shared session store |
| `internal/plugin/` | Plugin registry (TransformerPlugin, AuditWriterPlugin) |
| `internal/classify/` | Data classification engine (5 levels, 17 rules) |
| `internal/gateway/` | SQL Gateway HTTP API, query executor, allowlist, API key auth, webhook |
| `internal/config/` | Loading, validation, `$ENV{VAR}` expansion, env overrides, cross-reference |
| `internal/metrics/` | Counters, query latency histogram, per-protocol stats |
| `internal/plan/` | EXPLAIN-based query plan cost analysis (PostgreSQL + MySQL) |

### Pipeline Flow
```
Command → Inspect → Cost → Policy (14 conditions + SQLi detection) → Rate Limit
  → Anomaly → Approval (critical) → Forward → PII Auto-Mask
  → Result → Latency → Slow Query → Record → Audit → Broadcast
```

### Policy Condition Types
`sql_contains`, `sql_not_contains`, `sql_regex`, `sql_injection`, `risk_level_gte`,
`max_cost_gte`, `max_query_length`, `max_tables`, `max_joins`, `require_where`,
`work_hours`, `work_days`, `source_ip_in`, `source_ip_not_in`, `plan_cost_gte`

### Policy Files
- `configs/policies/default.json` — minimal (8 rules)
- `configs/policies/production.json` — production RBAC (13 rules)
- `configs/policies/waf.json` — full WAF (30+ rules, 8 roles)

## Conventions
- Protocol handlers implement `protocol.Handler` interface
- Masking is streaming — O(1) memory per row
- Audit logging is async via buffered channel (drops on overflow)
- Policy evaluation is cached (LRU, 60s TTL) with cache hit/miss counters
- Config supports `$ENV{VAR}` expansion in all string fields and `ARGUS_*` env overrides
- Rate limiter buckets auto-cleaned every 5 minutes (prevents memory leaks)
- Webhook writer flushed on graceful shutdown
- Policy files watched and hot-reloaded
- Tests use `net.Pipe()` for protocol-level testing
- Admin API uses `SessionProvider` interface to avoid import cycles
- Circuit breaker protects backend connections
- SQLi detection in `internal/policy/matcher.go` — `detectSQLInjection()` function
- Query plan cost analysis via EXPLAIN in `internal/plan/` — `ExplainPG()` and `ExplainMySQL()`
- mTLS client certificate auth via `config.TLSConfig.ClientAuth` + `ClientCAFile`
- Circuit breaker thresholds configurable via `pool.CircuitBreakerThreshold` + `CircuitBreakerResetTimeout`
