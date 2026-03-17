# Argus — Database Access Proxy

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
- **Zero external dependencies** — stdlib only, no CGO, single binary (~7.7MB)
- Config and policy files use JSON format
- 4 database protocols: PostgreSQL, MySQL, MSSQL, MongoDB
- 919 tests, 91.5% coverage (19/19 packages at 90%+, 4 at 100%)

### Key Packages (21 packages)
| Package | Purpose |
|---------|---------|
| `cmd/argus/` | Binary entry point, signal handling, component wiring |
| `internal/core/` | Listener, TLS, router, pipeline, approval workflow, cert rotation, banner |
| `internal/protocol/pg/` | PostgreSQL (Simple + Extended + COPY + SSL) |
| `internal/protocol/mysql/` | MySQL (COM_QUERY + prepared statements) |
| `internal/protocol/mssql/` | MSSQL TDS (Pre-Login, Login7, SQL Batch, result masking) |
| `internal/inspection/` | Tokenizer, classifier, extractor, fingerprint, anomaly, splitter, cost |
| `internal/policy/` | Engine, matcher, cache, dry-run, inheritance, validator |
| `internal/masking/` | Streaming pipeline, 8 transformers, PII auto-detection |
| `internal/ratelimit/` | Token bucket rate limiter |
| `internal/session/` | Lifecycle, identity, timeout, tagging |
| `internal/pool/` | Dedicated + shared pool, circuit breaker, histogram, health |
| `internal/audit/` | Logger, rotation, webhook, recorder, search, replay, compaction, slow query |
| `internal/admin/` | 23 REST endpoints + WebSocket, auth middleware |
| `internal/protocol/mongodb/` | MongoDB (OP_MSG + BSON extraction) |
| `internal/auth/` | LDAP (BER encoding) + SSO (JWT/HMAC-SHA256) |
| `internal/cluster/` | Multi-instance shared session store |
| `internal/plugin/` | Plugin registry (TransformerPlugin, AuditWriterPlugin) |
| `internal/classify/` | Data classification engine (5 levels, 17 rules) |
| `internal/config/` | Loading, validation, env overrides, cross-reference |
| `internal/metrics/` | Counters, query latency histogram |

### Pipeline Flow
```
Command → Inspect → Cost → Policy (8 conditions + cost) → Rate Limit
  → Anomaly → Approval (critical) → Forward → PII Auto-Mask
  → Result → Latency → Slow Query → Record → Audit → Broadcast
```

## Conventions
- Protocol handlers implement `protocol.Handler` interface
- Masking is streaming — O(1) memory per row
- Audit logging is async via buffered channel (drops on overflow)
- Policy evaluation is cached (LRU, 60s TTL)
- Config supports `$ENV{VAR}` for secrets and `ARGUS_*` env overrides
- Policy files watched and hot-reloaded
- Tests use `net.Pipe()` for protocol-level testing
- Admin API uses `SessionProvider` interface to avoid import cycles
- Circuit breaker protects backend connections
