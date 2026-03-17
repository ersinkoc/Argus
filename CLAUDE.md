# Argus — Database Access Proxy

## Project Overview
Protocol-aware database access proxy written in Go. Sits between applications and databases to enforce access policies, mask sensitive data, and log everything for audit.

## Build & Test
```bash
go build ./...                          # build all packages
go test ./... -count=1                  # run all tests
go test ./internal/inspection/ -v       # run specific package tests
make build                              # optimized binary with version
make test                               # run all tests
make test-cover                         # test with coverage report
make cross-all                          # cross-compile linux/darwin/windows
./argus -config configs/argus.json      # run with config
./argus --version                       # check version
```

## Architecture
- **Zero external dependencies** — stdlib only, no CGO, single binary (~7MB)
- Config and policy files use JSON format (no external YAML dependency)
- TLS support for both client-facing listeners and backend connections

### Key Packages
| Package | Purpose |
|---------|---------|
| `cmd/argus/` | Main binary entry point |
| `internal/core/` | TCP listener (with TLS), router, pipeline orchestrator |
| `internal/protocol/pg/` | PostgreSQL wire protocol (Simple Query) |
| `internal/inspection/` | SQL tokenizer, classifier, table/column extractor |
| `internal/policy/` | Policy engine, JSON loader, rule matching, decision cache |
| `internal/masking/` | Streaming result masking, 8 built-in transformers |
| `internal/session/` | Session lifecycle, identity, timeout |
| `internal/pool/` | Backend connection pooling, health checks |
| `internal/audit/` | Async structured audit logging |
| `internal/config/` | Configuration loading, validation, env overrides |
| `internal/admin/` | Prometheus metrics, health endpoint, session API |

### Data Flow
```
Client → Listener → Protocol Handler (auth) → Session → Command Loop:
  ReadCommand → Inspect SQL → Policy Evaluate → Allow/Block/Mask → Forward → Result → Audit
```

## Conventions
- All protocol handlers implement `protocol.Handler` interface
- Masking is streaming — O(1) memory per row, no buffering
- Audit logging is async via buffered channel (drops on overflow, never blocks)
- Policy evaluation is cached (LRU, 60s TTL, invalidated on reload)
- Config supports `$ENV{VAR}` for secrets and `ARGUS_*` env overrides
- Policy files are watched for changes and hot-reloaded every 5s
- Tests use `net.Pipe()` for protocol-level integration testing
