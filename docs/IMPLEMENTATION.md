# Implementation Notes

## Architecture Decisions

### JSON over YAML for Configuration

The specification calls for YAML configuration. We chose **JSON** instead because:

1. **Zero dependencies** — Go's standard library includes `encoding/json` but not a YAML parser
2. **No ambiguity** — JSON parsing is deterministic, no YAML gotchas (e.g., `no` becoming `false`)
3. **Tooling** — JSON is universally supported by editors, validators, and APIs
4. **Migration path** — a YAML front-end can be added in Phase 2 if desired

### Auth Passthrough Mode

The MVP implements **passthrough authentication** only:

1. Client sends startup message with credentials
2. Argus forwards the startup message to the backend verbatim
3. Backend performs actual authentication
4. Argus relays auth challenge/response messages between client and backend
5. Argus observes the username but never stores passwords

This means Argus sees the auth result but doesn't independently verify credentials. The benefit is simplicity and full compatibility with all PostgreSQL auth methods (cleartext, MD5, SCRAM-SHA-256).

**Proxy auth mode** (Phase 2) will decouple client identity from database credentials.

### SSL/TLS Handling

For the MVP, when a client sends an SSLRequest:

- Argus responds with `N` (SSL not supported at protocol level)
- The client falls back to unencrypted protocol
- **However**, the TCP listener itself can be TLS-enabled via configuration
- This means the connection IS encrypted at the transport layer, just not via the PostgreSQL SSLRequest mechanism

Full PostgreSQL-native SSL negotiation will be added in Phase 2.

### Streaming Masking Pipeline

The masking decision is made **once** at query time, not per-row:

```
1. Client sends: SELECT name, email, salary FROM employees
2. Policy engine returns: email → partial_email, salary → redact
3. Backend returns RowDescription: [name=col0, email=col1, salary=col2]
4. Pipeline creates: column_map = {1: partial_email, 2: redact}
5. For every DataRow: apply transforms at col1 and col2
```

Cost per row: one map lookup per masked column + transform function call. This is O(1) per row.

Memory per session: O(single_row_size), not O(result_set_size).

### Policy Evaluation Order

1. Policies are evaluated **top-to-bottom** (array order in JSON)
2. **First match wins** — once a policy matches, evaluation stops
3. Masking rules are cumulative — multiple policies can contribute masking rules
4. If no policy matches, `defaults.action` applies

This means more specific rules should come before general ones.

### Decision Cache

Policy decisions for identical contexts are cached:

- **Key**: SHA-256 hash of (username, roles, database, command_type, tables)
- **TTL**: 60 seconds (configurable)
- **Size**: bounded at 10,000 entries with 50% eviction on overflow
- **Invalidation**: entire cache cleared on policy file reload

The cache avoids re-evaluating the same rules for repeated query patterns.

### Audit Logger Design

The audit logger uses an **async buffered channel** pattern:

```go
auditChan := make(chan AuditEvent, 10000)
```

- Events are sent to the channel non-blocking
- If the buffer is full, events are **dropped** (with a counter), never blocking the proxy
- A dedicated goroutine reads from the channel and writes to output
- On shutdown, remaining events are drained before closing

This ensures the proxy pipeline is never blocked by slow I/O.

## Wire Protocol Details

### PostgreSQL Simple Query Flow

```
Client                    Argus                    Backend
  │                         │                         │
  │──── Query('SELECT..') ──>│                         │
  │                         │──── Query('SELECT..') ──>│
  │                         │<── RowDescription ───────│
  │<── RowDescription ──────│                         │
  │                         │<── DataRow ─────────────│
  │<── DataRow (masked) ────│                         │
  │                         │<── DataRow ─────────────│
  │<── DataRow (masked) ────│                         │
  │                         │<── CommandComplete ─────│
  │<── CommandComplete ─────│                         │
  │                         │<── ReadyForQuery ───────│
  │<── ReadyForQuery ───────│                         │
  │                         │                         │
```

### Message Format

All PostgreSQL messages (except startup) follow this format:

```
┌──────┬──────────┬─────────┐
│ Type │  Length  │ Payload │
│ 1B   │  4B     │ N bytes │
└──────┴──────────┴─────────┘
```

- Type: single byte identifying the message kind
- Length: 32-bit big-endian integer including itself (4 + payload length)
- Payload: message-specific data

### Startup Message Format

Startup messages have no type byte:

```
┌──────────┬─────────────────┬─────────────────────┐
│  Length  │ Protocol Version │ Parameters (k=v\0)  │
│  4B     │  4B (196608)    │ null-terminated pairs │
└──────────┴─────────────────┴─────────────────────┘
```

## File Conventions

| File | Format | Purpose |
|------|--------|---------|
| `argus.json` | JSON | Main configuration |
| `policies/*.json` | JSON | Policy rule files |
| `audit.jsonl` | JSON Lines | Audit log output |
| Prometheus `/metrics` | Text | Prometheus exposition format |
