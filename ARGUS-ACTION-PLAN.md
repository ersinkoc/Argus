# Argus — Action Plan

**Derived from:** `ARGUS-COMPREHENSIVE-REVIEW.md`  
**Date:** 2026-07-15  
**Goal:** Prioritized, actionable work items addressing every finding in the review, with scoped effort estimates and file-level references.

---

## How to Read This Plan

Each action item has:

- **ID**: Unique key for tracking (e.g., `A-01`)
- **Title**: Short description
- **Priority**: Critical → High → Medium → Low
- **Area**: Which module/package it affects
- **Effort**: Small (< 1d), Medium (1–3d), Large (1–2w), X-Large (> 2w)
- **Files**: Key files that need changes (representative, not exhaustive)
- **Description**: What the problem is and what to do about it
- **Dependencies**: Items this blocks or is blocked by
- **Risk**: Impact of deferring this item

The items are grouped into **phases** suitable for sprint planning:

| Phase | Horizon | Focus |
|-------|---------|-------|
| **Phase 0 — Firefighting** | Week 1 | Security fixes (critical + high) |
| **Phase 1 — Core Hardening** | Sprint 1–2 | Gateway coverage, cache, pagination, anomaly |
| **Phase 2 — Quality Infrastructure** | Sprint 3–4 | Fuzz, property tests, config polish |
| **Phase 3 — Feature Maturation** | Sprint 5–8 | Protocol parity, gateway executors |
| **Phase 4 — Platform** | Quarter 2+ | Infrastructure, automation, stretch |

---

## Phase 0 — Firefighting (Week 1)

These are the items where the current state poses a genuine risk to production use. Do these first.

### A-01: Fix SHA-256 prefix collision in hash transformer

| Field | Value |
|-------|-------|
| **Priority** | Critical |
| **Area** | `internal/masking` |
| **Effort** | Small (~2h) |
| **File** | `internal/masking/transformers.go:124–126` |

**Problem:** The `hashValue` transformer uses only the first 4 bytes (8 hex chars) of SHA-256. Per the birthday paradox, this has a ~49% collision probability after ~65K hashed values. For a data masking use case, collisions mean two distinct plaintexts produce the same masked output, which can lead to data corruption or misattribution.

**Action:** Change the hash prefix from 4 bytes to **16 bytes** (32 hex chars) — half of SHA-256, or make it **configurable** via a parameter on the transformer. 16 bytes (128 bits) has a negligible collision probability (< 2⁻⁶⁴ at 64K values).

```go
// Current (line 124–126):
func hashValue(value []byte) []byte {
    h := sha256.Sum256(value)
    return []byte(hex.EncodeToString(h[:4]))
}

// Fixed:
func hashValue(value []byte) []byte {
    h := sha256.Sum256(value)
    return []byte(hex.EncodeToString(h[:16])) // 16 bytes = 32 hex chars
}
```

**Risk of deferring:** Data corruption in masked result sets. A downstream system that relies on masked output uniqueness (e.g., joining on hashed values) will produce wrong results.

---

### A-02: Move WebSocket auth token from query string to header/first-frame

| Field | Value |
|-------|-------|
| **Priority** | Critical |
| **Area** | Admin UI + admin WebSocket |
| **Effort** | Small (~4h) |
| **Files** | `admin-ui/src/hooks/useWebSocket.ts:29`, `internal/admin/websocket.go`, `internal/admin/server.go` |

**Problem:** The WebSocket auth token is passed as a URL query parameter (`wss://host/api/events/ws?token=...`). Query strings are:
1. Logged verbatim by most reverse proxies, load balancers, and CDNs
2. Visible in browser history and `document.referrer`
3. Not covered by TLS URL encryption (the full URL, including query string, can appear in TLS handshake SNI logs in some configurations)

**Action:** Replace the query-string approach with one of:
- **Option A (simplest)**: Send the token as a custom HTTP header during the WebSocket upgrade (`Authorization: Bearer ...`). The Go server can inspect the upgrade headers.
- **Option B (more secure)**: Use first-frame authentication — after the WebSocket handshake, the client sends a JSON auth frame, and the server validates it before allowing event streaming. This requires a two-phase WebSocket protocol.

**Recommendation:** Option A is simpler and sufficient. Validate the `Authorization` header during the HTTP upgrade phase in `handleEventsWS`:

```go
// In internal/admin/server.go handleEventsWS:
auth := r.Header.Get("Authorization")
if !validateToken(auth) {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
```

Update the React hook to set the header during WebSocket construction (via `protocols` array or custom header — note that browsers don't allow custom headers on `new WebSocket()`, so the best approach is **first-frame auth** for browser contexts):

```typescript
// In admin-ui/src/hooks/useWebSocket.ts:
// Send token as first message after connection
ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", token }))
}
```

**Risk of deferring:** Credential leakage into access logs, proxy logs, and browser history. The common practice of sharing dashboard URLs makes this worse.

---

### A-03: Add `$FILE{}` credential reference syntax

| Field | Value |
|-------|-------|
| **Priority** | High |
| **Area** | `internal/config` |
| **Effort** | Small (~4h) |
| **Files** | `internal/config/config.go`, `internal/config/env_helpers.go` |

**Problem:** Config supports `$ENV{VAR}` for environment variable secrets but has no `$FILE{/path/to/secret}` syntax for Docker secrets, Kubernetes mounted secrets, or HashiCorp Vault agent files. Docker/K8s deployments must use env vars to inject secrets, which is against best practices (K8s Secrets as env vars are visible in `/proc` and `kubectl describe`).

**Action:** Add a `$FILE{}` syntax alongside the existing `$ENV{}` syntax. The resolver reads the file path and returns its contents (trimmed of trailing newlines). Implementation is ~20 lines in the config expansion logic:

```go
// ResolveValue replaces $ENV{NAME} and $FILE{/path/to/secret} references.
func ResolveValue(v string) string {
    // existing $ENV{} logic…
    for strings.Contains(v, "$ENV{") {
        // …
    }
    // new $FILE{} logic
    for strings.Contains(v, "$FILE{") {
        start := strings.Index(v, "$FILE{")
        end := strings.Index(v[start:], "}")
        if end < 0 { break }
        path := v[start+6 : start+end]
        data, err := os.ReadFile(path)
        if err != nil { break }
        v = v[:start] + strings.TrimRight(string(data), "\n\r") + v[start+end+1:]
    }
    return v
}
```

**Risk of deferring:** K8s deployments continue using env-var-based secrets, which is a well-documented security anti-pattern.

---

## Phase 1 — Core Hardening (Sprint 1–2)

### A-04: Raise gateway test coverage from 40% to 90%+

| Field | Value |
|-------|-------|
| **Priority** | Critical |
| **Area** | `internal/gateway` |
| **Effort** | Large (~5–8d) |
| **Files** | `internal/gateway/gateway.go`, `internal/gateway/executor.go`, `internal/gateway/executor_mysql.go`, `internal/gateway/handler.go`, `internal/gateway/auth.go`, `internal/gateway/allowlist.go`, `internal/gateway/webhook.go` (test files for each) |

**Problem:** The gateway package (which executes arbitrary SQL via HTTP — the highest-risk surface area in the project) has only 40% test coverage. This is dangerously low for a production service that:
1. Accepts user-supplied SQL over HTTP
2. Routes it through policy evaluation, masking, and execution
3. Returns results to the caller

**Action:** Write tests covering the following scenarios. The existing 8 test files (`gateway_test.go`, `gateway_behavior_test.go`, `executor_test.go`, `executor_mysql_test.go`, `full_executor_test.go`, `api_error_test.go`, `api_error_test.go`, `allowlist_test.go`, `api_key_rotation_test.go`) need expansion.

| Target | Current | Goal | Key scenarios |
|--------|---------|------|---------------|
| `Gateway.HandleQuery` | low | 90%+ | block, allow, masked, pending_approval, error paths, rate limit, auth failures |
| `Gateway.HandleApprove` | low | 90%+ | approve, deny, not found, already decided, timeout |
| `Gateway.HandleAllowlist` | low | 90%+ | add, get, delete, not found, duplicates |
| `Gateway.HandleDryRun` | low | 90%+ | valid query, invalid query, empty SQL, auth |
| `executor` (PG) | low | 85%+ | query success, connection error, auth error, timeout, result streaming |
| `executor_mysql` | low | 85%+ | same as PG executor |
| `allowlist` | medium | 95%+ | CRUD, persistence, concurrent access |
| `auth` (API keys) | medium | 95%+ | valid key, invalid key, expired key, rotation, disabled key |

**Test patterns to follow:** The rest of the codebase has excellent testing patterns — per-function unit tests, table-driven tests, and integration tests. The gateway should follow the same conventions.

**Dependencies:** A-01, A-02 (fix security issues in code paths that tests will cover)  
**Risk of deferring:** Highest-risk module in the project remains poorly tested. A bug here allows SQL injection bypass, auth bypass, or data leakage over the gateway HTTP API.

---

### A-05: Replace decision cache eviction with LRU

| Field | Value |
|-------|-------|
| **Priority** | High |
| **Area** | `internal/policy` |
| **Effort** | Small (~3–4h) |
| **File** | `internal/policy/engine.go:250–259` |

**Problem:** When the decision cache (10K entries) is full, it evicts "an arbitrary half" of entries by iterating the map and deleting the first `maxSize/2` entries it encounters. Go map iteration order is randomized, so this is effectively random eviction. This means:
1. A frequently-hit entry could be evicted while a never-used-again entry stays
2. Cache hit ratio degrades unnecessarily under steady-state load
3. Performance is inconsistent — a burst of unique queries can evict the entire working set

**Action:** Replace the eviction with a simple LRU (Least Recently Used) strategy. Go's `container/list` or a simple timestamp-based approach would work. The `decisionCache` already has TTL-based expiry cleanup (line 240–248), so the eviction threshold only matters when the cache is hot and full:

```go
// Option: timestamp-based LRU
// On eviction, find and remove the entry with the oldest access time.
type cacheEntry struct {
    decision  *Decision
    expiry    time.Time
    lastAccess time.Time // for LRU ordering
}
```

Alternatively, use `container/list` + `map[string]*list.Element` for O(1) evictions.

**Risk of deferring:** Reduced cache effectiveness under production load. Policy evaluation time target (< 100μs cached) could be missed for common query patterns if they're frequently evicted.

---

### A-06: Implement cursor-based pagination for session/audit list endpoints

| Field | Value |
|-------|-------|
| **Priority** | High |
| **Area** | `internal/admin` |
| **Effort** | Medium (~2d) |
| **Files** | `internal/admin/server.go`, `internal/admin/audit_handlers.go`, `internal/session/manager.go`, `admin-ui/src/lib/api.ts`, `admin-ui/src/pages/SessionsPage.tsx`, `admin-ui/src/pages/AuditPage.tsx` |

**Problem:** The API design standard declares cursor-based pagination (`GET /sessions?cursor=abc&limit=20`), but the actual session listing and audit search endpoints return everything unfiltered (`GET /api/sessions` — no pagination; `GET /api/audit/search` — limit-only, no cursor). Under load with 1,000+ sessions or 1M+ audit entries, these endpoints will:
1. Return massive payloads (MBs of JSON)
2. Cause high memory usage on the server
3. Time out the HTTP response
4. Freeze the admin UI

**Action:**

1. **Session listing**: Add `cursor` (session ID) and `limit` (default 20, max 100) query parameters. The session manager needs a cursor-based iteration method on `sync.Map`.
2. **Audit search**: Add `cursor` parameter (event ID or timestamp). The audit search layer (`audit.SearchFile`) needs cursor-aware file scanning.
3. **Response shape**: Add `nextCursor` and `hasMore` fields to JSON responses, matching the declared API design standard.
4. **API client**: Update `api.ts` with pagination parameters and response types.
5. **UI pages**: Add "Load more" or infinite scroll to sessions and audit log pages.

**Risk of deferring:** Admin UI becomes unusable at moderate scale. Backend processes O(n) data for every request.

---

### A-07: Harden anomaly detector frequency spike tracking

| Field | Value |
|-------|-------|
| **Priority** | High |
| **Area** | `internal/inspection` |
| **Effort** | Small (~3–4h) |
| **File** | `internal/inspection/anomaly.go:33–37` |

**Problem:** The anomaly detector tracks frequency spikes via a single per-minute counter (`recentMinute`). This means:
1. A burst of 100 queries in 2 seconds followed by 58 seconds of silence still shows as a spike in the minute bucket
2. A slow ramp from 10 qps to 50 qps over 5 minutes might not trigger any single minute bucket
3. Sub-minute patterns (e.g., 30 queries in 1 second every 30 seconds) are invisible

**Action:** Replace the single-minute counter with a **sliding window** of shorter buckets (e.g., 10-second sub-buckets within a 1-minute window). This is a small change to `userProfile`:

```go
type userProfile struct {
    // … existing fields …
    // Replace:
    //   recentMinute int64
    //   minuteStart  time.Time
    // With:
    subBuckets [6]int64   // six 10-second buckets
    bucketIdx  int
    bucketTime time.Time
}
```

When a query comes in, advance buckets if `time.Since(bucketTime) > 10s`. Sum all buckets for the per-minute rate. This catches sharp spikes that a single-minute counter would smooth out.

**Risk of deferring:** An attacker could exfiltrate data via a burst pattern that stays within the per-minute average but involves sharp sub-minute peaks.

---

### A-08: Make circuit breaker thresholds user-configurable

| Field | Value |
|-------|-------|
| **Priority** | High |
| **Area** | `internal/pool` |
| **Effort** | Small (~3h) |
| **Files** | `internal/pool/circuitbreaker.go`, `internal/pool/pool.go`, `internal/config/config.go` |

**Problem:** The circuit breaker has hardcoded thresholds (failure count, half-open retry interval, etc.). Operators cannot tune these for different backends (e.g., more aggressive for production primary, more lenient for read replicas). There are no circuit breaker metrics exposed for monitoring.

**Action:** Add circuit breaker configuration to `PoolConfig`:

```go
type CircuitBreakerConfig struct {
    Enabled         bool          `json:"enabled"`
    FailureCount    int           `json:"failure_count"`     // default 5
    HalfOpenMax     int           `json:"half_open_max"`     // default 3
    CooldownTimeout time.Duration `json:"cooldown_timeout"`  // default 30s
    HalfOpenTimeout time.Duration `json:"half_open_timeout"` // default 30s
}
```

Expose circuit breaker state in pool health metrics (currently `circuit_state` is already returned in `PoolHealth` — verify it's populated).

**Risk of deferring:** Circuit breaker may trip too easily on flaky-but-functional backends, or not aggressively enough on failing ones. No way to tune without code changes.

---

### A-09: Add Content-Security-Policy header to admin dashboard

| Field | Value |
|-------|-------|
| **Priority** | Medium |
| **Area** | `internal/admin` + `admin-ui` |
| **Effort** | Small (~1h) |
| **Files** | `internal/admin/dashboard_ui.go`, `internal/admin/server.go` |

**Problem:** The inline dashboard (`dashboard_ui.go`) has no Content-Security-Policy header, making it potentially vulnerable to XSS if user-controlled data (usernames, database names, SQL text) is rendered unsanitized. The React SPA also lacks a CSP header in the server response.

**Action:** Add a CSP header middleware for all `/ui*` routes:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:
```

The `'unsafe-inline'` for scripts is required because both the old inline dashboard and the React SPA use inline scripts. This is a partial fix — a full fix would move to nonce/hash-based CSP, but that requires build-time integration with Vite.

**Risk of deferring:** Low severity, but a missing CSP header is a common finding in security audits (PCI-DSS, SOC2).

---

## Phase 2 — Quality Infrastructure (Sprint 3–4)

### A-10: Add fuzz testing for SQL tokenizer and SQLi detector

| Field | Value |
|-------|-------|
| **Priority** | Medium |
| **Area** | `internal/inspection` + `internal/policy` |
| **Effort** | Medium (~2d) |
| **Files** | `internal/inspection/tokenizer.go`, `internal/policy/sqli_helpers.go` |

**Problem:** No fuzz testing exists for the SQL tokenizer or SQL injection detector. These are security-critical components that parse attacker-controlled input (SQL strings). A malformed SQL string or novel obfuscation technique could cause:
1. Tokenizer panic (crash the proxy)
2. SQLi bypass (fail to detect an injection pattern)
3. Incorrect classification (allow a blocked query)

**Action:** Add Go fuzz tests (`go test -fuzz`) targeting:
- `Tokenizer.Tokenize()` — with random SQL strings, Unicode, null bytes, overlong identifiers, nested comments, dialect-specific syntax
- `detectSQLInjection()` — with adversarial inputs designed to bypass detection (alternating case, mixed encoding, heavy nesting, comments in unusual places)

```go
// Example fuzz target for tokenizer:
func FuzzTokenizer(f *testing.F) {
    f.Add("SELECT * FROM users WHERE id = 1")
    f.Add("SELECT/*comment*/1/**/FROM/**/users")
    f.Fuzz(func(t *testing.T, sql string) {
        tok := inspection.NewTokenizer(sql)
        tokens := tok.Tokenize()
        // Verify no panic, tokens are sensible
        // Verify round-trip property: re-joining tokens covers original content
    })
}
```

**Risk of deferring:** Hard-to-discover bugs in parsing logic that could lead to security bypasses in production.

---

### A-11: Add property-based testing for masking transformers

| Field | Value |
|-------|-------|
| **Priority** | Medium |
| **Area** | `internal/masking` |
| **Effort** | Small (~1d) |
| **File** | `internal/masking/transformers.go` |

**Problem:** No property-based (generative) testing on masking transformers. Each transformer has implicit properties that should hold for ALL inputs:
- **`redact`**: Output length is always 3 (`***`)
- **`partial_email`**: Output contains `@` when input does; output never contains domain that wasn't in input
- **`partial_card`**: Output has exactly 19 chars form `****-****-****-XXXX`; last 4 digits match input's last 4
- **`hash`**: Same input → same output; different input → different output (collision property)
- **`null`**: Output is always `"NULL"` regardless of input

**Action:** Add property-based tests (using Go's testing/quick or a manual generative approach) for each transformer:

```go
func TestPartialEmail_Properties(t *testing.T) {
    t.Run("contains_at_when_input_has_at", func(t *testing.T) {
        testingProperty(t, func(email string) bool {
            if !strings.Contains(email, "@") { return true }
            result := string(partialEmail([]byte(email)))
            return strings.Contains(result, "@")
        })
    })
    t.Run("never_longer_than_input", func(t *testing.T) {
        testingProperty(t, func(email string) bool {
            result := string(partialEmail([]byte(email)))
            return len(result) <= len(email)
        })
    })
}
```

**Risk of deferring:** Regressions in transformers could silently leak partial PII data.

---

### A-12: Integrate race detector into default `make test` and CI

| Field | Value |
|-------|-------|
| **Priority** | Medium |
| **Area** | Build system, CI |
| **Effort** | Small (~2h) |
| **Files** | `Makefile`, `scripts/test-e2e.sh` (CI workflow) |

**Problem:** Race detector tests (`make test-race`) are a separate target not part of `make test`. They're not run in the default CI pipeline. Data races in concurrent Go code (session manager, pool, cache, audit logger) can cause crashes, data corruption, or silent misbehavior that only manifests under load.

**Action:**
1. Add `make test-race` to CI pipeline (after unit tests complete, parallel lane)
2. Increase CI timeout to 120s to accommodate the 2x overhead of the race detector
3. Optionally, add `build -race` for the tester stage in `Dockerfile`

**Risk of deferring:** Latent data races in production code, particularly in `sync.Map` access patterns and shared counter updates.

---

### A-13: Add full-pipeline benchmark targets

| Field | Value |
|-------|-------|
| **Priority** | Low |
| **Area** | Build system, CI |
| **Effort** | Small (~1d) |
| **Files** | `internal/core/pipeline_test.go`, `Makefile` |

**Problem:** Only per-package benchmarks exist. There's no end-to-end benchmark measuring the full proxy pipeline (read → classify → cost → policy → mask → forward → audit). Performance targets are documented (< 1ms per allow decision, < 5ms per 1000 masked rows) but cannot be verified.

**Action:** Add a pipeline benchmark that:
1. Sets up a mock client and mock backend
2. Sends a series of SQL commands through the full pipeline
3. Measures p50/p95/p99 latency under increasing concurrency (1, 10, 100 concurrent sessions)
4. Measures memory allocation per query

Add `make bench-full` target that runs these benchmarks and compares against documented targets.

**Risk of deferring:** Performance regression goes undetected until production.

---

## Phase 3 — Feature Maturation (Sprint 5–8)

### A-14: Complete MongoDB protocol support to production parity

| Field | Value |
|-------|-------|
| **Priority** | Medium |
| **Area** | `internal/protocol/mongodb` |
| **Effort** | Large (~1–2w) |
| **Files** | `internal/protocol/mongodb/handler.go`, `internal/protocol/mongodb/codec.go` |

**Problem:** MongoDB support is experimental — OP_MSG passthrough only, no identity extraction, no collection-level policy context, no BSON result masking, no E2E coverage parity with SQL protocols. Users who deploy MongoDB alongside their SQL databases cannot use Argus consistently.

**Action items (in dependency order):**
1. **Identity extraction**: Parse MongoDB auth frames (SCRAM-SHA-1, SCRAM-SHA-256) to extract username for session identity
2. **Collection context**: Parse OP_MSG payloads fully to extract collection names (equivalent to table names in SQL) for policy matching
3. **BSON result masking**: Implement BSON field-level masking in the result stream (corresponds to column masking in SQL)
4. **MongoDB gateway executor**: Add MongoDB query execution to the gateway HTTP API
5. **E2E tests**: Write Docker-based E2E tests with MongoDB target (add to `docker-compose.yml`)

**Risk of deferring:** MongoDB users must manage separate security tooling, fragmenting the value proposition.

---

### A-15: Add MSSQL gateway executor

| Field | Value |
|-------|-------|
| **Priority** | Medium |
| **Area** | `internal/gateway` |
| **Effort** | Medium (~3–5d) |
| **Files** | `internal/gateway/executor.go`, `internal/gateway/executor_mysql.go` (as reference) |

**Problem:** The gateway currently supports PG and MySQL executors but not MSSQL. Users of all three databases must use two gateways or bypass Argus for MSSQL queries.

**Action:** Implement `MSSQLExecutor` following the pattern of `executor_mysql.go`. The MSSQL protocol handler already supports SQL batch execution — the gateway executor needs to:
1. Accept a query string and parameters
2. Open a connection via the pool
3. Execute via the MSSQL protocol handler
4. Stream results back

**Risk of deferring:** Inconsistent user experience across database protocols.

---

### A-16: Add log archive/compression strategy

| Field | Value |
|-------|-------|
| **Priority** | Medium |
| **Area** | `internal/audit` |
| **Effort** | Medium (~2d) |
| **File** | `internal/audit/writer.go` |

**Problem:** Log compaction removes old files entirely. There's no archival or compression step — old audit data is either kept in full (consuming disk) or deleted (losing forensic data). Compliance requirements (PCI-DSS 10.7, SOC2 A1.2) often require log retention for 12+ months.

**Action:** Add a configurable archiver that:
1. Compresses old log files with gzip (configurable algorithm)
2. Optionally moves them to an archive directory
3. Configurable retention: keep compressed for N days, then delete

```go
type RotationConfig struct {
    MaxSizeMB   int    `json:"max_size_mb"`
    MaxFiles    int    `json:"max_files"`
    ArchiveDir  string `json:"archive_dir,omitempty"`
    Compression string `json:"compression,omitempty"` // "none", "gzip"
    Retention   string `json:"retention,omitempty"`   // "90d", "12M"
}
```

**Risk of deferring:** Disk space fills up or audit data is lost before compliance retention periods are met.

---

### A-17: Add multi-arch Docker builds and ARM CI

| Field | Value |
|-------|-------|
| **Priority** | Low |
| **Area** | Infrastructure, CI/CD |
| **Effort** | Medium (~2d) |
| **Files** | `Dockerfile`, `.github/workflows/ci.yml` |

**Problem:** Cross-compilation targets exist for ARM64 (`make cross-linux`) but Docker images are amd64-only. ARM64 deployment (AWS Graviton, Apple Silicon, Raspberry Pi clusters) requires separate builds or emulation.

**Action:**
1. Add `docker buildx` multi-arch build to CI: `--platform linux/amd64,linux/arm64`
2. Push manifest lists with both architectures under the same tag
3. Optionally add `Makefile` targets for `docker-multiarch`

**Risk of deferring:** ARM64 users must build their own images, increasing friction.

---

## Phase 4 — Platform (Quarter 2+)

These are larger strategic initiatives with rolling planning. Each would benefit from a dedicated design document before execution.

### A-18: Terraform provider for Policy-as-Code

| Field | Value |
|-------|-------|
| **Priority** | Low |
| **Area** | Infrastructure |
| **Effort** | X-Large (~3–4w) |
| **Files** | New repository: `terraform-provider-argus` |

**Action:** Create a Terraform provider that manages Argus policies and routing rules as declarative infrastructure. Resources: `argus_policy`, `argus_role`, `argus_routing_rule`, `argus_data_source_target_health`.

**Prerequisites:** Stable, versioned REST API (the current admin API needs to be versioned first — add `/v1/` prefix).

---

### A-19: Kubernetes Operator

| Field | Value |
|-------|-------|
| **Priority** | Low |
| **Area** | Infrastructure |
| **Effort** | X-Large (~4–6w) |
| **Files** | New repository: `argus-operator` |

**Action:** Build a K8s Operator using `controller-runtime` that manages:
- `ArgusProxy` CRD — deploy and configure Argus instances
- Policy CRDs — manage WAF policies as K8s custom resources
- Automatic TLS certificate management via cert-manager integration
- Automated rolling updates with zero-downtime connection draining

---

### A-20: AI/ML-driven anomaly detection

| Field | Value |
|-------|-------|
| **Priority** | Low |
| **Area** | `internal/inspection` |
| **Effort** | X-Large (~3–4w) |
| **Files** | `internal/inspection/anomaly.go` |

**Action:** Add an optional AI/ML module for anomaly detection that complements the heuristic approach:
- Train a lightweight model on historical query patterns (command type distributions, table access frequency, time-of-day patterns, result sizes)
- Score incoming queries against the model
- Flag outliers that the heuristic detector might miss (e.g., gradual behavior drift, subtle privilege escalation)
- Keep the existing heuristic detector as the fast path; ML as the optional slow path for high-context environments

**Note:** This would introduce an external dependency (ML inference library) — a meaningful departure from the zero-dependency principle. Should be an optional plugin, not a core requirement.

---

### A-21: Multi-instance cluster integration (Redis/etcd session store)

| Field | Value |
|-------|-------|
| **Priority** | Low |
| **Area** | `internal/cluster` |
| **Effort** | Large (~1–2w) |
| **Files** | `internal/cluster/store.go`, `internal/session/manager.go` |

**Action:** Complete the cluster store abstraction by implementing Redis and etcd backends for the `Store` interface. This enables:
- Cross-instance session listing and kill
- Global rate limiting across all proxy instances
- Shared anomaly detection data
- Rolling deployments without dropping all sessions

**Current state:** The `Store` interface is well-defined but has only an in-memory implementation and is not wired into the main binary. The wiring in `main.go` and `core/pipeline.go` needs to be updated.

---

## Dependencies Map

```
Phase 0 (Week 1)
  A-01 ─┐
  A-02 ─┤
  A-03 ─┤
         │
Phase 1 (Sprint 1–2)
  A-04 ─┤  ← blocked by A-01, A-02 (fix code first)
  A-05 ─┤
  A-06 ─┤
  A-07 ─┤
  A-08 ─┤
  A-09 ─┤
         │
Phase 2 (Sprint 3–4)
  A-10 ─┤
  A-11 ─┤
  A-12 ─┤
  A-13 ─┤
         │
Phase 3 (Sprint 5–8)
  A-14 ─┤  ← blocked by A-04 (gateway tests before new executor)
  A-15 ─┤  ← blocked by A-04 (same reason)
  A-16 ─┤
  A-17 ─┤
         │
Phase 4 (Q2+)
  A-18 ─┤  ← blocked by A-06 (stable API versioning)
  A-19 ─┤
  A-20 ─┤
  A-21 ─┤
```

---

## Effort Summary

| Phase | Small | Medium | Large | X-Large | Calendar |
|-------|-------|--------|-------|---------|----------|
| **Phase 0** | 3 | — | — | — | Week 1 |
| **Phase 1** | 4 | 1 | 1 | — | Sprint 1–2 (2 weeks) |
| **Phase 2** | 2 | 2 | — | — | Sprint 3–4 (2 weeks) |
| **Phase 3** | — | 3 | 1 | — | Sprint 5–8 (4 weeks) |
| **Phase 4** | — | — | 1 | 3 | Q2+ (rolling) |
| **Total** | **9** | **6** | **3** | **3** | **~9–10 weeks + Q2+** |

---

## Quick-Start: If You Only Do One Thing

| If you care about… | Start with |
|--------------------|------------|
| **Security** | A-01 (hash collision) → A-02 (WS token) → A-09 (CSP) |
| **Production readiness** | A-04 (gateway tests) → A-05 (cache eviction) → A-06 (pagination) |
| **Operational safety** | A-08 (circuit breaker config) → A-03 ($FILE syntax) → A-12 (race detection) |
| **Correctness** | A-10 (fuzz tokenizer) → A-11 (property-based masking tests) |
| **Database coverage** | A-14 (MongoDB parity) → A-15 (MSSQL gateway executor) |
| **Compliance** | A-16 (log archive) → A-09 (CSP) |

---

*Derived from ARGUS-COMPREHENSIVE-REVIEW.md — Action Plan v1.0*
