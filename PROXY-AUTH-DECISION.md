# Proxy Auth Mode — Architecture Decision Document

**For:** Monopam × Argus integration discussion (lu)  
**Date:** 2026-07-16  
**Context:** The resolve bridge (PostAuth hook + Monopam .NET) is built, deployed, and E2E-tested against real PostgreSQL. The remaining architectural decision is how to build the per-protocol auth server crypto needed for credential injection.

---

## 1. What Exists Today

### The Resolve Bridge (Verified Working)

```
psql → Argus(:19999) → [handshake relay] → PostgreSQL(:15432)
                              │
                        [PostAuth hook]
                              │
                    POST /api/db/resolve
                              │
                     Monopam (:5000)
                              │
                     Vault KV v2 (:8200)
```

**E2E verification:** `SELECT 1` through Argus → Monopam resolve → real PostgreSQL. Credentials from Vault match the real database. **All 24 Argus + 17 Monopam tests pass.**

### Files Delivered

| Component | Location | Lines |
|-----------|----------|-------|
| PostAuth hook stage | `argus/internal/core/middleware.go` | +30 |
| PostAuth wiring in pipeline | `argus/internal/core/pipeline.go` | +25 |
| IdentityResolverHook | `argus/internal/core/resolve_hook.go` | 111 |
| Go resolve HTTP client | `argus/internal/resolve/resolve.go` | 171 |
| Go resolve tests | `argus/internal/resolve/resolve_test.go` | 160 |
| main.go adapter + flags | `argus/cmd/argus/main.go` | +45 |
| Monopam .NET (3 projects) | `monopam/` | ~1200 |
| **Total delivered** | | **~1742** |

---

## 2. The Gap: What Proxy Auth Mode Requires

### Current flow (passthrough — what runs today)

```
1. Accept TCP connection
2. Lookup target from static config
3. Dial target backend
4. Handshake(client, backend) → RELAY auth messages verbatim
5. sessionInfo = {username, database}
6. PostAuth hook → POST /api/db/resolve → LOG result (informational)
7. Command loop (inspect → policy → mask → forward → audit)
```

**Problem:** Steps 2-4 happen before the resolve call (step 6). The backend is already connected and authenticated by the time we know the "real" target. The current hook can REJECT a connection but cannot CHANGE the target or inject credentials.

### Required flow (proxy auth — what needs building)

```
1. Accept TCP connection
2. READ CLIENT STARTUP ONLY (extract username, database)
                     ↓
3. POST /api/db/resolve → {target, credential}
                     ↓
4. Dial RESOLVED target (not static)
5. Perform CLIENT-SIDE auth to resolved target using resolved credential
   [Argus acts as auth-client to the real database]
6. Perform SERVER-SIDE auth to original client confirming success
   [Argus acts as auth-server to the application]
7. If both succeed → session established
8. Command loop (inspect → policy → mask → forward → audit) → UNCHANGED
```

**The command loop (step 8) does not change.** Only the connection setup (steps 1-7) changes. This is 3,500+ lines of existing code that remains untouched.

---

## 3. Per-Protocol Auth Server Crypto — Detailed Breakdown

### 3.1 PostgreSQL SCRAM-SHA-256

**Current relay code:** `internal/protocol/pg/auth.go:98-177` — `relayAuth()`  
This handles AuthOK, AuthCleartextPwd, AuthMD5Pwd, AuthSASL, AuthSASLContinue, AuthSASLFinal by reading from backend and forwarding to client.

**What needs to be built for proxy auth:**

**Server-side (Argus authenticating the client):**

Argus must implement the SCRAM-SHA-256 server state machine:

```
Client → SASLInitialResponse ("SCRAM-SHA-256", client-first-message)
Argus  → AuthenticationSASLContinue (server-first-message: nonce, salt, iterations)
Client → AuthenticationSASLFinal (client-final-message: channel-binding, client-proof)
Argus  → AuthOK (if ServerSignature matches) or ErrorResponse
```

**New code needed in `internal/protocol/pg/auth.go`:**

```go
// ProxyAuthServer performs the server side of PostgreSQL authentication.
// It validates the client's credentials against the resolved identity.
func ProxyAuthServer(ctx context.Context, client net.Conn, identity *core.ResolvedIdentity) error {
    // Wait for SASLInitialResponse from client
    // Generate server-first-message with fresh nonce and salt
    // Compute expected ClientProof from stored password
    // Validate client-final-message
    // Send AuthOK or ErrorResponse
}
```

**Client-side (Argus authenticating to the real database):**

Argus must implement the SCRAM-SHA-256 client to authenticate with the resolved password. The existing `relayAuth` code actually already does this for MD5 and cleartext — but SCRAM requires computing the ClientProof, which can't be relayed because the server challenge changes.

```go
// ProxyAuthClient performs the client side of PostgreSQL authentication.
// It authenticates to the real database using the resolved credential.
func ProxyAuthClient(ctx context.Context, backend net.Conn, password string) error {
    // Read server's auth request (SASL, SCRAM-SHA-256)
    // Compute client-first-message with nonce
    // Read server-first-message (nonce, salt, iterations)
    // Compute SaltedPassword, ClientKey, StoredKey, ClientSignature
    // Compute ClientProof and send
    // Read server-final-message, verify ServerSignature
}
```

**SCRAM crypto primitives needed (all standard Go crypto):**

| Primitive | Go stdlib | Notes |
|-----------|-----------|-------|
| SHA-256 | `crypto/sha256` | ✅ Built-in |
| PBKDF2 | `golang.org/x/crypto/pbkdf2` | Not stdlib, but widely used |
| HMAC-SHA256 | `crypto/hmac` | ✅ Built-in |
| XOR | built-in | ✅ |
| Nonce generation | `crypto/rand` | ✅ Built-in |

The `golang.org/x/crypto/pbkdf2` is the only non-stdlib dependency. It's a sub-repo of the Go team and extremely stable.

**Effort estimate:** **2-3 weeks** for a production-grade implementation including full test coverage of the SASL state machine, edge cases (channel binding, error paths, GSSAPI fallback).

### 3.2 MySQL caching_sha2_password

**Current relay code:** `internal/protocol/mysql/handler.go:85-105`  
MySQL 8 uses `caching_sha2_password` which has two phases:
1. Fast auth (if cached on server) — simple XOR scramble
2. Full auth (RSA public key exchange or SSL) — encrypt password with server's RSA key

**New code needed:**

```go
// ProxyAuthServer handles MySQL server-side authentication.
// MySQL auth phases:
//   Phase 1: Send auth_switch_request or caching_sha2_password
//   Phase 2: If fast auth fails, send RSA public key or SSL upgrade
func ProxyAuthServer(ctx context.Context, client net.Conn) error {
    // Generate auth_switch_request with server scramble
    // Validate client's auth response
    // Handle RSA-encrypted password exchange
}
```

**Client-side (Argus to MySQL):**
```go
// ProxyAuthClient authenticates to MySQL using resolved credential.
func ProxyAuthClient(ctx context.Context, backend net.Conn, password string) error {
    // Read MySQL greeting (server version, auth plugin, scramble)
    // Send auth response (fast XOR or RSA-encrypted password)
    // Handle auth_switch_request
}
```

**RSA dependency:** MySQL's RSA public key exchange requires RSA encryption. Go's `crypto/rsa` supports this, but the MySQL-specific OAEP padding needs careful implementation.

**Effort estimate:** **1-2 weeks**

### 3.3 MSSQL Login7 + NTLM

**Current relay code:** `internal/protocol/mssql/handler.go:36-70`

MSSQL uses Login7 TDS message for authentication. The relay currently passes Login7 through unmodified.

**New code needed:**

```go
// ProxyAuthServer handles TDS/MSSQL server-side authentication.
func ProxyAuthServer(ctx context.Context, client net.Conn) error {
    // Read PreLogin → respond with PreLogin response
    // Read Login7 → validate password using SQL Server auth
    // Send Login7 response (success/failure)
}
```

Actually, MSSQL's auth is more complex. Login7 can contain:
- SQL Server authentication (username + password hash)
- NTLM / Windows Authentication (requires SSPI)
- Active Directory (requires Kerberos)

For SQL Server auth, Argus would need to validate the password hash in Login7 against the resolved credential. This is non-trivial because Login7 sends a SHA-256 hash, not the plain password.

**Effort estimate:** **2-3 weeks** (for SQL Server auth only; NTLM/Kerberos would be significantly more)

### 3.4 MongoDB SCRAM-SHA-1/256

MongoDB is still experimental in Argus (OP_MSG passthrough only). Proxy auth mode should wait until MongoDB reaches production parity.

**Effort estimate:** N/A (deferred)

---

## 4. Total Effort Summary

| Protocol | Server auth | Client auth | Test | Total |
|----------|------------|------------|------|-------|
| PostgreSQL | 1.5 weeks | 1 week | 0.5 week | **3 weeks** |
| MySQL | 1 week | 0.5 week | 0.5 week | **2 weeks** |
| MSSQL | 1.5 weeks | 0.5 week | 0.5 week | **2.5 weeks** |
| MongoDB | N/A (deferred) | N/A | N/A | — |
| **Total** | | | | **~7.5 weeks** |

**Sequential:** PG first (3 weeks) → MySQL (2 weeks) → MSSQL (2.5 weeks) = **~7-8 weeks**  
**Parallel (different engineers):** PG + MySQL = 5 weeks (fastest path to value)

### Additional cross-cutting work (1 week):

| Item | Effort |
|------|--------|
| Pipeline refactor: split handshake into two halves | 2 days |
| Credential store abstraction in Go | 1 day |
| Identity-based target resolution | 1 day |
| E2E integration tests | 1 day |
| **Total** | **~1 week** |

---

## 5. The API Contract (Verified Working)

The contract between Argus and Monopam is already defined and tested:

**POST /api/db/resolve**

```json
{
  "username": "jane_app",
  "database": "production",
  "client_ip": "10.0.1.50",
  "protocol": "postgresql"
}
```

**Response:**
```json
{
  "host": "db-primary.internal",
  "port": 5432,
  "protocol": "postgresql",
  "username": "monopam_svc",
  "password": "pg_pass_789",
  "auth_method": "scram_sha_256",
  "roles": ["db_reader", "app_service"],
  "policy_tags": {"environment": "production", "tier": "primary"}
}
```

**All JSON keys confirmed matching between Go and C#** (snake_case). E2E-tested with real PostgreSQL.

---

## 6. Recommendation

### lu's original options, updated:

**Option (a) — Build proxy auth in Go now:**
- Feasible but blocks Monopam .NET progress
- 7-8 weeks of Go crypto engineering
- Risk: protocol-level bugs in auth state machines
- Upside: once done, credential injection works for all protocols

**Option (b) — Monopam .NET first, Go auth later ← (still the right call)**
- ✅ 1,742 lines of bridge code delivered and E2E-tested
- ✅ Monopam .NET resolves identities, manages credentials, integrates with Vault
- ✅ The PostAuth hook works for REJECTION (if resolve denies, connection is blocked)
- ❌ Cannot do INJECTION yet (changing target/credential requires auth server crypto)
- **When Go resources are available:** PG first (3 weeks), then MySQL (2 weeks)

**Option (c) — Consider alternatives:**
- No viable alternative matches Argus's protocol coverage (PG/MySQL/MSSQL all production-grade)
- Abandoning Argus means rebuilding 4 wire protocols from scratch (18+ months)

### What you can do TODAY with what's built:

| Scenario | Works? | How |
|----------|--------|-----|
| Block unknown users | ✅ Yes | PostAuth hook calls Monopam → 403 → connection rejected |
| Audit resolved identity | ✅ Yes | Hook logs resolved target to audit trail |
| Log who connected where | ✅ Yes | Monopam records each resolve call |
| Credential injection | ❌ No | Requires auth server crypto (not built) |
| Dynamic target routing | ❌ No | Requires pipeline refactor (built in Phase 2) |

This means **Monopam can go to production today** as an identity-aware blocking layer and audit source, even without credential injection. When the Go auth crypto is built, the injection capability activates without changing Monopam at all — the API contract is stable.

---

## 7. Concrete Next Step for lu

**If Monopam .NET continues first:**
1. Build `DatabaseController` / resolver / audit / policy frontend in .NET (lu's original plan)
2. Use Argus + Monopam as a blocking proxy in production (reject unknown users, audit all connections)
3. When Go team is available: build PG SCRAM-SHA-256 auth server/client (3 weeks)
4. Credential injection activates automatically — Monopam API doesn't change

**If Go auth is prioritized:**
1. Start with PostgreSQL SCRAM-SHA-256 — it's the most used protocol and the crypto is well-documented (RFC 5802, RFC 7677)
2. The Go `crypto` stdlib + `golang.org/x/crypto/pbkdf2` covers all primitives
3. Add MySQL next — reuses the SASL pattern
4. E2E test each protocol with real database before moving to the next

**I recommend sticking with Option (b):** The .NET track delivers immediate value (blocking + audit), the API contract is stable, and the Go crypto can be built later without any Monopam changes. The resolve bridge is proven — it's not a spike or a prototype.
