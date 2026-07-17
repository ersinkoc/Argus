# Resolve API Contract (Argus ⇄ Monopam)

**Status:** Implemented and enforced in code as of 2026-07-17.

This is the wire contract Argus already speaks. Monopam's `/api/db/resolve`
endpoint must conform to it. Nothing on the Argus side is pending — the
separate-secret credential-hiding flow is fully built, tested, and wired for
all three SQL protocols.

Source of truth: `internal/resolve/resolve.go` (types + validation),
`cmd/argus/main.go` (`monopamResolver`), `internal/core/proxy_auth.go` and
`internal/core/pipeline.go` (two-leg orchestration).

---

## The two-leg model (why there are two secrets)

Argus authenticates **two separate connections** per session:

| Leg | Who authenticates to whom | Credential used |
|-----|---------------------------|-----------------|
| Client leg | The end user proves identity **to Argus** | `client_secret` (the short-lived proxySecret) |
| Backend leg | Argus proves identity **to the real database** | `password` (the vaulted DB password) |

The end user **never sees or sends the real database password**. They present
only the `client_secret`. Argus validates that against the value from resolve,
then opens the backend connection using the vaulted `password` — which stays on
the Argus↔DB leg and is never sent back to the client.

Because the two secrets serve opposite legs, **they must differ**. Argus rejects
a resolve response where `client_secret == password` (constant-time compare).

---

## Endpoint

```
POST <resolve endpoint, e.g. http://monopam:8080/api/db/resolve>
Content-Type: application/json
Authorization: Bearer <api key>      # sent only if Argus is configured with --resolve-api-key
```

Configured via `--resolve-url` and `--resolve-api-key` CLI flags (or their env
equivalents). Default HTTP client timeout applies per call.

---

## Request body (Argus → Monopam)

All keys are **snake_case**.

```json
{
  "username":   "app_user",           // required — DB username from the client handshake
  "database":   "orders",             // optional — target database, omitted if empty
  "client_ip":  "10.2.0.14",          // optional — client source IP
  "protocol":   "postgresql",         // optional — "postgresql" | "mysql" | "mssql"
  "request_id": "..."                 // optional — correlation id, omitted if empty
}
```

| Field | JSON key | Type | Notes |
|-------|----------|------|-------|
| Username | `username` | string | Always present |
| Database | `database` | string | Omitted when empty |
| ClientIP | `client_ip` | string | Omitted when empty |
| Protocol | `protocol` | string | Omitted when empty |
| RequestID | `request_id` | string | Omitted when empty |

---

## Success response — HTTP 200 (Monopam → Argus)

All keys are **snake_case**.

```json
{
  "host":         "db-primary.internal",     // required, non-empty
  "port":         5432,                       // required
  "protocol":     "postgresql",
  "username":     "svc_orders_ro",            // DB user Argus authenticates as on the backend leg
  "password":     "<vaulted DB password>",    // required, non-empty — used ONLY on the backend leg
  "client_secret":"<short-lived proxySecret>",// required, non-empty, MUST differ from password
  "client_secret_expires_at": "2026-07-17T11:30:00Z", // optional RFC3339; if present, must be in the future
  "auth_method":  "scram-sha-256",            // optional hint
  "roles":        ["reader"],                 // optional; merged with policy-resolved roles
  "policy_tags":  {"team": "orders"}          // optional
}
```

### Validation Argus enforces on the 200 body (all must hold, else the connection is refused)

1. `host` non-empty
2. `password` non-empty
3. `client_secret` non-empty
4. `client_secret` **≠** `password` (constant-time compare)
5. if `client_secret_expires_at` present, it must be **after** now

Any failure ends the session before the backend is contacted.

---

## Denial / error response — HTTP 401 or 403

```json
{
  "code":    "USER_NOT_ENTITLED",
  "message": "no active grant for app_user on orders"
}
```

On 401/403 with a parseable body, Argus surfaces `code`/`message`. Any other
status (or an unparseable body) becomes a generic resolve failure and the
client is rejected.

---

## ⚠️ The one real coordination point: JSON naming

Argus uses **snake_case** JSON keys everywhere (`client_secret`, `client_ip`,
`request_id`, `client_secret_expires_at`). Go's decoder matches keys
case-insensitively **but not across underscores** — so a PascalCase key like
`ClientSecret` will **not** bind to `client_secret`, and Argus will treat the
field as empty and reject the response ("resolve returned empty client secret").

If Monopam serializes with .NET `System.Text.Json`, configure snake_case:

```csharp
new JsonSerializerOptions {
    PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower  // .NET 8+
}
```

or annotate each property with `[JsonPropertyName("client_secret")]`.

This is the only Monopam-side adaptation required; there is no Argus-side change
to make.
