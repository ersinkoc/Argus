# monopam

`monopam` is a small, standalone development implementation of Argus's database identity-resolution API. It has no third-party Go dependencies. A JSON file stands in for the production vault and short-lived proxy-secret issuer.

## The two authentication legs

A proxy-authenticated database connection has two deliberately separate credentials:

1. **Client → Argus:** the client proves knowledge of `client_secret`. Argus must use this field only for its client-facing authentication exchange.
2. **Argus → database:** Argus authenticates to the selected backend using `password`. Argus must use this field only on the backend-facing connection.

`client_secret` and `password` must never be equal. Monopam denies resolution when either is empty, when they are equal, or when the client secret has expired. The response is marked `Cache-Control: no-store` because it contains both credentials.

> `records.example.json` contains obvious, non-production sample values. The file store is only a development substitute for a vault and proxy-secret issuer; do not use it as a production secret store.

## Run

Requires Go 1.24 or newer.

```sh
cp records.example.json records.json
export MONOPAM_API_TOKEN='replace-with-a-long-random-token'
go run ./cmd/monopam -records ./records.json -addr 127.0.0.1:8080
```

Configuration can be supplied by environment variables or equivalent flags:

| Environment | Flag | Default |
|---|---|---|
| `MONOPAM_ADDR` | `-addr` | `127.0.0.1:8080` |
| `MONOPAM_API_TOKEN` | `-api-token` | required |
| `MONOPAM_RECORDS` | `-records` | `records.json` |

Avoid the `-api-token` flag on shared hosts because command-line arguments may be visible to other users. The environment variable is the preferred development option.

## Resolve API

`POST /api/db/resolve` requires the exact header `Authorization: Bearer <configured-token>` and an `application/json` content type. The request is the flat Argus shape:

```json
{
  "username": "demo-app",
  "database": "appdb",
  "client_ip": "192.0.2.10",
  "protocol": "postgresql",
  "request_id": "req-123"
}
```

Records are selected by an exact match of request `username` to record `handle` and an exact `protocol` match. When the request includes `database`, it must also match exactly. Argus may omit `database` (notably during the current MSSQL flow); in that case Monopam resolves only when handle plus protocol identifies exactly one record and denies ambiguous matches. A successful response is also flat:

```json
{
  "host": "postgres.example.invalid",
  "port": 5432,
  "protocol": "postgresql",
  "username": "demo_backend_user",
  "password": "NOT-FOR-PRODUCTION-backend-password",
  "client_secret": "NOT-FOR-PRODUCTION-client-secret",
  "auth_method": "scram_sha_256",
  "roles": ["application"],
  "policy_tags": {"environment": "development", "owner": "example"},
  "client_secret_expires_at": "2099-01-01T00:00:00Z"
}
```

The decoder rejects unknown fields, trailing JSON values, oversized bodies, missing required `username` or `protocol` fields, and non-JSON content types. `database` is optional as described above. Authentication failures return `401`; unknown or unsafe records return the same generic `403` denial to avoid revealing which handles exist. Errors use this stable shape:

```json
{"error":{"code":"ACCESS_DENIED","message":"database access denied"}}
```

`GET /healthz` provides a liveness response and does not expose record data.

## Verify

```sh
gofmt -w cmd internal
go test ./...
go vet ./...
go build ./...
```
