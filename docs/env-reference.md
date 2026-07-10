# Argus — Environment Variables Reference

All `$ENV{VAR}` patterns in configuration JSON files are expanded at runtime.
`ARGUS_*` prefixed environment variables override matching config file fields at startup.

## Database Backend Connections

| Variable | Required | Description |
|----------|----------|-------------|
| `DB_PG_HOST` | If using PG listener | PostgreSQL backend hostname |
| `DB_PG_PASSWORD` | If using PG listener | PostgreSQL backend password |
| `DB_MYSQL_HOST` | If using MySQL listener | MySQL/MariaDB backend hostname |
| `DB_MYSQL_PASSWORD` | If using MySQL listener | MySQL/MariaDB backend password |

## Admin API

| Variable | Required | Description |
|----------|----------|-------------|
| `ARGUS_ADMIN_TOKEN` | If admin enabled | Bearer token for admin API. Must be ≥ 32 chars. Generate: `openssl rand -hex 32` |

## SIEM / Audit Log Shipping

| Variable | Required | Description |
|----------|----------|-------------|
| `SIEM_WEBHOOK_URL` | No | Webhook URL for shipping audit events. Leave empty to use stdout only. |

## SQL Gateway

| Variable | Required | Description |
|----------|----------|-------------|
| `GATEWAY_API_KEY` | If gateway enabled | API key for X-API-Key header authentication |
| `GATEWAY_API_KEY_PREVIOUS` | No | Previous API key for zero-downtime rotation |
| `GATEWAY_APPROVAL_WEBHOOK` | No | Webhook URL for approval notifications |

## ARGUS_* Environment Overrides

These override matching fields in the config JSON file. Set via `export ARGUS_*` in your shell or Docker environment.

| Variable | Default | Description |
|----------|---------|-------------|
| `ARGUS_ADMIN_ENABLED` | `true` | Enable admin API server |
| `ARGUS_ADMIN_ADDRESS` | `:9090` | Admin API listen address |
| `ARGUS_ADMIN_AUTH_TOKEN` | — | Override admin auth token |
| `ARGUS_AUDIT_LEVEL` | `standard` | Audit level: `minimal`, `standard`, `verbose` |
| `ARGUS_AUDIT_BUFFER_SIZE` | `10000` | Audit event channel buffer size |
| `ARGUS_METRICS_ENABLED` | `true` | Enable Prometheus metrics endpoint |
| `ARGUS_METRICS_ADDRESS` | `:9091` | Metrics endpoint listen address |
| `ARGUS_POOL_MAX_CONNECTIONS_PER_TARGET` | `100` | Max connections per backend target |
| `ARGUS_ROUTING_DEFAULT_TARGET` | `pg-primary` | Default routing target name |
| `ARGUS_SESSION_IDLE_TIMEOUT` | `30m` | Session idle timeout duration |
| `ARGUS_SESSION_MAX_DURATION` | `8h` | Maximum session duration |

## Listener/Target Dynamic Overrides

For multi-instance setups, override specific listeners and targets by index:

```bash
export ARGUS_TARGETS_0_HOST=postgres-primary
export ARGUS_TARGETS_0_PORT=5432
export ARGUS_SERVER_LISTENERS_0_ADDRESS=:15432
```

## Quick Start

```bash
# 1. Set required variables
export DB_PG_HOST=localhost
export DB_PG_PASSWORD=your_password
export ARGUS_ADMIN_TOKEN=$(openssl rand -hex 32)

# 2. Validate config
./argus -config configs/argus.json -validate

# 3. Start Argus
./argus -config configs/argus.json
```
