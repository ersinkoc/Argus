# ──────────────────────────────────────────────
#  Argus Development Environment (PowerShell)
# ──────────────────────────────────────────────
# Starts Argus in dev mode with:
#   • Go backend on :9090 (admin API + health)
#   • Vite frontend on :5173 (hot-reload, proxies API to :9090)
#
# Usage:  .\dev.ps1
# ──────────────────────────────────────────────

$ROOT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ROOT_DIR

# ── Generate credentials ──────────────────────
$ADMIN_TOKEN = if ($env:ARGUS_ADMIN_TOKEN) { $env:ARGUS_ADMIN_TOKEN } else { -join ((48..57) + (97..102) | Get-Random -Count 32 | ForEach-Object { [char]$_ }) }
$GATEWAY_KEY = if ($env:ARGUS_GATEWAY_API_KEY) { $env:ARGUS_GATEWAY_API_KEY } else { "gw-dev-" + (-join ((48..57) + (97..102) | Get-Random -Count 8 | ForEach-Object { [char]$_ })) }

$env:ARGUS_ADMIN_TOKEN = $ADMIN_TOKEN
$env:ARGUS_GATEWAY_API_KEY = $GATEWAY_KEY
$env:DB_PG_HOST = if ($env:DB_PG_HOST) { $env:DB_PG_HOST } else { "127.0.0.1" }
$env:DB_MYSQL_HOST = if ($env:DB_MYSQL_HOST) { $env:DB_MYSQL_HOST } else { "127.0.0.1" }
$env:DB_MSSQL_HOST = if ($env:DB_MSSQL_HOST) { $env:DB_MSSQL_HOST } else { "127.0.0.1" }

# ── Cleanup on exit ───────────────────────────
$script:BackendPID = $null
$script:FrontendPID = $null

function Cleanup {
    Write-Host "`n[INFO]  Shutting down..."
    if ($script:BackendPID) { Stop-Process -Id $script:BackendPID -Force -ErrorAction SilentlyContinue }
    if ($script:FrontendPID) { Stop-Process -Id $script:FrontendPID -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK]    Stopped."
}

Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Cleanup } | Out-Null

# ── 1. Build admin UI (embed into Go binary) ──
Write-Host "[INFO]  Building admin UI..."
Set-Location "$ROOT_DIR\admin-ui"
npm install --silent 2>$null
npx vite build --logLevel error
Copy-Item -Path "dist\*" -Destination "$ROOT_DIR\internal\admin\adminui\" -Recurse -Force
Write-Host "[OK]    Admin UI built and embedded."

# ── 2. Build Go binary ────────────────────────
Set-Location $ROOT_DIR
Write-Host "[INFO]  Building Argus binary..."
go build -o argus-dev.exe ./cmd/argus/
Write-Host "[OK]    Binary built: argus-dev.exe"

# ── 3. Start backend ──────────────────────────
Write-Host "[INFO]  Starting Go backend on :9090..."
$CONFIG = if ($args[0]) { $args[0] } else { "configs\argus-dev-full.json" }
$env:ARGUS_POLICY_FILE = "$ROOT_DIR\configs\policies\waf.json"
$processBackend = Start-Process -FilePath ".\argus-dev.exe" -ArgumentList "-config", $CONFIG -PassThru -NoNewWindow
$script:BackendPID = $processBackend.Id
Start-Sleep -Seconds 2

if (-not (Get-Process -Id $script:BackendPID -ErrorAction SilentlyContinue)) {
    Write-Host "[ERR]   Backend failed to start. Check config: $CONFIG"
    exit 1
}
Write-Host "[OK]    Backend running (PID $script:BackendPID)"

# ── 4. Start Vite dev server ──────────────────
Write-Host "[INFO]  Starting Vite dev server on :5173..."
Set-Location "$ROOT_DIR\admin-ui"
$processFrontend = Start-Process -FilePath "npx" -ArgumentList "vite", "--host" -PassThru -NoNewWindow
$script:FrontendPID = $processFrontend.Id
Start-Sleep -Seconds 3
Set-Location $ROOT_DIR

# ── 5. Print summary ──────────────────────────
Clear-Host
Write-Host @"

╔══════════════════════════════════════════════════════════╗
║              Argus — Dev Environment Ready              ║
╚══════════════════════════════════════════════════════════╝

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Admin Panel
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  URL:        http://localhost:5173/ui/
  Prod URL:   http://localhost:9090/ui/

  Admin Token:  $ADMIN_TOKEN
  Gateway Key:  $GATEWAY_KEY

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   API Endpoints
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Health:     curl http://localhost:9090/healthz
  Metrics:    curl http://localhost:9090/metrics
  Sessions:   curl -H 'Authorization: Bearer <token>' http://localhost:9090/api/sessions
  Dashboard:  curl -H 'Authorization: Bearer <token>' http://localhost:9090/api/dashboard
  Policies:   curl -H 'Authorization: Bearer <token>' http://localhost:9090/api/policies

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Database Proxy Ports
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PostgreSQL:  localhost:15432
  MySQL:       localhost:13306
  MSSQL:       localhost:11433

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Quick Test Commands
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # Check health:
  curl http://localhost:9090/livez

  # List sessions (with token):
  curl -H 'Authorization: Bearer $ADMIN_TOKEN' `
    http://localhost:9090/api/sessions

  # WebSocket live events:
  (open http://localhost:5173/ui/events in browser)

  Press Ctrl+C to stop all services

"@

# Keep running
while ($true) { Start-Sleep -Seconds 1 }
