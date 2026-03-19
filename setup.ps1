<#
.SYNOPSIS
    Argus - Interactive setup script for Windows
.DESCRIPTION
    Checks and installs prerequisites (Go, Docker Desktop), builds Argus,
    starts the full database stack (PostgreSQL + MySQL + MSSQL) via Docker
    Compose, and optionally runs the end-to-end test suite.
.EXAMPLE
    .\setup.ps1              # Full interactive setup
    .\setup.ps1 -SkipBuild   # Skip Go build (use existing binary)
    .\setup.ps1 -SkipTests   # Skip E2E tests at the end
    .\setup.ps1 -DownOnly    # Stop stack and remove volumes
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$SkipTests,
    [switch]$DownOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok   { param($msg) Write-Host "  [OK] $msg"  -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "  [!!] $msg"  -ForegroundColor Yellow }
function Write-Info { param($msg) Write-Host "      $msg"   -ForegroundColor Gray }

function Write-Banner {
    Write-Host ""
    Write-Host "  +---------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |           Argus - Setup               |" -ForegroundColor Cyan
    Write-Host "  |  Database Firewall & Access Proxy     |" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Confirm-Step {
    param([string]$Question, [bool]$Default = $true)
    $yn = if ($Default) { "Y/n" } else { "y/N" }
    $ans = Read-Host "  $Question [$yn]"
    if ([string]::IsNullOrWhiteSpace($ans)) { return $Default }
    return ($ans -match '^[Yy]')
}

function Test-Cmd { param($c) return [bool](Get-Command $c -ErrorAction SilentlyContinue) }

# ---------------------------------------------------------------------------
# Version requirements
# ---------------------------------------------------------------------------
$MIN_GO     = [Version]"1.21.0"
$GO_LATEST  = "1.23.4"
$MIN_DOCKER = [Version]"24.0.0"

function Get-GoVersion {
    try {
        $raw = (& go version 2>$null) -replace 'go version go','' -replace ' .*',''
        return [Version]$raw
    } catch { return $null }
}

function Get-DockerVersion {
    try {
        $raw = (& docker version --format '{{.Server.Version}}' 2>$null)
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $clean = $raw -replace '[^0-9.]','' -replace '\.+$',''
        return [Version]$clean
    } catch { return $null }
}

# ---------------------------------------------------------------------------
# winget helper
# ---------------------------------------------------------------------------
function Ensure-Winget {
    if (Test-Cmd "winget") { return $true }
    Write-Warn "winget not found. Opening Microsoft Store for App Installer..."
    Start-Process "https://aka.ms/getwinget"
    Write-Warn "Install App Installer from the Store, then re-run this script."
    return $false
}

# ---------------------------------------------------------------------------
# Go install / upgrade
# ---------------------------------------------------------------------------
function Install-Go {
    Write-Step "Installing Go $GO_LATEST via winget..."
    if (-not (Ensure-Winget)) { return $false }
    & winget install GoLang.Go --accept-source-agreements --accept-package-agreements -e
    # Refresh PATH for this session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
    return (Test-Cmd "go")
}

function Ensure-Go {
    Write-Step "Checking Go installation..."
    $ver = Get-GoVersion
    if ($null -eq $ver) {
        Write-Warn "Go not found."
        if (-not (Confirm-Step "Install Go $GO_LATEST via winget?")) {
            Write-Host "`n[FAIL] Go is required. Install from https://golang.org/dl/" -ForegroundColor Red
            exit 1
        }
        if (-not (Install-Go)) {
            Write-Host "`n[FAIL] Go installation failed." -ForegroundColor Red
            exit 1
        }
        $ver = Get-GoVersion
    }
    if ($ver -lt $MIN_GO) {
        Write-Warn "Go $ver found but $MIN_GO+ required."
        if (Confirm-Step "Upgrade Go via winget?") {
            & winget upgrade GoLang.Go --accept-source-agreements --accept-package-agreements -e
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                        [System.Environment]::GetEnvironmentVariable("Path","User")
        }
    }
    Write-Ok "Go $(go version)"
}

# ---------------------------------------------------------------------------
# Docker install / start
# ---------------------------------------------------------------------------
function Wait-DockerDaemon {
    param([int]$Seconds = 90)
    Write-Info "Waiting for Docker daemon (up to $Seconds s)..."
    $elapsed = 0
    while ($elapsed -lt $Seconds) {
        Start-Sleep 5
        $elapsed += 5
        if ($null -ne (Get-DockerVersion)) {
            Write-Ok "Docker daemon is up."
            return $true
        }
        Write-Host "  ... still waiting (${elapsed}s)" -ForegroundColor Gray
    }
    return $false
}

function Install-DockerDesktop {
    Write-Step "Installing Docker Desktop via winget..."
    if (-not (Ensure-Winget)) { return }
    & winget install Docker.DockerDesktop --accept-source-agreements --accept-package-agreements -e
    Write-Warn "Docker Desktop installed. You must RESTART your session and re-run this script."
    exit 0
}

function Ensure-Docker {
    Write-Step "Checking Docker installation..."
    $ver = Get-DockerVersion
    if ($null -eq $ver) {
        Write-Warn "Docker daemon not reachable."
        # Check if Docker Desktop is installed but not started
        $ddPaths = @(
            "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
            "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
        )
        $ddExe = $ddPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($ddExe) {
            Write-Info "Docker Desktop found. Starting..."
            Start-Process $ddExe
            if (-not (Wait-DockerDaemon -Seconds 90)) {
                Write-Host "`n[FAIL] Docker Desktop did not start. Please launch it manually." -ForegroundColor Red
                exit 1
            }
            $ver = Get-DockerVersion
        } else {
            Write-Warn "Docker Desktop is not installed."
            if (-not (Confirm-Step "Install Docker Desktop via winget? (requires restart after)")) {
                Write-Host "`n[FAIL] Docker is required. Install from https://www.docker.com/products/docker-desktop/" -ForegroundColor Red
                exit 1
            }
            Install-DockerDesktop
            return
        }
    }
    Write-Ok "Docker $ver"
    # Verify compose v2
    $composeOk = $false
    try { & docker compose version 2>$null | Out-Null; $composeOk = ($LASTEXITCODE -eq 0) } catch {}
    if (-not $composeOk) {
        Write-Host "`n[FAIL] docker compose (v2) not available. Update Docker Desktop." -ForegroundColor Red
        exit 1
    }
    Write-Ok "docker compose ready"
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
function Build-Argus {
    if ($SkipBuild) { Write-Warn "Skipping build (-SkipBuild)"; return }
    Write-Step "Building Argus binary..."
    $version  = try { & git describe --tags --always 2>$null } catch { "dev" }
    $buildtime = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    $ldflags  = "-s -w -X main.Version=$version -X main.BuildTime=$buildtime"
    & go build -ldflags $ldflags -o argus.exe ./cmd/argus/
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[FAIL] go build failed." -ForegroundColor Red
        exit 1
    }
    Write-Ok "Binary built: argus.exe ($version)"
}

# ---------------------------------------------------------------------------
# Health wait
# ---------------------------------------------------------------------------
function Wait-Healthy {
    param([int]$TimeoutSec = 120)
    Write-Step "Waiting for containers to become healthy..."
    $elapsed = 0
    while ($elapsed -lt $TimeoutSec) {
        Start-Sleep 5
        $elapsed += 5
        try {
            $json = & docker compose ps --format json 2>$null
            # docker compose ps --format json returns one JSON object per line
            $unhealthy = $json -split "`n" |
                Where-Object { $_.Trim() -ne "" } |
                ForEach-Object {
                    try { $_ | ConvertFrom-Json } catch { $null }
                } |
                Where-Object { $_ -ne $null -and $_.Health -ne "" -and $_.Health -ne "healthy" } |
                ForEach-Object { $_.Name }
            if (-not $unhealthy) {
                Write-Ok "All containers healthy."
                return
            }
            Write-Host "  ... waiting (${elapsed}s): $($unhealthy -join ', ')" -ForegroundColor Gray
        } catch {
            Write-Host "  ... waiting (${elapsed}s)" -ForegroundColor Gray
        }
    }
    Write-Warn "Timeout reached - containers may still be initialising."
}

# ---------------------------------------------------------------------------
# MSSQL setup
# ---------------------------------------------------------------------------
function Setup-MSSQL {
    Write-Step "Setting up MSSQL database and user..."
    Start-Sleep 10

    $sql = "IF NOT EXISTS (SELECT name FROM sys.databases WHERE name=N'testdb') CREATE DATABASE testdb; " +
           "IF NOT EXISTS (SELECT name FROM sys.server_principals WHERE name=N'argus_test') " +
           "BEGIN CREATE LOGIN argus_test WITH PASSWORD=N'argus_pass', CHECK_POLICY=OFF; END " +
           "USE testdb; " +
           "IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name=N'argus_test') " +
           "BEGIN CREATE USER argus_test FOR LOGIN argus_test; ALTER ROLE db_owner ADD MEMBER argus_test; END"

    $sqlArgs = @("-S","localhost","-U","sa","-P","Argus_Pass123!","-C","-N","-Q",$sql)
    $ran = $false

    foreach ($cname in @("argus-mssql-1","argus_mssql_1")) {
        try {
            & docker exec $cname /opt/mssql-tools18/bin/sqlcmd @sqlArgs 2>$null
            if ($LASTEXITCODE -eq 0) { Write-Ok "MSSQL ready."; $ran = $true; break }
        } catch {}
    }
    if (-not $ran) {
        Write-Warn "MSSQL setup failed - run 'make setup-mssql' manually if MSSQL is needed."
    }
}

# ---------------------------------------------------------------------------
# Print endpoints
# ---------------------------------------------------------------------------
function Print-Endpoints {
    Write-Host ""
    Write-Host "  Stack is running! Service endpoints:" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Databases (direct):" -ForegroundColor White
    Write-Host "    PostgreSQL  ->  localhost:35432   (argus_test / argus_pass / testdb)"
    Write-Host "    MySQL       ->  localhost:33306   (argus_test / argus_pass / testdb)"
    Write-Host "    MSSQL       ->  localhost:31433   (argus_test / argus_pass / testdb)"
    Write-Host ""
    Write-Host "  Argus Proxy:" -ForegroundColor White
    Write-Host "    PostgreSQL  ->  localhost:30100"
    Write-Host "    MySQL       ->  localhost:30101"
    Write-Host "    MSSQL       ->  localhost:30102"
    Write-Host "    Admin API   ->  http://localhost:30200"
    Write-Host "    Metrics     ->  http://localhost:30200/metrics"
    Write-Host ""
    Write-Host "  Useful commands:" -ForegroundColor White
    Write-Host "    docker compose logs -f argus   # follow Argus logs"
    Write-Host "    docker compose ps              # service status"
    Write-Host "    .\setup.ps1 -DownOnly          # stop and remove volumes"
    Write-Host ""
}

# ---------------------------------------------------------------------------
# E2E tests
# ---------------------------------------------------------------------------
function Run-E2E {
    if ($SkipTests) { return }
    if (-not (Confirm-Step "Run end-to-end tests now?" $false)) { return }
    Write-Step "Running E2E test suite..."
    if (Test-Cmd "bash") {
        & bash scripts/test-e2e-full.sh
    } elseif (Test-Cmd "wsl") {
        & wsl bash scripts/test-e2e-full.sh
    } else {
        Write-Warn "bash not found. Install Git for Windows or WSL to run E2E tests."
        Write-Info "Manual: wsl bash scripts/test-e2e-full.sh"
    }
}

# ===========================================================================
# MAIN
# ===========================================================================
Write-Banner

# Change to script directory
Set-Location $PSScriptRoot

# Handle --down
if ($DownOnly) {
    Write-Step "Bringing stack down..."
    & docker compose down -v
    Write-Ok "Stack stopped and volumes removed."
    exit 0
}

Ensure-Go
Ensure-Docker
Build-Argus

# Choose mode
Write-Host ""
Write-Host "  Choose deployment mode:" -ForegroundColor White
Write-Host "    [1] Full stack  - PostgreSQL + MySQL + MSSQL via Docker Compose (recommended)"
Write-Host "    [2] Local only  - Run argus.exe with local PostgreSQL (you manage the DB)"
Write-Host "    [3] Exit"
$mode = Read-Host "  Choice [1]"
if ([string]::IsNullOrWhiteSpace($mode)) { $mode = "1" }

if ($mode -eq "3") { exit 0 }

if ($mode -eq "2") {
    Write-Step "Local mode - starting Argus..."
    Write-Info "Press Ctrl+C to stop."
    & .\argus.exe -config configs/argus.json
    exit 0
}

# --- Full Docker stack ---
Write-Step "Building Docker image..."
& docker compose build --no-cache argus
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[FAIL] docker compose build failed." -ForegroundColor Red
    exit 1
}

Write-Step "Starting database stack (PostgreSQL + MySQL + MSSQL)..."
& docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[FAIL] docker compose up failed." -ForegroundColor Red
    exit 1
}

Wait-Healthy
Setup-MSSQL
Print-Endpoints
Run-E2E

Write-Step "Setup complete."
