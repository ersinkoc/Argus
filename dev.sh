#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────
#  Argus Development Environment
# ──────────────────────────────────────────────
# This script starts Argus in dev mode with:
#   • Go backend on :9090 (admin API + health)
#   • Vite frontend on :5173 (hot-reload, proxies API to :9090)
#
# Usage:  bash dev.sh
# ──────────────────────────────────────────────

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

# ── Colours ───────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err()   { echo -e "${RED}[ERR]${NC}   $1"; }

# ── Generate credentials ──────────────────────
ADMIN_TOKEN="${ARGUS_ADMIN_TOKEN:-$(openssl rand -hex 32)}"
GATEWAY_KEY="${ARGUS_GATEWAY_API_KEY:-gw-dev-$(openssl rand -hex 8)}"

export ARGUS_ADMIN_TOKEN="$ADMIN_TOKEN"
export ARGUS_GATEWAY_API_KEY="$GATEWAY_KEY"
export DB_PG_HOST="${DB_PG_HOST:-127.0.0.1}"
export DB_MYSQL_HOST="${DB_MYSQL_HOST:-127.0.0.1}"
export DB_MSSQL_HOST="${DB_MSSQL_HOST:-127.0.0.1}"

# ── Cleanup on exit ───────────────────────────
cleanup() {
  info "Shutting down..."
  [ -n "${BACKEND_PID:-}" ] && kill "$BACKEND_PID" 2>/dev/null || true
  [ -n "${FRONTEND_PID:-}" ] && kill "$FRONTEND_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  ok "Stopped."
}
trap cleanup EXIT INT TERM

# ── 1. Build admin UI (embed into Go binary) ──
info "Building admin UI..."
cd "$ROOT_DIR/admin-ui"
npm install --silent 2>/dev/null
npx vite build --logLevel error
cp -r dist/* "$ROOT_DIR/internal/admin/adminui/"
ok "Admin UI built and embedded."

# ── 2. Build Go binary ────────────────────────
cd "$ROOT_DIR"
info "Building Argus binary..."
go build -o argus-dev ./cmd/argus/
ok "Binary built: argus-dev"

# ── 3. Start backend ──────────────────────────
info "Starting Go backend on :9090..."
CONFIG="${1:-configs/argus-dev-full.json}"

# Resolve policy path to absolute path so the $ENV{} ref works
export ARGUS_POLICY_FILE="${ROOT_DIR}/configs/policies/waf.json"

./argus-dev -config "$CONFIG" &
BACKEND_PID=$!
sleep 2

# Verify backend started
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  err "Backend failed to start. Check the config file: $CONFIG"
  exit 1
fi
ok "Backend running (PID $BACKEND_PID)"

# ── 4. Start Vite dev server ──────────────────
info "Starting Vite dev server on :5173..."
cd "$ROOT_DIR/admin-ui"
npx vite --host &
FRONTEND_PID=$!
sleep 3

# ── 5. Print summary ──────────────────────────
clear
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              ${BOLD}Argus — Dev Environment Ready${NC}              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}  Admin Panel${NC}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}URL:${NC}      http://localhost:5173/ui/"
echo -e "  ${BOLD}Prod URL:${NC} http://localhost:9090/ui/"
echo ""
echo -e "  ${YELLOW}  Admin Token:${NC}  ${BOLD}$ADMIN_TOKEN${NC}"
echo -e "  ${YELLOW}  Gateway Key:${NC}  ${BOLD}$GATEWAY_KEY${NC}"
echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}  API Endpoints${NC}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Health:${NC}     curl http://localhost:9090/healthz"
echo -e "  ${BOLD}Metrics:${NC}    curl http://localhost:9090/metrics"
echo -e "  ${BOLD}Sessions:${NC}   curl -H 'Authorization: Bearer <token>' http://localhost:9090/api/sessions"
echo -e "  ${BOLD}Dashboard:${NC}  curl -H 'Authorization: Bearer <token>' http://localhost:9090/api/dashboard"
echo -e "  ${BOLD}Policies:${NC}   curl -H 'Authorization: Bearer <token>' http://localhost:9090/api/policies"
echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}  Database Proxy Ports${NC}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}PostgreSQL:${NC}  localhost:15432"
echo -e "  ${BOLD}MySQL:${NC}      localhost:13306"
echo -e "  ${BOLD}MSSQL:${NC}      localhost:11433"
echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}  Quick Test Commands${NC}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  # Check health:"
echo -e "  curl http://localhost:9090/livez"
echo ""
echo -e "  # List sessions (with token):"
echo -e "  curl -H 'Authorization: Bearer $ADMIN_TOKEN' \\"
echo -e "    http://localhost:9090/api/sessions"
echo ""
echo -e "  # WebSocket live events:"
echo -e "  (open http://localhost:5173/ui/events in browser)"
echo ""
echo -e "  ${YELLOW}  Press Ctrl+C to stop all services${NC}"
echo ""

# Keep running until Ctrl+C
wait
