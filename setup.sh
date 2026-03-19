#!/usr/bin/env bash
# ==============================================================================
#  Argus — Interactive setup script for Linux / macOS
#
#  Usage:
#    ./setup.sh              Full interactive setup
#    ./setup.sh --skip-build Skip Go build
#    ./setup.sh --skip-tests Skip E2E tests
#    ./setup.sh --down       Stop stack and remove volumes
# ==============================================================================
set -euo pipefail

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; GRAY='\033[0;37m'; BOLD='\033[1m'; NC='\033[0m'

step()  { echo -e "\n${CYAN}==> $*${NC}"; }
ok()    { echo -e "  ${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "  ${YELLOW}[!!]${NC} $*"; }
info()  { echo -e "  ${GRAY}    $*${NC}"; }
fail()  { echo -e "\n${RED}[FAIL]${NC} $*"; exit 1; }

banner() {
  echo ""
  echo -e "${CYAN}${BOLD}  ╔═══════════════════════════════════════╗"
  echo -e "  ║           Argus — Setup               ║"
  echo -e "  ║  Database Firewall & Access Proxy     ║"
  echo -e "  ╚═══════════════════════════════════════╝${NC}"
  echo ""
}

confirm() {
  local question="$1"
  local default="${2:-y}"
  local yn; [[ "$default" == "y" ]] && yn="Y/n" || yn="y/N"
  read -rp "  $question [$yn] " ans
  ans="${ans:-$default}"
  [[ "$ans" =~ ^[Yy] ]]
}

cmd_exists() { command -v "$1" &>/dev/null; }

# ── flags ─────────────────────────────────────────────────────────────────────
SKIP_BUILD=0; SKIP_TESTS=0; DOWN_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --skip-tests) SKIP_TESTS=1 ;;
    --down)       DOWN_ONLY=1 ;;
  esac
done

# ── detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
PKG_MANAGER=""

detect_pkg_manager() {
  if   cmd_exists apt-get; then PKG_MANAGER="apt"
  elif cmd_exists dnf;     then PKG_MANAGER="dnf"
  elif cmd_exists yum;     then PKG_MANAGER="yum"
  elif cmd_exists pacman;  then PKG_MANAGER="pacman"
  elif cmd_exists brew;    then PKG_MANAGER="brew"
  fi
}

SUDO=""
if [[ "$(id -u)" -ne 0 ]] && cmd_exists sudo; then SUDO="sudo"; fi

# ── Go install ────────────────────────────────────────────────────────────────
MIN_GO="1.21"
GO_LATEST="1.23.4"   # update as needed

go_version() {
  go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+(\.[0-9]+)?' || true
}

version_gte() {
  # returns 0 (true) if $1 >= $2
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

install_go_linux() {
  local arch
  case "$ARCH" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    armv7l)  arch="armv6l" ;;
    *)       fail "Unsupported arch $ARCH for auto Go install. Download from https://golang.org/dl/" ;;
  esac
  local tarball="go${GO_LATEST}.linux-${arch}.tar.gz"
  local url="https://go.dev/dl/${tarball}"
  info "Downloading $url ..."
  curl -fsSL "$url" -o "/tmp/$tarball"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "/tmp/$tarball"
  rm "/tmp/$tarball"
  export PATH="/usr/local/go/bin:$PATH"
  # persist for future shells
  local profile="${HOME}/.profile"
  grep -q '/usr/local/go/bin' "$profile" 2>/dev/null || \
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$profile"
}

install_go_mac() {
  if cmd_exists brew; then
    brew install go
  else
    local arch; [[ "$ARCH" == "arm64" ]] && arch="arm64" || arch="amd64"
    local pkg="go${GO_LATEST}.darwin-${arch}.pkg"
    local url="https://go.dev/dl/$pkg"
    info "Downloading $url ..."
    curl -fsSL "$url" -o "/tmp/$pkg"
    $SUDO installer -pkg "/tmp/$pkg" -target /
    rm "/tmp/$pkg"
    export PATH="/usr/local/go/bin:$PATH"
  fi
}

ensure_go() {
  step "Checking Go installation..."
  if cmd_exists go; then
    local ver; ver=$(go_version)
    if version_gte "$ver" "$MIN_GO"; then
      ok "Go $ver"
      return
    fi
    warn "Go $ver found but $MIN_GO+ required."
  else
    warn "Go not found."
  fi

  confirm "Install/upgrade Go $GO_LATEST?" || fail "Go is required."

  case "$OS" in
    Linux)  install_go_linux ;;
    Darwin) install_go_mac ;;
    *)      fail "Cannot auto-install Go on $OS. Visit https://golang.org/dl/" ;;
  esac

  cmd_exists go || fail "Go installation failed."
  ok "Go $(go_version) installed."
}

# ── Docker install ────────────────────────────────────────────────────────────
MIN_DOCKER="24.0"

docker_server_version() {
  docker version --format '{{.Server.Version}}' 2>/dev/null | grep -oP '[0-9]+\.[0-9]+' || true
}

install_docker_linux() {
  case "$PKG_MANAGER" in
    apt)
      info "Installing Docker via apt (official Docker repo)..."
      $SUDO apt-get update -qq
      $SUDO apt-get install -y -q ca-certificates curl gnupg lsb-release
      $SUDO install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
      local codename; codename=$(lsb_release -cs 2>/dev/null || . /etc/os-release && echo "$VERSION_CODENAME")
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $codename stable" | \
        $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
      $SUDO apt-get update -qq
      $SUDO apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      $SUDO systemctl enable --now docker 2>/dev/null || true
      # add current user to docker group
      if [[ -n "$SUDO" ]]; then
        $SUDO usermod -aG docker "$USER" || true
        warn "Added $USER to docker group — you may need to log out and back in."
      fi
      ;;
    dnf|yum)
      info "Installing Docker via dnf/yum..."
      $SUDO "$PKG_MANAGER" install -y yum-utils
      $SUDO yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      $SUDO "$PKG_MANAGER" install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      $SUDO systemctl enable --now docker 2>/dev/null || true
      $SUDO usermod -aG docker "$USER" 2>/dev/null || true
      ;;
    pacman)
      info "Installing Docker via pacman..."
      $SUDO pacman -Sy --noconfirm docker docker-compose
      $SUDO systemctl enable --now docker 2>/dev/null || true
      $SUDO usermod -aG docker "$USER" 2>/dev/null || true
      ;;
    brew)
      brew install docker docker-compose
      ;;
    *)
      fail "No supported package manager found. Install Docker manually: https://docs.docker.com/engine/install/"
      ;;
  esac
}

install_docker_mac() {
  if cmd_exists brew; then
    info "Installing Docker Desktop via Homebrew Cask..."
    brew install --cask docker
    info "Starting Docker Desktop..."
    open -a Docker
  else
    fail "Homebrew not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
  fi
}

wait_for_docker() {
  info "Waiting for Docker daemon (up to 90s)..."
  local i=0
  while [[ $i -lt 90 ]]; do
    if docker info &>/dev/null; then
      ok "Docker daemon is up."
      return 0
    fi
    sleep 5; ((i+=5))
    echo -ne "  ... ${i}s\r"
  done
  fail "Docker daemon did not start in time. Start Docker manually."
}

ensure_docker() {
  step "Checking Docker installation..."
  detect_pkg_manager

  if ! cmd_exists docker; then
    warn "Docker not found."
    confirm "Install Docker?" || fail "Docker is required."
    case "$OS" in
      Linux)  install_docker_linux ;;
      Darwin) install_docker_mac ;;
      *)      fail "Cannot auto-install Docker on $OS." ;;
    esac
  fi

  wait_for_docker

  local ver; ver=$(docker_server_version)
  if [[ -z "$ver" ]]; then
    fail "Docker installed but daemon not reachable."
  fi
  ok "Docker $ver"

  # Docker Compose v2
  if docker compose version &>/dev/null 2>&1; then
    ok "docker compose $(docker compose version --short 2>/dev/null)"
  elif cmd_exists docker-compose; then
    warn "Only docker-compose v1 found. Upgrade to Docker with Compose v2 plugin."
    fail "docker compose (v2) is required."
  else
    fail "docker compose not available. Ensure Docker Engine includes the compose plugin."
  fi
}

# ── Build Argus ───────────────────────────────────────────────────────────────
build_argus() {
  [[ $SKIP_BUILD -eq 1 ]] && { warn "Skipping build (--skip-build)"; return; }
  step "Building Argus binary..."
  local version; version=$(git describe --tags --always 2>/dev/null || echo "dev")
  local buildtime; buildtime=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.Version=$version -X main.BuildTime=$buildtime" \
    -o argus \
    ./cmd/argus/
  ok "Binary built: ./argus ($version)"
}

# ── Mode selection ────────────────────────────────────────────────────────────
select_mode() {
  echo ""
  echo -e "  ${BOLD}Choose deployment mode:${NC}"
  echo "  [1] Full stack — PostgreSQL + MySQL + MSSQL via Docker Compose (recommended)"
  echo "  [2] Local only — Run argus with local PostgreSQL (you manage the DB)"
  echo "  [3] Exit"
  read -rp "  Choice [1]: " mode
  mode="${mode:-1}"
  echo "$mode"
}

# ── MSSQL setup ───────────────────────────────────────────────────────────────
setup_mssql() {
  step "Setting up MSSQL database and user..."
  sleep 10  # extra buffer

  local sql="
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name='testdb')
    CREATE DATABASE testdb;
IF NOT EXISTS (SELECT name FROM sys.server_principals WHERE name='argus_test')
BEGIN
    CREATE LOGIN argus_test WITH PASSWORD='argus_pass', CHECK_POLICY=OFF;
END
USE testdb;
IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name='argus_test')
BEGIN
    CREATE USER argus_test FOR LOGIN argus_test;
    ALTER ROLE db_owner ADD MEMBER argus_test;
END"

  # try both possible container names
  for cname in argus-mssql-1 argus_mssql_1; do
    if docker exec "$cname" \
        /opt/mssql-tools18/bin/sqlcmd \
        -S localhost -U sa -P 'Argus_Pass123!' -C -N \
        -Q "$sql" &>/dev/null 2>&1; then
      ok "MSSQL testdb and argus_test user ready."
      return
    fi
  done
  warn "MSSQL setup failed — run 'make setup-mssql' manually if MSSQL is needed."
}

# ── Health wait ───────────────────────────────────────────────────────────────
wait_healthy() {
  step "Waiting for containers to become healthy..."
  local timeout=120 elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    # count containers not yet healthy
    local unhealthy
    unhealthy=$(docker compose ps --format json 2>/dev/null | \
      python3 -c "
import sys,json
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try:
        d=json.loads(line)
        h=d.get('Health','')
        if h and h!='healthy':
            print(d.get('Name','?'))
    except: pass" 2>/dev/null || \
      docker compose ps 2>/dev/null | awk 'NR>1 && $0 !~ /healthy/ && $0 ~ /\(/ {print $1}' \
    )
    if [[ -z "$unhealthy" ]]; then
      ok "All containers healthy."
      return
    fi
    sleep 5; ((elapsed+=5))
    echo -ne "  ... waiting (${elapsed}s): $unhealthy\r"
  done
  echo ""
  warn "Some containers may not be healthy yet — continuing anyway."
}

# ── Print endpoints ───────────────────────────────────────────────────────────
print_endpoints() {
  echo ""
  echo -e "  ${BOLD}Stack is running! Service endpoints:${NC}"
  echo ""
  echo -e "  ${BOLD}Databases (direct access):${NC}"
  echo "    PostgreSQL  ->  localhost:35432   (argus_test / argus_pass / testdb)"
  echo "    MySQL       ->  localhost:33306   (argus_test / argus_pass / testdb)"
  echo "    MSSQL       ->  localhost:31433   (argus_test / argus_pass / testdb)"
  echo ""
  echo -e "  ${BOLD}Argus Proxy:${NC}"
  echo "    PostgreSQL  ->  localhost:30100"
  echo "    MySQL       ->  localhost:30101"
  echo "    MSSQL       ->  localhost:30102"
  echo "    Admin API   ->  http://localhost:30200"
  echo "    Metrics     ->  http://localhost:30200/metrics"
  echo ""
  echo -e "  ${BOLD}Useful commands:${NC}"
  echo "    docker compose logs -f argus   # follow Argus logs"
  echo "    docker compose ps              # service status"
  echo "    ./setup.sh --down              # stop and remove volumes"
  echo ""
}

# ── E2E tests ─────────────────────────────────────────────────────────────────
run_e2e() {
  [[ $SKIP_TESTS -eq 1 ]] && return
  confirm "Run end-to-end tests now?" || return
  step "Running E2E test suite..."
  bash scripts/test-e2e-full.sh
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
banner

if [[ $DOWN_ONLY -eq 1 ]]; then
  step "Bringing stack down..."
  docker compose down -v
  ok "Stack stopped and volumes removed."
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ensure_go
ensure_docker
build_argus

mode=$(select_mode)

case "$mode" in
  2)
    step "Local mode — starting Argus with configs/argus.json..."
    info "Press Ctrl+C to stop."
    exec ./argus -config configs/argus.json
    ;;
  3)
    exit 0
    ;;
  *)
    step "Building Docker image..."
    docker compose build --no-cache argus

    step "Starting database stack (PostgreSQL + MySQL + MSSQL)..."
    docker compose up -d

    wait_healthy
    setup_mssql
    print_endpoints
    run_e2e

    step "Setup complete."
    ;;
esac
