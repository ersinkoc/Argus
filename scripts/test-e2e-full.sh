#!/bin/bash
# Comprehensive E2E Test Suite for Argus
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
API="http://localhost:30200"

check() {
    local desc="$1"; shift
    if eval "$@" > /dev/null 2>&1; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        FAIL=$((FAIL + 1))
    fi
}

PG="docker run --rm --network argus_default -e PGPASSWORD=argus_pass postgres:16-alpine psql -h argus -p 15432 -U argus_test -d testdb -t -A -c"
MY="docker run --rm --network argus_default mariadb:11 mariadb -h argus -P 13306 -u argus_test -pargus_pass --skip-ssl testdb -N -B -e"

echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${CYAN}  Argus Full E2E Test Suite${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"

echo ""
echo -e "${YELLOW}[1/8] Health & Probes${NC}"
check "GET /healthz"     "curl -sf $API/healthz"
check "GET /livez"       "curl -sf $API/livez"
check "GET /ready"       "curl -sf $API/ready"
check "GET /metrics"     "curl -sf $API/metrics | grep argus_active_sessions"

echo ""
echo -e "${YELLOW}[2/8] PostgreSQL CRUD${NC}"
check "PG SELECT 1"       "$PG 'SELECT 1'"
check "PG CREATE TABLE"   "$PG 'CREATE TABLE IF NOT EXISTS e2e_pg (id SERIAL PRIMARY KEY, name TEXT, email TEXT, salary INT)'"
check "PG INSERT"          "$PG \"INSERT INTO e2e_pg (name, email, salary) VALUES ('Alice', 'alice@example.com', 75000)\""
check "PG SELECT rows"    "$PG 'SELECT count(*) FROM e2e_pg'"
check "PG UPDATE"          "$PG \"UPDATE e2e_pg SET name = 'Updated' WHERE id = 1\""
check "PG DELETE"          "$PG 'DELETE FROM e2e_pg WHERE id = 1'"
check "PG DROP TABLE"      "$PG 'DROP TABLE IF EXISTS e2e_pg'"
check "PG multi-statement" "$PG 'SELECT 1 AS a; SELECT 2 AS b'"

echo ""
echo -e "${YELLOW}[3/8] MySQL/MariaDB CRUD${NC}"
check "MySQL SELECT 1"       "timeout 15 $MY 'SELECT 1'"
check "MySQL CREATE TABLE"   "timeout 15 $MY 'CREATE TABLE IF NOT EXISTS e2e_my (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100))'"
check "MySQL INSERT"          "timeout 15 $MY \"INSERT INTO e2e_my (name, email) VALUES ('Bob', 'bob@test.com')\""
check "MySQL SELECT rows"    "timeout 15 $MY 'SELECT COUNT(*) FROM e2e_my'"
check "MySQL DROP TABLE"      "timeout 15 $MY 'DROP TABLE IF EXISTS e2e_my'"

echo ""
echo -e "${YELLOW}[4/8] Policy Enforcement${NC}"
$PG "CREATE TABLE IF NOT EXISTS pol_test (id SERIAL, name TEXT, email TEXT)" > /dev/null 2>&1
$PG "INSERT INTO pol_test (name, email) VALUES ('Test', 'test@test.com')" > /dev/null 2>&1
check "SELECT allowed"          "$PG 'SELECT * FROM pol_test'"
check "INSERT allowed"          "$PG \"INSERT INTO pol_test (name, email) VALUES ('X', 'x@x.com')\""
check "UPDATE with WHERE"       "$PG \"UPDATE pol_test SET name = 'Y' WHERE id = 1\""
check "DELETE with WHERE"       "$PG 'DELETE FROM pol_test WHERE id = 1'"
$PG "DROP TABLE IF EXISTS pol_test" > /dev/null 2>&1

echo ""
echo -e "${YELLOW}[5/8] Admin REST API${NC}"
check "Dashboard"               "curl -sf $API/api/dashboard | grep uptime"
check "Sessions"                "curl -sf $API/api/sessions"
check "Stats"                   "curl -sf $API/api/stats | grep commands"
check "Pool health"             "curl -sf $API/api/pool/health | grep summary"
check "Approvals"               "curl -sf $API/api/approvals"
check "Policy validate"         "curl -sf $API/api/policies/validate"
check "Policy dry-run"          "curl -sf -X POST '$API/api/policies/dryrun?username=dev_john&sql=SELECT+1' | grep action"
check "Config export"           "curl -sf $API/api/config/export | grep listeners"

echo ""
echo -e "${YELLOW}[6/8] Prometheus Metrics${NC}"
M=$(curl -sf $API/metrics)
check "active_sessions"    "echo '$M' | grep argus_active_sessions"
check "connections_total"  "echo '$M' | grep argus_connections_total"
check "commands_total"     "echo '$M' | grep argus_commands_total"
check "query_duration"     "echo '$M' | grep argus_query_duration_count"
check "protocol_stats"     "echo '$M' | grep argus_protocol_commands_total"
check "pool_wait"          "echo '$M' | grep argus_pool_wait_count"
check "go_goroutines"      "echo '$M' | grep argus_go_goroutines"

echo ""
echo -e "${YELLOW}[7/8] Dashboard Data${NC}"
D=$(curl -sf $API/api/dashboard)
check "uptime present"         "echo '$D' | grep uptime"
check "healthy_targets"        "echo '$D' | grep healthy_targets"
check "total_commands > 0"     "echo '$D' | grep -o 'total_commands\":[1-9]'"
check "pool targets"           "echo '$D' | grep postgres"

echo ""
echo -e "${YELLOW}[8/8] Multi-Protocol Health${NC}"
H=$(curl -sf $API/healthz)
check "PG target"           "echo '$H' | grep postgres"
check "MySQL target"        "echo '$H' | grep mysql"
check "MSSQL target"        "echo '$H' | grep mssql"
check "status=healthy"      "echo '$H' | grep '\"status\":\"healthy\"'"
check "version"             "echo '$H' | grep v1.0.0"

echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL))
echo -e " Results: ${GREEN}${PASS}/${TOTAL} passed${NC}, ${RED}${FAIL} failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo ""
[ $FAIL -eq 0 ] || exit 1
