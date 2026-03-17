#!/bin/bash
# End-to-End Test Script for Argus Multi-Database Proxy
#
# Prerequisites:
#   docker compose up -d
#   Wait for all services to be healthy
#
# Ports:
#   Direct DB:    PG=35432  MySQL=33306  MSSQL=31433
#   Via Argus:    PG=30100  MySQL=30101  MSSQL=30102
#   Admin/Metrics: 30200

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local desc="$1"
    local cmd="$2"

    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "=========================================="
echo " Argus E2E Test Suite"
echo "=========================================="

# ---- Health Checks ----
echo ""
echo -e "${YELLOW}[1/6] Health Checks${NC}"

check "Argus healthz" \
    "curl -sf http://localhost:30200/healthz"

check "Argus livez" \
    "curl -sf http://localhost:30200/livez"

check "Argus readiness" \
    "curl -sf http://localhost:30200/ready"

check "Argus metrics" \
    "curl -sf http://localhost:30200/metrics | grep argus_active_sessions"

# ---- PostgreSQL via Argus ----
echo ""
echo -e "${YELLOW}[2/6] PostgreSQL via Argus (port 30100)${NC}"

check "PG connect & SELECT 1" \
    "PGPASSWORD=argus_pass psql -h localhost -p 30100 -U argus_test -d testdb -c 'SELECT 1' -t"

check "PG create table" \
    "PGPASSWORD=argus_pass psql -h localhost -p 30100 -U argus_test -d testdb -c 'CREATE TABLE IF NOT EXISTS e2e_test (id SERIAL PRIMARY KEY, name TEXT, email TEXT)'"

check "PG insert data" \
    "PGPASSWORD=argus_pass psql -h localhost -p 30100 -U argus_test -d testdb -c \"INSERT INTO e2e_test (name, email) VALUES ('Alice', 'alice@example.com'), ('Bob', 'bob@test.org')\""

check "PG select data" \
    "PGPASSWORD=argus_pass psql -h localhost -p 30100 -U argus_test -d testdb -c 'SELECT * FROM e2e_test' -t"

check "PG update data" \
    "PGPASSWORD=argus_pass psql -h localhost -p 30100 -U argus_test -d testdb -c \"UPDATE e2e_test SET name = 'Alice Updated' WHERE id = 1\""

check "PG cleanup" \
    "PGPASSWORD=argus_pass psql -h localhost -p 30100 -U argus_test -d testdb -c 'DROP TABLE IF EXISTS e2e_test'"

# ---- MySQL via Argus ----
echo ""
echo -e "${YELLOW}[3/6] MySQL via Argus (port 30101)${NC}"

check "MySQL connect & SELECT 1" \
    "mysql -h 127.0.0.1 -P 30101 -u argus_test -pargus_pass testdb -e 'SELECT 1'"

check "MySQL create table" \
    "mysql -h 127.0.0.1 -P 30101 -u argus_test -pargus_pass testdb -e 'CREATE TABLE IF NOT EXISTS e2e_test (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255))'"

check "MySQL insert" \
    "mysql -h 127.0.0.1 -P 30101 -u argus_test -pargus_pass testdb -e \"INSERT INTO e2e_test (name, email) VALUES ('Charlie', 'charlie@example.com')\""

check "MySQL select" \
    "mysql -h 127.0.0.1 -P 30101 -u argus_test -pargus_pass testdb -e 'SELECT * FROM e2e_test'"

check "MySQL cleanup" \
    "mysql -h 127.0.0.1 -P 30101 -u argus_test -pargus_pass testdb -e 'DROP TABLE IF EXISTS e2e_test'"

# ---- Direct DB Access (bypass Argus) ----
echo ""
echo -e "${YELLOW}[4/6] Direct DB Access (bypass Argus)${NC}"

check "PG direct (port 35432)" \
    "PGPASSWORD=argus_pass psql -h localhost -p 35432 -U argus_test -d testdb -c 'SELECT version()' -t"

check "MySQL direct (port 33306)" \
    "mysql -h 127.0.0.1 -P 33306 -u argus_test -pargus_pass testdb -e 'SELECT VERSION()'"

# ---- Admin API ----
echo ""
echo -e "${YELLOW}[5/6] Admin API${NC}"

check "Dashboard" \
    "curl -sf http://localhost:30200/api/dashboard | grep uptime"

check "Sessions list" \
    "curl -sf http://localhost:30200/api/sessions"

check "Stats" \
    "curl -sf http://localhost:30200/api/stats | grep commands"

check "Pool health" \
    "curl -sf http://localhost:30200/api/pool/health | grep summary"

check "Policy validate" \
    "curl -sf http://localhost:30200/api/policies/validate"

check "Policy dry-run" \
    "curl -sf -X POST 'http://localhost:30200/api/policies/dryrun?username=dev_john&sql=SELECT+*+FROM+users'"

# ---- Metrics Verification ----
echo ""
echo -e "${YELLOW}[6/6] Metrics Verification${NC}"

check "Prometheus connections metric" \
    "curl -sf http://localhost:30200/metrics | grep argus_connections_total"

check "Prometheus commands metric" \
    "curl -sf http://localhost:30200/metrics | grep argus_commands_total"

check "Prometheus protocol stats" \
    "curl -sf http://localhost:30200/metrics | grep argus_protocol_commands_total"

check "Prometheus query duration" \
    "curl -sf http://localhost:30200/metrics | grep argus_query_duration_count"

check "Prometheus pool wait" \
    "curl -sf http://localhost:30200/metrics | grep argus_pool_wait_count"

# ---- Summary ----
echo ""
echo "=========================================="
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "=========================================="
echo ""

if [ $FAIL -gt 0 ]; then
    exit 1
fi
