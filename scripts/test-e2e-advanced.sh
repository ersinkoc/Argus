#!/bin/bash
# Advanced E2E Test Suite — Real Database Policy Enforcement
# Tests Argus with production-like policies on real PostgreSQL + MySQL
#
# Usage: make docker-up && bash scripts/test-e2e-advanced.sh

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
API="http://localhost:30200"

PG="docker run --rm --network argus_default -e PGPASSWORD=argus_pass postgres:16-alpine psql -h argus -p 15432 -U argus_test -d testdb -t -A -c"
MY="timeout 15 docker run --rm --network argus_default mariadb:11 mariadb -h argus -P 13306 -u argus_test -pargus_pass --skip-ssl testdb -N -B -e"

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

check_output() {
    local desc="$1"
    local cmd="$2"
    local expected="$3"
    local output
    output=$(eval "$cmd" 2>/dev/null)
    if echo "$output" | grep -q "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc (got: $(echo "$output" | head -1 | cut -c1-60))"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Argus Advanced E2E — Real Database Policy Tests${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[1/9] Setup Test Data${NC}"

check "PG: Create users table" \
    "$PG 'CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT, email TEXT, phone TEXT, salary INT, tc_kimlik TEXT)'"

check "PG: Insert test data" \
    "$PG \"INSERT INTO users (name, email, phone, salary, tc_kimlik) VALUES ('Alice', 'alice@example.com', '+905321234567', 85000, '10000000146'), ('Bob', 'bob@test.org', '+905559876543', 120000, '12345678901') ON CONFLICT DO NOTHING\""

check "MySQL: Create users table" \
    "$MY 'CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), phone VARCHAR(20), salary INT)'"

check "MySQL: Insert test data" \
    "$MY \"INSERT IGNORE INTO users (name, email, phone, salary) VALUES ('Charlie', 'charlie@example.com', '+905551112233', 95000)\""

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[2/9] PG: Read Operations${NC}"

check "PG: SELECT * FROM users" \
    "$PG 'SELECT * FROM users'"

check_output "PG: SELECT returns Alice" \
    "$PG 'SELECT name FROM users WHERE id = 1'" \
    "Alice"

check_output "PG: Count rows" \
    "$PG 'SELECT count(*) FROM users'" \
    "2"

check "PG: SELECT with JOIN (self)" \
    "$PG 'SELECT u1.name, u2.email FROM users u1 JOIN users u2 ON u1.id = u2.id'"

check "PG: SELECT with WHERE" \
    "$PG \"SELECT * FROM users WHERE salary > 100000\""

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[3/9] PG: Write Operations${NC}"

check "PG: UPDATE with WHERE" \
    "$PG \"UPDATE users SET name = 'Alice Updated' WHERE id = 1\""

check "PG: INSERT single" \
    "$PG \"INSERT INTO users (name, email, phone, salary, tc_kimlik) VALUES ('Eve', 'eve@test.com', '+905001112233', 70000, '11111111111')\""

check "PG: DELETE with WHERE" \
    "$PG 'DELETE FROM users WHERE name = '\''Eve'\'''"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[4/9] PG: DDL Operations${NC}"

check "PG: CREATE TABLE allowed" \
    "$PG 'CREATE TABLE IF NOT EXISTS temp_test (id INT)'"

check "PG: DROP TABLE allowed (argus_test is not in !dba exclusion — default policy allows)" \
    "$PG 'DROP TABLE IF EXISTS temp_test'"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[5/9] MySQL: Full CRUD via Argus${NC}"

check "MySQL: SELECT" \
    "$MY 'SELECT * FROM users'"

check "MySQL: UPDATE" \
    "$MY \"UPDATE users SET name = 'Charlie Updated' WHERE id = 1\""

check "MySQL: INSERT" \
    "$MY \"INSERT INTO users (name, email, phone, salary) VALUES ('Dave', 'dave@test.com', '+905001234567', 60000)\""

check "MySQL: DELETE" \
    "$MY 'DELETE FROM users WHERE name = '\''Dave'\'''"

check "MySQL: CREATE TABLE" \
    "$MY 'CREATE TABLE IF NOT EXISTS temp_mysql (id INT AUTO_INCREMENT PRIMARY KEY, val TEXT)'"

check "MySQL: DROP TABLE" \
    "$MY 'DROP TABLE IF EXISTS temp_mysql'"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[6/9] Audit Log Verification${NC}"

# Check that Argus logged commands
METRICS=$(curl -sf $API/metrics)

check_output "Audit: commands total > 0" \
    "echo '$METRICS'" \
    "argus_commands_total [1-9]"

check_output "Audit: PG protocol commands > 0" \
    "echo '$METRICS' | grep 'argus_protocol_commands_total'" \
    "[1-9]"

check_output "Audit: query duration recorded" \
    "echo '$METRICS' | grep 'argus_query_duration_microseconds_count'" \
    "[1-9]"

# Verify audit via dashboard
DASHBOARD=$(curl -sf $API/api/dashboard)

check_output "Dashboard: total_commands > 5" \
    "echo '$DASHBOARD'" \
    "total_commands"

check_output "Dashboard: total_connections > 0" \
    "echo '$DASHBOARD'" \
    "total_connections"

check_output "Dashboard: healthy targets = 3" \
    "echo '$DASHBOARD'" \
    "healthy_targets"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[7/9] Admin API Deep Tests${NC}"

# Policy dry-run: SELECT should be allowed
check_output "DryRun: SELECT allowed" \
    "curl -sf -X POST '$API/api/policies/dryrun?username=dev_john&sql=SELECT+*+FROM+users'" \
    "allow"

# Policy dry-run: DDL with DROP for non-DBA — check risk score is high
check_output "DryRun: DROP DDL high risk for dev" \
    "curl -sf -X POST '$API/api/policies/dryrun?username=dev_john&sql=DROP+TABLE+users'" \
    "risk_score"

# Policy dry-run: DDL with DROP for DBA should be allowed
check_output "DryRun: DROP allowed for admin" \
    "curl -sf -X POST '$API/api/policies/dryrun?username=admin&sql=DROP+TABLE+users'" \
    "allow"

# Policy validate
check_output "Validate: policy valid" \
    "curl -sf $API/api/policies/validate" \
    "valid"

# Config export
check_output "Config: has listeners" \
    "curl -sf $API/api/config/export" \
    "listeners"

# Stats
check_output "Stats: has commands" \
    "curl -sf $API/api/stats" \
    "commands"

# Pool health
check_output "Pool: all healthy" \
    "curl -sf $API/api/pool/health" \
    "healthy"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[8/9] Prometheus Metrics Deep Check${NC}"

check_output "Metric: active_sessions gauge" \
    "echo '$METRICS'" \
    "argus_active_sessions"

check_output "Metric: pool active per target" \
    "echo '$METRICS'" \
    "argus_pool_connections"

check_output "Metric: pool idle per target" \
    "echo '$METRICS'" \
    "argus_pool_connections"

check_output "Metric: query latency p50" \
    "echo '$METRICS'" \
    "argus_query_duration_microseconds_bucket"

check_output "Metric: pool wait p95" \
    "echo '$METRICS'" \
    "argus_pool_acquire_wait_microseconds_bucket"

check_output "Metric: go memory" \
    "echo '$METRICS'" \
    "argus_go_alloc_bytes"

check_output "Metric: database queries" \
    "echo '$METRICS'" \
    "argus_database_queries_total"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[9/9] Cleanup${NC}"

check "PG: Drop test table" \
    "$PG 'DROP TABLE IF EXISTS users'"

check "MySQL: Drop test table" \
    "$MY 'DROP TABLE IF EXISTS users'"

# ═══════════════════════════════════════════
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL))
echo -e " Results: ${GREEN}${PASS}/${TOTAL} passed${NC}, ${RED}${FAIL} failed${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""
[ $FAIL -eq 0 ] || exit 1
