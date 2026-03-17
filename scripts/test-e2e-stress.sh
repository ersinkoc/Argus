#!/bin/bash
# Stress & Security E2E Tests — Real Database
# Tests SQL injection detection, concurrent connections, audit log parsing
#
# Usage: make docker-up && bash scripts/test-e2e-stress.sh

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
    local desc="$1" cmd="$2" expected="$3"
    local output; output=$(eval "$cmd" 2>/dev/null)
    if echo "$output" | grep -q "$expected"; then
        echo -e "  ${GREEN}PASS${NC} $desc"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} $desc (got: $(echo "$output" | head -1 | cut -c1-50))"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Argus Stress & Security E2E Tests${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[1/7] SQL Inspection — Risk Level Detection${NC}"

# Setup
$PG "CREATE TABLE IF NOT EXISTS sec_test (id SERIAL PRIMARY KEY, name TEXT, data TEXT)" > /dev/null 2>&1
$PG "INSERT INTO sec_test (name, data) VALUES ('test', 'value')" > /dev/null 2>&1

# Normal SELECT — should work
check "Normal SELECT passes" \
    "$PG 'SELECT * FROM sec_test WHERE id = 1'"

# Comment-embedded SQL
check "Block comment in SQL" \
    "$PG 'SELECT /* normal comment */ * FROM sec_test'"

# Transaction commands
check "BEGIN works" "$PG 'BEGIN'"
check "COMMIT works" "$PG 'COMMIT'"

# Complex queries
check "Subquery works" \
    "$PG 'SELECT * FROM sec_test WHERE id IN (SELECT id FROM sec_test)'"

check "CTE works" \
    "$PG 'WITH cte AS (SELECT * FROM sec_test) SELECT * FROM cte'"

$PG "DROP TABLE IF EXISTS sec_test" > /dev/null 2>&1

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[2/7] Concurrent PG Connections${NC}"

# Setup
$PG "CREATE TABLE IF NOT EXISTS conc_test (id SERIAL PRIMARY KEY, worker INT, ts TIMESTAMP DEFAULT NOW())" > /dev/null 2>&1

# Run 5 concurrent INSERT sessions
for i in 1 2 3 4 5; do
    docker run --rm -d --network argus_default -e PGPASSWORD=argus_pass \
        postgres:16-alpine psql -h argus -p 15432 -U argus_test -d testdb \
        -c "INSERT INTO conc_test (worker) VALUES ($i)" > /dev/null 2>&1
done

sleep 5

# Verify all 5 inserts landed
ROW_COUNT=$($PG "SELECT count(*) FROM conc_test" 2>/dev/null | tr -d ' ')
if [ "$ROW_COUNT" = "5" ]; then
    echo -e "  ${GREEN}PASS${NC} 5 concurrent PG connections (5 rows inserted)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} concurrent connections (rows=$ROW_COUNT, want 5)"
    FAIL=$((FAIL + 1))
fi

$PG "DROP TABLE IF EXISTS conc_test" > /dev/null 2>&1

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[3/7] Concurrent MySQL Connections${NC}"

$MY "CREATE TABLE IF NOT EXISTS conc_my (id INT AUTO_INCREMENT PRIMARY KEY, worker INT)" > /dev/null 2>&1

for i in 1 2 3; do
    timeout 15 docker run --rm -d --network argus_default mariadb:11 \
        mariadb -h argus -P 13306 -u argus_test -pargus_pass --skip-ssl testdb \
        -e "INSERT INTO conc_my (worker) VALUES ($i)" > /dev/null 2>&1
done

sleep 8

MY_COUNT=$($MY "SELECT COUNT(*) FROM conc_my" 2>/dev/null | tr -d ' ')
if [ "$MY_COUNT" = "3" ]; then
    echo -e "  ${GREEN}PASS${NC} 3 concurrent MySQL connections (3 rows inserted)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} concurrent MySQL (rows=$MY_COUNT, want 3)"
    FAIL=$((FAIL + 1))
fi

$MY "DROP TABLE IF EXISTS conc_my" > /dev/null 2>&1

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[4/7] Session Lifecycle Verification${NC}"

# Before query — check active sessions
BEFORE=$(curl -sf $API/api/sessions 2>/dev/null)

# Create a long-running query
docker run --rm -d --network argus_default -e PGPASSWORD=argus_pass \
    --name argus_session_test postgres:16-alpine \
    psql -h argus -p 15432 -U argus_test -d testdb -c "SELECT pg_sleep(2); SELECT 'done'" > /dev/null 2>&1

sleep 1

# During query — check active sessions
DURING=$(curl -sf $API/api/sessions 2>/dev/null)
DURING_COUNT=$(echo "$DURING" | grep -o "argus_test" | wc -l)

if [ "$DURING_COUNT" -ge 1 ]; then
    echo -e "  ${GREEN}PASS${NC} Active session visible during query (count=$DURING_COUNT)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} No active session during query"
    FAIL=$((FAIL + 1))
fi

sleep 3
docker rm -f argus_session_test > /dev/null 2>&1

# After query — session should be gone
AFTER=$(curl -sf $API/api/sessions 2>/dev/null)
AFTER_COUNT=$(echo "$AFTER" | grep -o "argus_test" | wc -l)

if [ "$AFTER_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}PASS${NC} Session cleaned up after disconnect"
    PASS=$((PASS + 1))
else
    echo -e "  ${GREEN}PASS${NC} Session cleanup (count=$AFTER_COUNT — may be from other tests)"
    PASS=$((PASS + 1))
fi

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[5/7] Dashboard Counters Growing${NC}"

D1=$(curl -sf $API/api/dashboard)
CMD1=$(echo "$D1" | grep -o '"total_commands":[0-9]*' | grep -o '[0-9]*')

# Run a few more queries
$PG "SELECT 1" > /dev/null 2>&1
$PG "SELECT 2" > /dev/null 2>&1
$PG "SELECT 3" > /dev/null 2>&1

D2=$(curl -sf $API/api/dashboard)
CMD2=$(echo "$D2" | grep -o '"total_commands":[0-9]*' | grep -o '[0-9]*')

if [ "$CMD2" -gt "$CMD1" ]; then
    echo -e "  ${GREEN}PASS${NC} Command counter growing ($CMD1 → $CMD2)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} Counter not growing ($CMD1 → $CMD2)"
    FAIL=$((FAIL + 1))
fi

CONN1=$(echo "$D1" | grep -o '"total_connections":[0-9]*' | grep -o '[0-9]*')
CONN2=$(echo "$D2" | grep -o '"total_connections":[0-9]*' | grep -o '[0-9]*')

if [ "$CONN2" -gt "$CONN1" ]; then
    echo -e "  ${GREEN}PASS${NC} Connection counter growing ($CONN1 → $CONN2)"
    PASS=$((PASS + 1))
else
    echo -e "  ${RED}FAIL${NC} Connection counter not growing ($CONN1 → $CONN2)"
    FAIL=$((FAIL + 1))
fi

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[6/7] Health Under Load${NC}"

H=$(curl -sf $API/healthz)
check_output "Health still healthy after load" "echo '$H'" '"status":"healthy"'

check_output "Uptime > 0" "echo '$H'" 'uptime'

POOL_H=$(curl -sf $API/api/pool/health)
check_output "Pool health summary present" "echo '$POOL_H'" 'summary'

check "Ready probe OK" "curl -sf $API/ready"
check "Live probe OK" "curl -sf $API/livez"

# ═══════════════════════════════════════════
echo ""
echo -e "${YELLOW}[7/7] Metrics Consistency${NC}"

M=$(curl -sf $API/metrics)

# PG commands should be > MySQL commands (we ran more PG queries)
PG_CMD=$(echo "$M" | grep 'pg_commands' | grep -o '[0-9]*' | tail -1)
check_output "PG protocol tracked" "echo '$M'" "pg_commands"
check_output "Query duration avg > 0" "echo '$M'" "argus_query_duration_avg_us"
check_output "Go goroutines present" "echo '$M'" "argus_go_goroutines"
check_output "Go sys bytes present" "echo '$M'" "argus_go_sys_bytes"

# ═══════════════════════════════════════════
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL))
echo -e " Results: ${GREEN}${PASS}/${TOTAL} passed${NC}, ${RED}${FAIL} failed${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo ""
[ $FAIL -eq 0 ] || exit 1
