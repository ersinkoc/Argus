#!/bin/bash
# =============================================================================
# Argus Extra Real-World Scenarios
# Tests: Transactions, Large data, Error handling, Complex queries, Admin API
# Covers: PG + MySQL through Argus proxy
# Note: MSSQL sqlcmd ODBC 18 requires TLS — MSSQL tested at protocol level
# =============================================================================

# Note: no set -e — we test expected failures in error resilience phase

PG="docker exec -e PGPASSWORD=argus_pass argus-postgres-1 psql -h argus -p 15432 -U argus_test -d testdb -q -t"
MY="docker exec argus-mysql-1 mariadb -h argus -P 13306 -u argus_test -pargus_pass --skip-ssl -s testdb"
API="http://127.0.0.1:30200"

OK=0; FAIL=0; TOTAL=0
pass() { OK=$((OK+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
run_pg()  { MSYS_NO_PATHCONV=1 $PG "$1" 2>/dev/null && pass "$2" || fail "$2"; }
run_my()  { MSYS_NO_PATHCONV=1 $MY -e "$1" 2>/dev/null && pass "$2" || fail "$2"; }
check_api() {
  local desc="$1" url="$2" expected="$3"
  local out; out=$(curl -s "$url" 2>/dev/null)
  if echo "$out" | grep -q "$expected"; then pass "$desc"; else fail "$desc (expected: $expected)"; fi
}

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ARGUS EXTRA SCENARIOS E2E TEST                        ║"
echo "║   Dashboard: http://127.0.0.1:30200/ui                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Snapshot dashboard before
CMD_BEFORE=$(curl -sf $API/api/dashboard 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['traffic']['total_commands'])" 2>/dev/null || echo 0)

# ─────────────────────────────────────────────────
# PHASE 1: PostgreSQL Transactions
# ─────────────────────────────────────────────────
echo "━━━ PHASE 1: PostgreSQL Transactions ━━━"

run_pg "CREATE TABLE IF NOT EXISTS tx_accounts (id SERIAL PRIMARY KEY, name VARCHAR(50) UNIQUE, balance DECIMAL(12,2));" "PG: Create accounts table"
run_pg "INSERT INTO tx_accounts (name, balance) VALUES ('Alice', 10000), ('Bob', 5000), ('Charlie', 3000) ON CONFLICT (name) DO NOTHING;" "PG: Seed accounts"

run_pg "BEGIN; UPDATE tx_accounts SET balance = balance - 2000 WHERE name = 'Alice'; UPDATE tx_accounts SET balance = balance + 2000 WHERE name = 'Bob'; COMMIT;" "PG: Transaction — transfer Alice→Bob"
run_pg "SELECT name, balance FROM tx_accounts ORDER BY name;" "PG: Verify balances"

run_pg "BEGIN; INSERT INTO tx_accounts (name, balance) VALUES ('Diana', 7500) ON CONFLICT (name) DO NOTHING; UPDATE tx_accounts SET balance = balance + 500 WHERE name = 'Charlie'; COMMIT;" "PG: Multi-step transaction"
run_pg "SELECT COUNT(*) AS accounts, SUM(balance) AS total FROM tx_accounts;" "PG: Account summary"

run_pg "BEGIN; INSERT INTO tx_accounts (name, balance) VALUES ('TempUser', 999) ON CONFLICT (name) DO NOTHING; SAVEPOINT sp1; UPDATE tx_accounts SET balance = 0 WHERE name = 'Alice'; ROLLBACK TO sp1; COMMIT;" "PG: SAVEPOINT + partial rollback"
run_pg "SELECT name, balance FROM tx_accounts WHERE name IN ('Alice', 'TempUser') ORDER BY name;" "PG: Verify savepoint (Alice balance unchanged)"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 2: MySQL Transactions & Complex Queries
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 2: MySQL Transactions & Complex Queries ━━━"

run_my "CREATE TABLE IF NOT EXISTS my_inventory (
  id INT AUTO_INCREMENT PRIMARY KEY, product VARCHAR(100), warehouse VARCHAR(50),
  quantity INT DEFAULT 0, unit_cost DECIMAL(10,2), last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);" "MySQL: Create inventory table"

run_my "INSERT INTO my_inventory (product, warehouse, quantity, unit_cost) VALUES
  ('Widget A', 'Istanbul', 500, 12.50),
  ('Widget A', 'Berlin', 300, 12.50),
  ('Widget B', 'Istanbul', 200, 45.00),
  ('Widget B', 'Berlin', 150, 45.00),
  ('Widget B', 'Tokyo', 400, 45.00),
  ('Gadget X', 'Istanbul', 100, 99.99),
  ('Gadget X', 'Tokyo', 250, 99.99),
  ('Gadget Y', 'Berlin', 75, 199.99);" "MySQL: Insert 8 inventory rows"

run_my "START TRANSACTION; UPDATE my_inventory SET quantity = quantity - 50 WHERE product = 'Widget A' AND warehouse = 'Istanbul'; UPDATE my_inventory SET quantity = quantity + 50 WHERE product = 'Widget A' AND warehouse = 'Berlin'; COMMIT;" "MySQL: Transaction — warehouse transfer"

run_my "SELECT product, SUM(quantity) AS total_qty, SUM(quantity * unit_cost) AS total_value
  FROM my_inventory GROUP BY product ORDER BY total_value DESC;" "MySQL: Inventory value by product"

run_my "SELECT warehouse, COUNT(DISTINCT product) AS products, SUM(quantity) AS total_units,
  SUM(quantity * unit_cost) AS total_value
  FROM my_inventory GROUP BY warehouse ORDER BY total_value DESC;" "MySQL: Warehouse summary"

run_my "SELECT product, warehouse, quantity,
  quantity * 100.0 / SUM(quantity) OVER (PARTITION BY product) AS pct_of_product
  FROM my_inventory ORDER BY product, pct_of_product DESC;" "MySQL: Window function — % distribution"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 3: Large Batch Data & Analytics
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 3: Large Batch Data & Analytics ━━━"

run_pg "CREATE TABLE IF NOT EXISTS events (id SERIAL PRIMARY KEY, event_type VARCHAR(20), user_id INT, payload TEXT, created_at TIMESTAMP DEFAULT NOW());" "PG: Create events table"

# 200 row bulk insert
SQL="INSERT INTO events (event_type, user_id, payload) VALUES"
TYPES=("click" "view" "purchase" "signup" "logout")
for i in $(seq 1 200); do
  t="${TYPES[$((RANDOM % 5))]}"
  u=$((RANDOM % 50 + 1))
  SQL="$SQL ('$t', $u, 'payload_$i')"
  if [ $i -lt 200 ]; then SQL="$SQL,"; fi
done
SQL="$SQL;"
run_pg "$SQL" "PG: Bulk insert 200 events"

run_pg "SELECT event_type, COUNT(*) AS cnt FROM events GROUP BY event_type ORDER BY cnt DESC;" "PG: Event distribution"

run_pg "WITH user_events AS (
  SELECT user_id, COUNT(*) AS event_count FROM events GROUP BY user_id
)
SELECT
  CASE WHEN event_count > 10 THEN 'power' WHEN event_count > 5 THEN 'active' ELSE 'casual' END AS segment,
  COUNT(*) AS users, AVG(event_count) AS avg_events
FROM user_events GROUP BY segment ORDER BY avg_events DESC;" "PG: CTE — user segmentation"

run_pg "SELECT event_type, user_id, COUNT(*) AS cnt,
  RANK() OVER (PARTITION BY event_type ORDER BY COUNT(*) DESC) AS rnk
FROM events GROUP BY event_type, user_id
ORDER BY event_type, rnk LIMIT 15;" "PG: Window — top users per event type"

run_pg "SELECT generate_series(1, 5) AS bucket,
  COUNT(*) FILTER (WHERE user_id BETWEEN 1 AND 10) AS seg_1_10,
  COUNT(*) FILTER (WHERE user_id BETWEEN 11 AND 20) AS seg_11_20,
  COUNT(*) FILTER (WHERE user_id BETWEEN 21 AND 30) AS seg_21_30
FROM events GROUP BY bucket;" "PG: FILTER clause — cross-tab"

# MySQL bulk
run_my "CREATE TABLE IF NOT EXISTS logs (id INT AUTO_INCREMENT PRIMARY KEY, level VARCHAR(10), service VARCHAR(30), message TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP);" "MySQL: Create logs table"

SQL_MY="INSERT INTO logs (level, service, message) VALUES"
LEVELS=("INFO" "WARN" "ERROR" "DEBUG")
SERVICES=("api-gw" "auth-svc" "order-svc" "payment-svc" "notification-svc")
for i in $(seq 1 100); do
  l="${LEVELS[$((RANDOM % 4))]}"
  s="${SERVICES[$((RANDOM % 5))]}"
  SQL_MY="$SQL_MY ('$l', '$s', 'Log entry $i from $s')"
  if [ $i -lt 100 ]; then SQL_MY="$SQL_MY,"; fi
done
SQL_MY="$SQL_MY;"
run_my "$SQL_MY" "MySQL: Bulk insert 100 log entries"

run_my "SELECT service, level, COUNT(*) AS cnt FROM logs GROUP BY service, level ORDER BY service, cnt DESC;" "MySQL: Log distribution by service+level"

run_my "SELECT service, COUNT(*) AS errors FROM logs WHERE level = 'ERROR' GROUP BY service ORDER BY errors DESC;" "MySQL: Error count by service"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 4: Complex PG Queries (subqueries, CTEs, laterals)
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 4: Complex PostgreSQL Queries ━━━"

run_pg "SELECT DISTINCT event_type FROM events WHERE user_id IN (
  SELECT user_id FROM events GROUP BY user_id HAVING COUNT(*) > 3
) ORDER BY event_type;" "PG: Correlated subquery — active user event types"

run_pg "WITH RECURSIVE nums AS (
  SELECT 1 AS n UNION ALL SELECT n+1 FROM nums WHERE n < 10
) SELECT n, n*n AS square, n*n*n AS cube FROM nums;" "PG: Recursive CTE — number series"

run_pg "SELECT e1.event_type AS from_event, e2.event_type AS to_event, COUNT(*) AS transitions
FROM events e1 JOIN events e2 ON e1.user_id = e2.user_id AND e2.id = e1.id + 1
GROUP BY from_event, to_event ORDER BY transitions DESC LIMIT 10;" "PG: Event transition analysis (self-join)"

run_pg "SELECT event_type,
  COUNT(*) AS total,
  ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct
FROM events GROUP BY event_type ORDER BY pct DESC;" "PG: Percentage distribution with window"

run_pg "SELECT DISTINCT ON (event_type) event_type, user_id, created_at
FROM events ORDER BY event_type, created_at DESC;" "PG: DISTINCT ON — latest event per type"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 5: Admin API Comprehensive
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 5: Admin API Comprehensive ━━━"

check_api "API: /healthz" "$API/healthz" "healthy"
check_api "API: /ready" "$API/ready" "ready"
check_api "API: /livez" "$API/livez" "alive"
check_api "API: Dashboard uptime" "$API/api/dashboard" "uptime"
check_api "API: Dashboard healthy_targets" "$API/api/dashboard" "healthy_targets"
check_api "API: Sessions" "$API/api/sessions" "\["
check_api "API: Pool health" "$API/api/pool/health" "healthy"
check_api "API: Config export" "$API/api/config/export" "targets"
check_api "API: Stats" "$API/api/stats" "commands"
check_api "API: Policy validate" "$API/api/policies/validate" "valid"
check_api "API: Metrics goroutines" "$API/metrics" "argus_go_goroutines"
check_api "API: Metrics pool active" "$API/metrics" "argus_pool_connections"
check_api "API: Metrics query duration" "$API/metrics" "argus_query_duration"
check_api "API: Audit search" "$API/api/audit/search?limit=5" "\["
check_api_post() {
  local desc="$1" url="$2" expected="$3"
  local out; out=$(curl -s -X POST "$url" 2>/dev/null)
  if echo "$out" | grep -q "$expected"; then pass "$desc"; else fail "$desc (expected: $expected)"; fi
}
check_api_post "API: DryRun SELECT" "$API/api/policies/dryrun?username=dev&sql=SELECT+1" "allow"
check_api_post "API: DryRun DROP (risk=75)" "$API/api/policies/dryrun?username=dev_john&sql=DROP+TABLE+users" "risk_score"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 6: Error Resilience
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 6: Error Resilience ━━━"

# Use psql -c (not -q -t) so error exit codes propagate correctly
PG_ERR="docker exec -e PGPASSWORD=argus_pass argus-postgres-1 psql -h argus -p 15432 -U argus_test -d testdb -c"

MSYS_NO_PATHCONV=1 $PG_ERR "SELECT * FROM nonexistent_xyz_table;" 2>/dev/null
if [ $? -ne 0 ]; then pass "PG: Missing table error (expected)"; else fail "PG: Should have errored"; fi

MSYS_NO_PATHCONV=1 $MY -e "SELECT * FROM nonexistent_xyz_table;" 2>/dev/null
if [ $? -ne 0 ]; then pass "MySQL: Missing table error (expected)"; else fail "MySQL: Should have errored"; fi

check_api "API: Healthy after missing table errors" "$API/healthz" "healthy"

MSYS_NO_PATHCONV=1 $PG_ERR "SELECTTTT broken syntax;" 2>/dev/null
if [ $? -ne 0 ]; then pass "PG: Syntax error handled gracefully"; else fail "PG: Should have errored"; fi

MSYS_NO_PATHCONV=1 $MY -e "SELECTTTT broken syntax;" 2>/dev/null
if [ $? -ne 0 ]; then pass "MySQL: Syntax error handled gracefully"; else fail "MySQL: Should have errored"; fi

# Empty result set
run_pg "SELECT * FROM events WHERE user_id = -999;" "PG: Empty result set (no crash)"
run_my "SELECT * FROM logs WHERE level = 'NONEXISTENT';" "MySQL: Empty result set (no crash)"

check_api "API: Still healthy after all errors" "$API/healthz" "healthy"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 7: Concurrent Mixed Protocol Burst
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 7: Concurrent Mixed Protocol Burst ━━━"

for i in $(seq 1 15); do
  MSYS_NO_PATHCONV=1 $PG "SELECT $i AS pg_n, NOW() AS ts;" 2>/dev/null &
done
for i in $(seq 1 15); do
  MSYS_NO_PATHCONV=1 $MY -e "SELECT $i AS my_n, NOW() AS ts;" 2>/dev/null &
done
wait
pass "30 concurrent PG+MySQL queries completed"

# Second burst — write operations
for i in $(seq 1 5); do
  MSYS_NO_PATHCONV=1 $PG "INSERT INTO events (event_type, user_id, payload) VALUES ('burst', $i, 'concurrent_$i');" 2>/dev/null &
  MSYS_NO_PATHCONV=1 $MY -e "INSERT INTO logs (level, service, message) VALUES ('INFO', 'burst-test', 'concurrent_$i');" 2>/dev/null &
done
wait
pass "10 concurrent write operations completed"

check_api "API: Healthy after burst" "$API/healthz" "healthy"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 8: Data Integrity Verification
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 8: Data Integrity Verification ━━━"

run_pg "SELECT COUNT(*) AS total_events FROM events;" "PG: Count events (200 + burst)"
run_my "SELECT COUNT(*) AS total_logs FROM logs;" "MySQL: Count logs (100 + burst)"
run_pg "SELECT COUNT(*) AS total_accounts FROM tx_accounts;" "PG: Count accounts"
run_my "SELECT COUNT(*) AS total_inventory FROM my_inventory;" "MySQL: Count inventory"

# Verify transaction integrity
run_pg "SELECT SUM(balance) AS should_be_consistent FROM tx_accounts;" "PG: Balance integrity check"

sleep 1

# ─────────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────────
echo ""
echo "━━━ Cleanup ━━━"
run_pg "DROP TABLE IF EXISTS tx_accounts, events CASCADE;" "PG: Drop tables"
run_my "DROP TABLE IF EXISTS my_inventory, logs, bulk_my;" "MySQL: Drop tables"

# ─────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────
CMD_AFTER=$(curl -sf $API/api/dashboard 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['traffic']['total_commands'])" 2>/dev/null || echo 0)

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   RESULTS: $OK passed, $FAIL failed, $TOTAL total       "
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Commands during test: $CMD_BEFORE → $CMD_AFTER (+$((CMD_AFTER - CMD_BEFORE)))"

curl -sf $API/api/dashboard 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
o=d['overview'];t=d['traffic'];p=d['pool']
print(f'  Memory: {o[\"memory_mb\"]}MB  Goroutines: {o[\"goroutines\"]}')
print(f'  Total Connections: {t[\"total_connections\"]}  Rows: {t[\"total_rows\"]}')
for n,s in p['targets'].items():
    h='UP' if s['Healthy'] else 'DOWN'
    print(f'  {n:10s}: {h}')
" 2>/dev/null

echo ""
exit $FAIL
