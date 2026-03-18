#!/bin/bash
# =============================================================================
# Argus Continuous Stress Test — runs until Ctrl+C
# Simulates realistic multi-protocol database traffic
# Watch live: http://127.0.0.1:30200/ui
# =============================================================================

PG="docker exec -e PGPASSWORD=argus_pass argus-postgres-1 psql -h argus -p 15432 -U argus_test -d testdb -q -t"
MY="docker exec argus-mysql-1 mariadb -h argus -P 13306 -u argus_test -pargus_pass --skip-ssl -s testdb"

ROUND=0; OK=0; FAIL=0
USERS=("alice" "bob" "charlie" "diana" "eve" "frank" "grace" "henry")
PRODUCTS=("Laptop" "Phone" "Tablet" "Monitor" "Keyboard" "Mouse" "Headset" "Camera" "Speaker" "Cable")
CITIES=("Istanbul" "London" "Berlin" "Tokyo" "NYC" "Paris" "Dubai" "Sydney" "Toronto" "Seoul")
STATUSES=("pending" "processing" "shipped" "delivered" "cancelled")

trap cleanup EXIT INT TERM
cleanup() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Stopping... cleaning up tables"
  MSYS_NO_PATHCONV=1 $PG "DROP TABLE IF EXISTS stress_orders, stress_users, stress_logs CASCADE;" 2>/dev/null
  MSYS_NO_PATHCONV=1 $MY -e "DROP TABLE IF EXISTS stress_products, stress_customers;" 2>/dev/null
  echo ""
  echo "╔═══════════════════════════════════════╗"
  echo "║  FINAL: $OK ok / $FAIL fail / $ROUND rounds  "
  echo "╚═══════════════════════════════════════╝"
  stats
  exit 0
}

stats() {
  curl -s http://127.0.0.1:30200/api/dashboard 2>/dev/null | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  o=d['overview'];t=d['traffic']
  print(f'  Connections: {t[\"total_connections\"]}  Commands: {t[\"total_commands\"]}  Rows: {t[\"total_rows\"]}')
  print(f'  Blocked: {t[\"blocked_commands\"]}  Masked: {t[\"masked_results\"]}  Memory: {o[\"memory_mb\"]}MB')
except: pass
" 2>/dev/null
}

q_pg() { MSYS_NO_PATHCONV=1 $PG "$1" 2>/dev/null && OK=$((OK+1)) || FAIL=$((FAIL+1)); }
q_my() { MSYS_NO_PATHCONV=1 $MY -e "$1" 2>/dev/null && OK=$((OK+1)) || FAIL=$((FAIL+1)); }

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ARGUS CONTINUOUS STRESS TEST                           ║"
echo "║  Dashboard: http://127.0.0.1:30200/ui                   ║"
echo "║  Press Ctrl+C to stop                                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Setup
echo "[setup] Creating tables..."
MSYS_NO_PATHCONV=1 $PG "CREATE TABLE IF NOT EXISTS stress_users (
  id SERIAL PRIMARY KEY, name VARCHAR(50), email VARCHAR(100), city VARCHAR(50),
  balance DECIMAL(12,2) DEFAULT 1000, login_count INT DEFAULT 0, created_at TIMESTAMP DEFAULT NOW()
);" 2>/dev/null
MSYS_NO_PATHCONV=1 $PG "CREATE TABLE IF NOT EXISTS stress_orders (
  id SERIAL PRIMARY KEY, user_id INT, product VARCHAR(80), qty INT, price DECIMAL(10,2),
  status VARCHAR(20) DEFAULT 'pending', note TEXT, created_at TIMESTAMP DEFAULT NOW()
);" 2>/dev/null
MSYS_NO_PATHCONV=1 $PG "CREATE TABLE IF NOT EXISTS stress_logs (
  id SERIAL PRIMARY KEY, level VARCHAR(10), msg TEXT, ts TIMESTAMP DEFAULT NOW()
);" 2>/dev/null
MSYS_NO_PATHCONV=1 $MY -e "CREATE TABLE IF NOT EXISTS stress_products (
  id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), category VARCHAR(50),
  price DECIMAL(10,2), stock INT DEFAULT 100, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);" 2>/dev/null
MSYS_NO_PATHCONV=1 $MY -e "CREATE TABLE IF NOT EXISTS stress_customers (
  id INT AUTO_INCREMENT PRIMARY KEY, company VARCHAR(100), contact VARCHAR(100),
  city VARCHAR(50), credit DECIMAL(12,2) DEFAULT 10000, active BOOLEAN DEFAULT TRUE
);" 2>/dev/null

# Seed
echo "[setup] Seeding initial data..."
for u in "${USERS[@]}"; do
  MSYS_NO_PATHCONV=1 $PG "INSERT INTO stress_users (name, email, city) VALUES ('$u', '$u@test.com', '${CITIES[$((RANDOM % 10))]}')" 2>/dev/null
done
for p in "${PRODUCTS[@]}"; do
  MSYS_NO_PATHCONV=1 $MY -e "INSERT IGNORE INTO stress_products (name, category, price, stock) VALUES ('$p Pro', 'Electronics', $((RANDOM % 2000 + 99)).99, $((RANDOM % 500 + 10)))" 2>/dev/null
done
for c in "${CITIES[@]}"; do
  MSYS_NO_PATHCONV=1 $MY -e "INSERT IGNORE INTO stress_customers (company, contact, city, credit) VALUES ('${c} Corp', 'manager@${c,,}.com', '$c', $((RANDOM % 50000 + 5000)))" 2>/dev/null
done

echo "[ready] Starting continuous load..."
echo ""

while true; do
  ROUND=$((ROUND+1))
  ts=$(date +%H:%M:%S)
  action=$((RANDOM % 20))

  case $action in
    0|1|2)
      # PG: Insert order
      u=$((RANDOM % 8 + 1))
      p="${PRODUCTS[$((RANDOM % 10))]}"
      qty=$((RANDOM % 10 + 1))
      price=$((RANDOM % 500 + 20))
      echo "[$ts] R$ROUND PG INSERT order: user=$u product=$p qty=$qty"
      q_pg "INSERT INTO stress_orders (user_id, product, qty, price) VALUES ($u, '$p', $qty, $price.99);"
      ;;
    3|4)
      # PG: Select with JOIN
      echo "[$ts] R$ROUND PG SELECT join: user orders summary"
      q_pg "SELECT u.name, COUNT(o.id) AS orders, COALESCE(SUM(o.price*o.qty),0) AS total
        FROM stress_users u LEFT JOIN stress_orders o ON u.id=o.user_id
        GROUP BY u.name ORDER BY total DESC LIMIT 5;"
      ;;
    5)
      # PG: Update order status
      s="${STATUSES[$((RANDOM % 5))]}"
      echo "[$ts] R$ROUND PG UPDATE order status → $s"
      q_pg "UPDATE stress_orders SET status='$s' WHERE id=(SELECT id FROM stress_orders ORDER BY RANDOM() LIMIT 1);"
      ;;
    6)
      # PG: Complex analytics
      echo "[$ts] R$ROUND PG ANALYTICS: revenue by product"
      q_pg "SELECT product, COUNT(*) AS cnt, SUM(price*qty) AS rev, AVG(price) AS avg_price
        FROM stress_orders GROUP BY product HAVING COUNT(*)>0 ORDER BY rev DESC LIMIT 5;"
      ;;
    7)
      # PG: User login simulation
      u="${USERS[$((RANDOM % 8))]}"
      echo "[$ts] R$ROUND PG LOGIN: $u"
      q_pg "UPDATE stress_users SET login_count=login_count+1 WHERE name='$u';"
      q_pg "SELECT id, name, city, balance, login_count FROM stress_users WHERE name='$u';"
      ;;
    8)
      # PG: Balance update
      amount=$((RANDOM % 200 - 100))
      echo "[$ts] R$ROUND PG BALANCE: adjust by $amount"
      q_pg "UPDATE stress_users SET balance=balance+$amount WHERE id=$((RANDOM % 8 + 1));"
      ;;
    9)
      # PG: Audit log
      echo "[$ts] R$ROUND PG LOG: write audit entry"
      q_pg "INSERT INTO stress_logs (level, msg) VALUES ('INFO', 'Round $ROUND action at $ts');"
      ;;
    10|11)
      # MySQL: Product search
      echo "[$ts] R$ROUND MY SELECT: product search"
      q_my "SELECT name, price, stock FROM stress_products WHERE stock > 0 ORDER BY price DESC LIMIT 5;"
      ;;
    12)
      # MySQL: Update stock
      echo "[$ts] R$ROUND MY UPDATE: stock adjustment"
      q_my "UPDATE stress_products SET stock=stock-$((RANDOM%5+1)) WHERE id=$((RANDOM%10+1)) AND stock>0;"
      ;;
    13)
      # MySQL: Customer report
      echo "[$ts] R$ROUND MY SELECT: customer report"
      q_my "SELECT company, city, credit, active FROM stress_customers WHERE active=1 ORDER BY credit DESC;"
      ;;
    14)
      # MySQL: Aggregate
      echo "[$ts] R$ROUND MY ANALYTICS: inventory value"
      q_my "SELECT category, COUNT(*) AS cnt, SUM(stock) AS total_stock, SUM(price*stock) AS value
        FROM stress_products GROUP BY category;"
      ;;
    15)
      # PG: Multi-statement
      echo "[$ts] R$ROUND PG MULTI: 3 statements"
      q_pg "SELECT COUNT(*) FROM stress_users; SELECT COUNT(*) FROM stress_orders; SELECT COUNT(*) FROM stress_logs;"
      ;;
    16)
      # PG: Subquery
      echo "[$ts] R$ROUND PG SUBQUERY: top spenders"
      q_pg "SELECT name, balance FROM stress_users WHERE id IN (
        SELECT user_id FROM stress_orders GROUP BY user_id HAVING SUM(price*qty) > 500
      );"
      ;;
    17)
      # MySQL: Credit update
      echo "[$ts] R$ROUND MY UPDATE: credit adjustment"
      q_my "UPDATE stress_customers SET credit=credit+$((RANDOM%1000)) WHERE id=$((RANDOM%10+1));"
      ;;
    18)
      # PG: Delete old logs
      echo "[$ts] R$ROUND PG DELETE: prune old logs"
      q_pg "DELETE FROM stress_logs WHERE id IN (SELECT id FROM stress_logs ORDER BY ts LIMIT 5);"
      ;;
    19)
      # PG: Window function
      echo "[$ts] R$ROUND PG WINDOW: running total"
      q_pg "SELECT name, balance, SUM(balance) OVER (ORDER BY balance DESC) AS running_total
        FROM stress_users LIMIT 5;"
      ;;
  esac

  # Stats every 10 rounds
  if [ $((ROUND % 10)) -eq 0 ]; then
    echo "    ── R$ROUND: $OK ok / $FAIL fail ──"
    stats
  fi

  # Random delay 200ms-1s
  sleep 0.$((RANDOM % 8 + 2))
done
