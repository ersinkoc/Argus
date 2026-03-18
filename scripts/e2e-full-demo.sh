#!/bin/bash
# =============================================================================
# Argus Full Demo — Masking, Blocking, Rate Limit, Multi-protocol
# Dashboard: http://127.0.0.1:30200/ui
# Ctrl+C to stop
# =============================================================================

# When Argus runs inside Docker use: -h argus -p 15432
# When Argus runs natively on host use: -h host.docker.internal -p 30100
ARGUS_PG_HOST="${ARGUS_PG_HOST:-host.docker.internal}"
ARGUS_PG_PORT="${ARGUS_PG_PORT:-30100}"
ARGUS_MY_HOST="${ARGUS_MY_HOST:-host.docker.internal}"
ARGUS_MY_PORT="${ARGUS_MY_PORT:-30101}"
PG_CMD="docker exec -e PGPASSWORD=argus_pass argus-postgres-1 psql -h $ARGUS_PG_HOST -p $ARGUS_PG_PORT"
MY_CMD="docker exec argus-mysql-1 mariadb -h $ARGUS_MY_HOST -P $ARGUS_MY_PORT --skip-ssl"

pg()       { MSYS_NO_PATHCONV=1 $PG_CMD -U "$1" -d testdb -q -t -c "$2" 2>&1; }
my()       { MSYS_NO_PATHCONV=1 $MY_CMD -u "$1" -p"$2" -s testdb -e "$3" 2>&1; }
pg_admin() { pg "admin" "$1"; }
pg_app()   { pg "webapp" "$1"; }
pg_support(){ pg "support_jane" "$1"; }
pg_analyst(){ pg "analyst" "$1"; }
pg_user()  { pg "bob" "$1"; }

ROUND=0; BLOCK=0; MASK=0; ALLOW=0; TOTAL=0

trap cleanup EXIT INT TERM
cleanup() {
  echo ""
  echo "[cleanup] Dropping test tables..."
  pg_admin "DROP TABLE IF EXISTS demo_audit, demo_orders, demo_employees, demo_accounts CASCADE;" 2>/dev/null
  my "argus_test" "argus_pass" "DROP TABLE IF EXISTS demo_inventory, demo_clients;" 2>/dev/null
  echo ""
  echo "╔═══════════════════════════════════════════════════════╗"
  printf "║  RESULTS: %d rounds, %d allow, %d blocked, %d masked   \n" $ROUND $ALLOW $BLOCK $MASK
  echo "╚═══════════════════════════════════════════════════════╝"
  curl -s http://127.0.0.1:30200/api/dashboard 2>/dev/null | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  o=d['overview'];t=d['traffic']
  print(f'  Connections:  {t[\"total_connections\"]}')
  print(f'  Commands:     {t[\"total_commands\"]}')
  print(f'  Rows:         {t[\"total_rows\"]}')
  print(f'  Blocked:      {t[\"blocked_commands\"]}')
  print(f'  Masked:       {t[\"masked_results\"]}')
  print(f'  Memory:       {o[\"memory_mb\"]} MB')
except: pass
" 2>/dev/null
  echo ""
  exit 0
}

c_green() { echo -e "\033[32m$1\033[0m"; }
c_red()   { echo -e "\033[31m$1\033[0m"; }
c_yellow(){ echo -e "\033[33m$1\033[0m"; }
c_cyan()  { echo -e "\033[36m$1\033[0m"; }
c_gray()  { echo -e "\033[90m$1\033[0m"; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ARGUS FULL DEMO — Masking, Blocking, Rate Limit        ║"
echo "║  Dashboard: http://127.0.0.1:30200/ui                   ║"
echo "║  Ctrl+C to stop                                         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── SETUP ────────────────────────────────────────
echo "$(c_cyan '[setup]') Creating test schema with sensitive data..."

pg_admin "
CREATE TABLE IF NOT EXISTS demo_employees (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100),
  phone VARCHAR(20),
  ssn VARCHAR(11),
  salary DECIMAL(10,2),
  department VARCHAR(50),
  password_hash VARCHAR(128),
  hire_date DATE DEFAULT CURRENT_DATE
);
CREATE TABLE IF NOT EXISTS demo_orders (
  id SERIAL PRIMARY KEY,
  employee_id INT REFERENCES demo_employees(id),
  product VARCHAR(100),
  quantity INT,
  total DECIMAL(10,2),
  status VARCHAR(20) DEFAULT 'new',
  credit_card VARCHAR(19),
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS demo_accounts (
  id SERIAL PRIMARY KEY,
  owner VARCHAR(100),
  iban VARCHAR(34),
  balance DECIMAL(15,2),
  currency VARCHAR(3) DEFAULT 'USD'
);
CREATE TABLE IF NOT EXISTS demo_audit (
  id SERIAL PRIMARY KEY,
  actor VARCHAR(50),
  action VARCHAR(50),
  detail TEXT,
  ts TIMESTAMP DEFAULT NOW()
);
" 2>/dev/null
echo "  $(c_green '✓') PG tables created"

my "argus_test" "argus_pass" "
CREATE TABLE IF NOT EXISTS demo_inventory (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sku VARCHAR(20) UNIQUE,
  name VARCHAR(100),
  category VARCHAR(50),
  price DECIMAL(10,2),
  stock INT DEFAULT 0,
  supplier_email VARCHAR(100)
);
CREATE TABLE IF NOT EXISTS demo_clients (
  id INT AUTO_INCREMENT PRIMARY KEY,
  company VARCHAR(100),
  contact_email VARCHAR(100),
  phone VARCHAR(20),
  credit_limit DECIMAL(12,2) DEFAULT 10000,
  tax_id VARCHAR(20),
  active BOOLEAN DEFAULT TRUE
);
" 2>/dev/null
echo "  $(c_green '✓') MySQL tables created"

# ── SEED DATA ────────────────────────────────────
echo "$(c_cyan '[setup]') Inserting sensitive demo data..."

pg_admin "
INSERT INTO demo_employees (name, email, phone, ssn, salary, department, password_hash) VALUES
  ('Alice Johnson', 'alice@company.com', '+1-555-0101', '123-45-6789', 95000, 'Engineering', 'pbkdf2:sha256:260000\$salt\$hash_alice'),
  ('Bob Smith', 'bob@company.com', '+1-555-0202', '234-56-7890', 75000, 'Sales', 'pbkdf2:sha256:260000\$salt\$hash_bob'),
  ('Charlie Brown', 'charlie@company.com', '+1-555-0303', '345-67-8901', 120000, 'Management', 'pbkdf2:sha256:260000\$salt\$hash_charlie'),
  ('Diana Ross', 'diana@company.com', '+1-555-0404', '456-78-9012', 85000, 'Engineering', 'pbkdf2:sha256:260000\$salt\$hash_diana'),
  ('Eve Wilson', 'eve@company.com', '+1-555-0505', '567-89-0123', 110000, 'Finance', 'pbkdf2:sha256:260000\$salt\$hash_eve'),
  ('Frank Miller', 'frank@company.com', '+1-555-0606', '678-90-1234', 68000, 'Support', 'pbkdf2:sha256:260000\$salt\$hash_frank'),
  ('Grace Lee', 'grace@company.com', '+1-555-0707', '789-01-2345', 92000, 'Engineering', 'pbkdf2:sha256:260000\$salt\$hash_grace'),
  ('Henry Chen', 'henry@company.com', '+1-555-0808', '890-12-3456', 145000, 'Management', 'pbkdf2:sha256:260000\$salt\$hash_henry')
ON CONFLICT DO NOTHING;
INSERT INTO demo_orders (employee_id, product, quantity, total, status, credit_card) VALUES
  (1, 'Server Rack', 2, 15000.00, 'approved', '4111-1111-1111-1111'),
  (2, 'Office Supplies', 50, 750.00, 'delivered', '5500-0000-0000-0004'),
  (3, 'Software License', 10, 5000.00, 'pending', '3782-822463-10005'),
  (1, 'Laptop', 5, 12500.00, 'approved', '4111-1111-1111-1111'),
  (4, 'Monitor', 10, 4500.00, 'shipped', '6011-0000-0000-0004'),
  (5, 'Cloud Credits', 1, 25000.00, 'approved', '4111-2222-3333-4444');
INSERT INTO demo_accounts (owner, iban, balance, currency) VALUES
  ('Company Main', 'TR33 0006 1005 1978 6457 8413 26', 1500000.00, 'TRY'),
  ('USD Reserve', 'GB29 NWBK 6016 1331 9268 19', 500000.00, 'USD'),
  ('Petty Cash', 'DE89 3704 0044 0532 0130 00', 10000.00, 'EUR');
" 2>/dev/null
echo "  $(c_green '✓') PG demo data inserted (employees, orders, accounts)"

my "argus_test" "argus_pass" "
INSERT IGNORE INTO demo_inventory (sku, name, category, price, stock, supplier_email) VALUES
  ('SRV-R740', 'Dell R740 Server', 'Servers', 8999.99, 15, 'sales@dell-partner.com'),
  ('LAP-MBP16', 'MacBook Pro 16', 'Laptops', 2499.99, 50, 'enterprise@apple-reseller.com'),
  ('MON-4K32', 'LG 32\" 4K Monitor', 'Displays', 599.99, 100, 'bulk@lg-wholesale.com'),
  ('NET-SW48', 'Cisco 48-port Switch', 'Network', 3200.00, 8, 'orders@cisco-partner.com'),
  ('SEC-FW01', 'Palo Alto Firewall', 'Security', 12500.00, 3, 'gov@paloalto.com'),
  ('STO-NAS8', 'Synology 8-Bay NAS', 'Storage', 1899.99, 20, 'reseller@synology.com');
INSERT IGNORE INTO demo_clients (company, contact_email, phone, credit_limit, tax_id) VALUES
  ('ACME Corp', 'finance@acme.com', '+1-800-ACME', 100000, '12-3456789'),
  ('Globex Inc', 'ap@globex.net', '+44-20-7946-0958', 75000, 'GB123456789'),
  ('Initech LLC', 'billing@initech.io', '+1-512-555-0199', 50000, '98-7654321'),
  ('Umbrella Co', 'procurement@umbrella.org', '+81-3-1234-5678', 200000, 'JP1234567890');
" 2>/dev/null
echo "  $(c_green '✓') MySQL demo data inserted (inventory, clients)"
echo ""

# ── CONTINUOUS LOOP ──────────────────────────────
while true; do
  ROUND=$((ROUND+1))
  ts=$(date +%H:%M:%S)
  action=$((RANDOM % 30))

  case $action in
    # ── NORMAL QUERIES (admin) ──
    0)
      echo "[$ts] $(c_green 'ADMIN') SELECT employees — full access"
      result=$(pg_admin "SELECT name, email, phone, ssn, salary FROM demo_employees LIMIT 3;")
      echo "$result" | head -3
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    1)
      echo "[$ts] $(c_green 'ADMIN') INSERT new order"
      pg_admin "INSERT INTO demo_orders (employee_id, product, quantity, total, credit_card) VALUES ($((RANDOM%8+1)), 'Item-$ROUND', $((RANDOM%10+1)), $((RANDOM%5000+100)).00, '4111-0000-0000-$((RANDOM%9000+1000))');" >/dev/null
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    2)
      echo "[$ts] $(c_green 'ADMIN') Complex JOIN — order summary"
      pg_admin "SELECT e.name, e.department, COUNT(o.id) AS orders, SUM(o.total) AS spent FROM demo_employees e LEFT JOIN demo_orders o ON e.id=o.employee_id GROUP BY e.id, e.name, e.department ORDER BY spent DESC NULLS LAST LIMIT 5;" | head -5
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;

    # ── MASKED QUERIES (support user) ──
    3|4)
      echo "[$ts] $(c_yellow 'SUPPORT') SELECT employees — email/phone/ssn MASKED"
      result=$(pg_support "SELECT name, email, phone, ssn, salary, password_hash FROM demo_employees ORDER BY name LIMIT 4;")
      echo "$result" | head -4
      MASK=$((MASK+1)); TOTAL=$((TOTAL+1))
      ;;
    5)
      echo "[$ts] $(c_yellow 'SUPPORT') SELECT orders — credit_card MASKED"
      result=$(pg_support "SELECT e.name, o.product, o.total, o.credit_card FROM demo_orders o JOIN demo_employees e ON o.employee_id=e.id LIMIT 3;")
      echo "$result" | head -3
      MASK=$((MASK+1)); TOTAL=$((TOTAL+1))
      ;;

    # ── MASKED QUERIES (analyst) ──
    6)
      echo "[$ts] $(c_yellow 'ANALYST') SELECT accounts — sees email but SSN/password MASKED"
      result=$(pg_analyst "SELECT name, email, ssn, salary FROM demo_employees WHERE department='Engineering';")
      echo "$result" | head -3
      MASK=$((MASK+1)); TOTAL=$((TOTAL+1))
      ;;

    # ── BLOCKED QUERIES ──
    7|8)
      echo "[$ts] $(c_red 'BOB') DROP TABLE attempt — should be BLOCKED"
      result=$(pg_user "DROP TABLE demo_employees;" 2>&1)
      echo "  $(c_red '→') $result" | head -2
      BLOCK=$((BLOCK+1)); TOTAL=$((TOTAL+1))
      ;;
    9)
      echo "[$ts] $(c_red 'SUPPORT') DROP TABLE attempt — should be BLOCKED"
      result=$(pg_support "DROP TABLE demo_orders;" 2>&1)
      echo "  $(c_red '→') $result" | head -2
      BLOCK=$((BLOCK+1)); TOTAL=$((TOTAL+1))
      ;;
    10)
      echo "[$ts] $(c_red 'ANALYST') DELETE without WHERE — should be BLOCKED"
      result=$(pg_analyst "DELETE FROM demo_employees;" 2>&1)
      echo "  $(c_red '→') $result" | head -2
      BLOCK=$((BLOCK+1)); TOTAL=$((TOTAL+1))
      ;;

    # ── MYSQL QUERIES ──
    11|12)
      echo "[$ts] $(c_green 'MYSQL') SELECT inventory with supplier emails"
      my "argus_test" "argus_pass" "SELECT name, price, stock, supplier_email FROM demo_inventory ORDER BY price DESC LIMIT 4;" | head -4
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    13)
      echo "[$ts] $(c_green 'MYSQL') Client report"
      my "argus_test" "argus_pass" "SELECT company, contact_email, credit_limit, tax_id FROM demo_clients WHERE active=1;" | head -4
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    14)
      echo "[$ts] $(c_green 'MYSQL') Stock update"
      my "argus_test" "argus_pass" "UPDATE demo_inventory SET stock=stock-$((RANDOM%3+1)) WHERE sku='LAP-MBP16' AND stock>0;"
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    15)
      echo "[$ts] $(c_green 'MYSQL') Inventory analytics"
      my "argus_test" "argus_pass" "SELECT category, COUNT(*) AS cnt, SUM(stock) AS total_stock, SUM(price*stock) AS value FROM demo_inventory GROUP BY category ORDER BY value DESC;"
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;

    # ── APP USER (rate limited) ──
    16|17)
      echo "[$ts] $(c_cyan 'APP') Rapid queries (rate limited to 50/s)"
      for i in $(seq 1 3); do
        pg_app "SELECT id, name, department FROM demo_employees WHERE id=$((RANDOM%8+1));" >/dev/null
      done
      echo "  3 rapid selects sent"
      ALLOW=$((ALLOW+3)); TOTAL=$((TOTAL+3))
      ;;

    # ── COMPLEX ANALYTICS ──
    18)
      echo "[$ts] $(c_green 'ADMIN') Window function — salary ranking"
      pg_admin "SELECT name, department, salary, RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS dept_rank FROM demo_employees;" | head -5
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    19)
      echo "[$ts] $(c_green 'ADMIN') Subquery — above avg salary"
      pg_admin "SELECT name, salary FROM demo_employees WHERE salary > (SELECT AVG(salary) FROM demo_employees) ORDER BY salary DESC;" | head -4
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    20)
      echo "[$ts] $(c_green 'ADMIN') Multi-statement"
      pg_admin "SELECT COUNT(*) AS employees FROM demo_employees; SELECT COUNT(*) AS orders FROM demo_orders; SELECT SUM(balance) AS total_balance FROM demo_accounts;"
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;

    # ── DATA MODIFICATIONS ──
    21)
      echo "[$ts] $(c_green 'ADMIN') UPDATE order status"
      pg_admin "UPDATE demo_orders SET status='shipped' WHERE status='approved' AND id=(SELECT id FROM demo_orders WHERE status='approved' LIMIT 1);" >/dev/null
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    22)
      echo "[$ts] $(c_green 'ADMIN') Audit log entry"
      pg_admin "INSERT INTO demo_audit (actor, action, detail) VALUES ('system', 'round_$ROUND', 'Automated check at $ts');" >/dev/null
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    23)
      echo "[$ts] $(c_green 'ADMIN') Balance transfer"
      pg_admin "UPDATE demo_accounts SET balance = balance - 100 WHERE owner='Petty Cash'; UPDATE demo_accounts SET balance = balance + 100 WHERE owner='Company Main';" >/dev/null
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;

    # ── EDGE CASES ──
    24)
      echo "[$ts] $(c_green 'ADMIN') LIKE pattern search"
      pg_admin "SELECT name, email FROM demo_employees WHERE email LIKE '%company.com' ORDER BY name;" | head -4
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    25)
      echo "[$ts] $(c_green 'ADMIN') IN clause"
      pg_admin "SELECT name, department, salary FROM demo_employees WHERE department IN ('Engineering','Finance') ORDER BY salary DESC;" | head -4
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    26)
      echo "[$ts] $(c_green 'MYSQL') BETWEEN query"
      my "argus_test" "argus_pass" "SELECT name, price FROM demo_inventory WHERE price BETWEEN 1000 AND 10000 ORDER BY price;" | head -4
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    27)
      echo "[$ts] $(c_green 'ADMIN') Account balances"
      pg_admin "SELECT owner, iban, balance, currency FROM demo_accounts ORDER BY balance DESC;"
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    28)
      echo "[$ts] $(c_green 'ADMIN') Prune old audit logs"
      pg_admin "DELETE FROM demo_audit WHERE ts < NOW() - INTERVAL '5 minutes';" >/dev/null
      ALLOW=$((ALLOW+1)); TOTAL=$((TOTAL+1))
      ;;
    29)
      echo "[$ts] $(c_yellow 'SUPPORT') Account balance — sensitive data"
      result=$(pg_support "SELECT owner, iban, balance FROM demo_accounts;")
      echo "$result" | head -3
      MASK=$((MASK+1)); TOTAL=$((TOTAL+1))
      ;;
  esac

  # Stats every 15 rounds
  if [ $((ROUND % 15)) -eq 0 ]; then
    echo ""
    echo "$(c_gray "── Round $ROUND: $ALLOW allow / $BLOCK blocked / $MASK masked / $TOTAL total ──")"
    curl -s http://127.0.0.1:30200/api/dashboard 2>/dev/null | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  t=d['traffic']
  print(f'   Argus: conn={t[\"total_connections\"]} cmd={t[\"total_commands\"]} rows={t[\"total_rows\"]} blocked={t[\"blocked_commands\"]} masked={t[\"masked_results\"]}')
except: pass
" 2>/dev/null
    echo ""
  fi

  sleep 0.$((RANDOM % 8 + 2))
done
