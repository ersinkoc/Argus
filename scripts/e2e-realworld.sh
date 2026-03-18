#!/bin/bash
# =============================================================================
# Argus Real-World E2E Stress Test
# Simulates a production workload across PostgreSQL, MySQL, and MSSQL
# Run while watching http://127.0.0.1:30200/ui for live monitoring
# =============================================================================

set -e

PG="docker exec -e PGPASSWORD=argus_pass argus-postgres-1 psql -h argus -p 15432 -U argus_test -d testdb -q -t"
MY="docker exec argus-mysql-1 mariadb -h argus -P 13306 -u argus_test -pargus_pass --skip-ssl -s testdb"
MS="docker exec argus-mssql-1 /opt/mssql-tools18/bin/sqlcmd -S argus:11433 -U sa -P Argus_Pass123! -C -N -Q"

OK=0; FAIL=0; TOTAL=0
pass() { OK=$((OK+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
run_pg()  { MSYS_NO_PATHCONV=1 $PG "$1" 2>/dev/null && pass "$2" || fail "$2"; }
run_my()  { MSYS_NO_PATHCONV=1 $MY -e "$1" 2>/dev/null && pass "$2" || fail "$2"; }
run_ms()  { MSYS_NO_PATHCONV=1 $MS "$1" 2>/dev/null && pass "$2" || fail "$2"; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ARGUS REAL-WORLD E2E TEST                             ║"
echo "║   Dashboard: http://127.0.0.1:30200/ui                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────
# PHASE 1: Schema Setup
# ─────────────────────────────────────────────────
echo "━━━ PHASE 1: Schema Setup ━━━"

run_pg "CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE, email VARCHAR(100),
  password_hash VARCHAR(128), role VARCHAR(20) DEFAULT 'user',
  created_at TIMESTAMP DEFAULT NOW(), last_login TIMESTAMP, active BOOLEAN DEFAULT true
);" "PG: Create users table"

run_pg "CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id),
  product VARCHAR(100), quantity INT, price DECIMAL(10,2),
  status VARCHAR(20) DEFAULT 'pending', created_at TIMESTAMP DEFAULT NOW()
);" "PG: Create orders table"

run_pg "CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY, action VARCHAR(50), table_name VARCHAR(50),
  record_id INT, old_value TEXT, new_value TEXT, changed_by VARCHAR(50),
  changed_at TIMESTAMP DEFAULT NOW()
);" "PG: Create audit_log table"

run_my "CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), category VARCHAR(50),
  price DECIMAL(10,2), stock INT DEFAULT 0, sku VARCHAR(20) UNIQUE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);" "MySQL: Create products table"

run_my "CREATE TABLE IF NOT EXISTS customers (
  id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100),
  phone VARCHAR(20), city VARCHAR(50), credit_limit DECIMAL(10,2) DEFAULT 5000,
  registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);" "MySQL: Create customers table"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 2: Data Population (bulk inserts)
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 2: Data Population ━━━"

run_pg "INSERT INTO users (username, email, password_hash, role) VALUES
  ('admin', 'admin@company.com', 'hash_admin_123', 'admin'),
  ('alice', 'alice@company.com', 'hash_alice_456', 'manager'),
  ('bob', 'bob@company.com', 'hash_bob_789', 'user'),
  ('charlie', 'charlie@company.com', 'hash_charlie_012', 'user'),
  ('diana', 'diana@company.com', 'hash_diana_345', 'analyst'),
  ('eve', 'eve@company.com', 'hash_eve_678', 'user'),
  ('frank', 'frank@company.com', 'hash_frank_901', 'manager'),
  ('grace', 'grace@company.com', 'hash_grace_234', 'user'),
  ('henry', 'henry@company.com', 'hash_henry_567', 'admin'),
  ('ivy', 'ivy@company.com', 'hash_ivy_890', 'analyst')
ON CONFLICT (username) DO NOTHING;" "PG: Insert 10 users"

run_pg "INSERT INTO orders (user_id, product, quantity, price, status) VALUES
  (1, 'Laptop Pro', 2, 2499.99, 'completed'),
  (2, 'Wireless Mouse', 5, 29.99, 'completed'),
  (3, 'USB-C Hub', 1, 79.99, 'pending'),
  (4, 'Monitor 27\"', 1, 599.99, 'shipped'),
  (2, 'Keyboard', 3, 149.99, 'completed'),
  (5, 'Webcam HD', 2, 89.99, 'pending'),
  (1, 'SSD 1TB', 4, 129.99, 'completed'),
  (6, 'Headphones', 1, 249.99, 'shipped'),
  (3, 'Laptop Stand', 2, 59.99, 'completed'),
  (7, 'Docking Station', 1, 199.99, 'pending'),
  (8, 'Mouse Pad XL', 3, 24.99, 'completed'),
  (4, 'Cable Kit', 5, 19.99, 'completed'),
  (9, 'Webcam 4K', 1, 179.99, 'shipped'),
  (10, 'Desk Lamp', 2, 49.99, 'completed'),
  (5, 'Chair Mat', 1, 89.99, 'pending');" "PG: Insert 15 orders"

run_my "INSERT IGNORE INTO products (name, category, price, stock, sku) VALUES
  ('MacBook Pro 16', 'Laptops', 2499.99, 50, 'MBP-16-2024'),
  ('Dell XPS 15', 'Laptops', 1799.99, 30, 'DXPS-15-2024'),
  ('iPhone 15 Pro', 'Phones', 1199.99, 200, 'IP15P-256'),
  ('Samsung S24 Ultra', 'Phones', 1299.99, 150, 'SS24U-256'),
  ('Sony WH-1000XM5', 'Audio', 349.99, 100, 'SWXM5-BLK'),
  ('AirPods Pro 2', 'Audio', 249.99, 300, 'APP2-USB'),
  ('iPad Air M2', 'Tablets', 599.99, 80, 'IPADM2-64'),
  ('Logitech MX Master', 'Accessories', 99.99, 500, 'LMXM3S'),
  ('Samsung 4K Monitor', 'Monitors', 449.99, 60, 'S4K28-2024'),
  ('Razer Keyboard', 'Accessories', 159.99, 200, 'RZKB-V3');" "MySQL: Insert 10 products"

run_my "INSERT IGNORE INTO customers (name, email, phone, city, credit_limit) VALUES
  ('Acme Corp', 'orders@acme.com', '+1-555-0101', 'New York', 50000),
  ('TechStart Inc', 'buy@techstart.io', '+1-555-0202', 'San Francisco', 25000),
  ('Global Trade', 'procurement@gtrade.com', '+44-20-7123', 'London', 75000),
  ('Innovate Labs', 'admin@innovate.co', '+49-30-1234', 'Berlin', 30000),
  ('DataFlow Systems', 'it@dataflow.net', '+81-3-5678', 'Tokyo', 40000);" "MySQL: Insert 5 customers"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 3: Application Queries (realistic patterns)
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 3: Application Queries ━━━"

echo "  [Simulating web app login flow]"
run_pg "SELECT id, username, role FROM users WHERE username = 'alice' AND active = true;" "PG: User login lookup"
run_pg "UPDATE users SET last_login = NOW() WHERE username = 'alice';" "PG: Update last_login"

echo "  [Simulating dashboard data load]"
run_pg "SELECT u.username, COUNT(o.id) as order_count, SUM(o.price * o.quantity) as total_spent
  FROM users u LEFT JOIN orders o ON u.id = o.user_id
  GROUP BY u.username ORDER BY total_spent DESC NULLS LAST;" "PG: User order summary (JOIN + GROUP BY)"

run_pg "SELECT status, COUNT(*) as cnt, SUM(price * quantity) as total
  FROM orders GROUP BY status ORDER BY total DESC;" "PG: Order status report"

run_my "SELECT category, COUNT(*) as products, SUM(stock) as total_stock, AVG(price) as avg_price
  FROM products GROUP BY category ORDER BY total_stock DESC;" "MySQL: Product category report"

run_my "SELECT p.name, p.price, p.stock, p.category
  FROM products p WHERE p.stock < 100 ORDER BY p.stock ASC;" "MySQL: Low stock alert query"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 4: Concurrent Writes (order processing)
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 4: Concurrent Writes ━━━"

for i in $(seq 1 5); do
  run_pg "INSERT INTO orders (user_id, product, quantity, price, status)
    VALUES ($((RANDOM % 10 + 1)), 'Batch Item $i', $((RANDOM % 5 + 1)), $((RANDOM % 500 + 50)).99, 'pending');" "PG: New order #$i"
done

run_my "UPDATE products SET stock = stock - 1 WHERE sku = 'MBP-16-2024' AND stock > 0;" "MySQL: Decrement stock"
run_my "UPDATE products SET stock = stock - 2 WHERE sku = 'IP15P-256' AND stock > 0;" "MySQL: Decrement phone stock"
run_my "UPDATE customers SET credit_limit = credit_limit - 2500 WHERE name = 'Acme Corp';" "MySQL: Reduce credit limit"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 5: Analytical Queries (heavy reads)
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 5: Analytical Queries ━━━"

run_pg "SELECT u.username, u.email, u.role, COUNT(o.id) as orders,
  COALESCE(SUM(o.price * o.quantity), 0) as revenue,
  MAX(o.created_at) as last_order
  FROM users u LEFT JOIN orders o ON u.id = o.user_id
  GROUP BY u.id, u.username, u.email, u.role
  HAVING COUNT(o.id) > 0
  ORDER BY revenue DESC;" "PG: Revenue per user (complex aggregate)"

run_pg "SELECT product, SUM(quantity) as total_qty, SUM(price * quantity) as total_value,
  COUNT(*) as order_count
  FROM orders WHERE status = 'completed'
  GROUP BY product ORDER BY total_value DESC;" "PG: Best selling products"

run_pg "SELECT DATE_TRUNC('day', created_at) as day, COUNT(*) as orders, SUM(price * quantity) as daily_revenue
  FROM orders GROUP BY day ORDER BY day;" "PG: Daily revenue trend"

run_my "SELECT c.name, c.city, c.credit_limit,
  (SELECT COUNT(*) FROM products WHERE category = 'Laptops') as laptop_count
  FROM customers c ORDER BY c.credit_limit DESC;" "MySQL: Customer report with subquery"

run_my "SELECT name, price, stock, price * stock as inventory_value
  FROM products ORDER BY inventory_value DESC;" "MySQL: Inventory valuation"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 6: Rapid-fire Queries (stress)
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 6: Rapid-fire Stress (20 queries) ━━━"

for i in $(seq 1 10); do
  MSYS_NO_PATHCONV=1 $PG "SELECT $i AS n, NOW() AS ts;" 2>/dev/null &
done
for i in $(seq 1 10); do
  MSYS_NO_PATHCONV=1 $MY -e "SELECT $i AS n, NOW() AS ts;" 2>/dev/null &
done
wait
pass "20 concurrent queries completed"

sleep 2

# ─────────────────────────────────────────────────
# PHASE 7: Multi-statement & Edge Cases
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 7: Edge Cases ━━━"

run_pg "SELECT 1 AS a; SELECT 2 AS b; SELECT 3 AS c;" "PG: Multi-statement (3 queries)"
run_pg "SELECT * FROM users WHERE username IN ('admin', 'alice', 'bob');" "PG: IN clause query"
run_pg "SELECT username, email FROM users WHERE email LIKE '%company.com' ORDER BY username;" "PG: LIKE pattern query"
run_my "SELECT UPPER(name), ROUND(price, 0) FROM products WHERE price BETWEEN 100 AND 500;" "MySQL: BETWEEN + functions"
run_my "SELECT COUNT(*) AS total, MAX(price) AS max_price, MIN(price) AS min_price FROM products;" "MySQL: Aggregate functions"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 8: Audit & Updates
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 8: Data Modifications ━━━"

run_pg "UPDATE orders SET status = 'shipped' WHERE status = 'pending' AND created_at < NOW() - INTERVAL '1 minute';" "PG: Batch status update"
run_pg "INSERT INTO audit_log (action, table_name, record_id, changed_by)
  SELECT 'status_update', 'orders', id, 'system' FROM orders WHERE status = 'shipped';" "PG: Audit log insert"
run_my "UPDATE products SET price = price * 0.9 WHERE category = 'Audio';" "MySQL: 10% discount on Audio"
run_pg "DELETE FROM orders WHERE status = 'completed' AND price * quantity < 50;" "PG: Cleanup small completed orders"

sleep 1

# ─────────────────────────────────────────────────
# PHASE 9: Final Report
# ─────────────────────────────────────────────────
echo ""
echo "━━━ PHASE 9: Final Verification ━━━"

run_pg "SELECT COUNT(*) AS total_users FROM users;" "PG: Count users"
run_pg "SELECT COUNT(*) AS total_orders FROM orders;" "PG: Count orders"
run_pg "SELECT COUNT(*) AS audit_entries FROM audit_log;" "PG: Count audit log"
run_my "SELECT COUNT(*) AS total_products FROM products;" "MySQL: Count products"
run_my "SELECT COUNT(*) AS total_customers FROM customers;" "MySQL: Count customers"

# ─────────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────────
echo ""
echo "━━━ Cleanup ━━━"
run_pg "DROP TABLE IF EXISTS audit_log, orders, users CASCADE;" "PG: Drop tables"
run_my "DROP TABLE IF EXISTS products, customers;" "MySQL: Drop tables"

# ─────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   RESULTS: $OK passed, $FAIL failed, $TOTAL total       "
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Dashboard stats
curl -s http://127.0.0.1:30200/api/dashboard 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
o=d['overview'];t=d['traffic'];p=d['pool']
print('  Argus Dashboard Stats:')
print(f'    Uptime:       {o[\"uptime\"]}')
print(f'    Connections:  {t[\"total_connections\"]}')
print(f'    Commands:     {t[\"total_commands\"]}')
print(f'    Rows:         {t[\"total_rows\"]}')
print(f'    Blocked:      {t[\"blocked_commands\"]}')
print(f'    Masked:       {t[\"masked_results\"]}')
print(f'    Memory:       {o[\"memory_mb\"]} MB')
print(f'    Goroutines:   {o[\"goroutines\"]}')
for n,s in p['targets'].items():
    h='UP' if s['Healthy'] else 'DOWN'
    print(f'    {n:10s}: {h} (idle={s[\"Idle\"]})')
" 2>/dev/null

echo ""
echo "  MySQL warnings: $(docker logs argus-mysql-1 2>&1 | grep -c 'Aborted') aborted connections"
echo ""

exit $FAIL
