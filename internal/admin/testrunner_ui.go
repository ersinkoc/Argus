package admin

import "net/http"

var testRunnerPage = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus Test Runner</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,monospace;background:#0f172a;color:#e2e8f0;padding:20px}
h1{color:#38bdf8;margin-bottom:5px}
.sub{color:#64748b;font-size:13px;margin-bottom:20px}
.row{display:flex;gap:20px;margin-bottom:20px}
.col{flex:1}
.panel{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;margin-bottom:16px}
.panel h2{font-size:14px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}
.btn{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;margin:3px;transition:all 0.2s}
.btn:hover{transform:scale(1.02)}
.btn-green{background:#059669;color:white}.btn-green:hover{background:#047857}
.btn-yellow{background:#d97706;color:white}.btn-yellow:hover{background:#b45309}
.btn-red{background:#dc2626;color:white}.btn-red:hover{background:#b91c1c}
.btn-blue{background:#2563eb;color:white}.btn-blue:hover{background:#1d4ed8}
.btn-purple{background:#7c3aed;color:white}.btn-purple:hover{background:#6d28d9}
.btn-gray{background:#475569;color:white}.btn-gray:hover{background:#334155}
.btn-lg{padding:12px 24px;font-size:15px}
.btn[disabled]{opacity:0.5;cursor:not-allowed}
#log{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:12px;height:500px;overflow-y:auto;font-size:12px;line-height:1.8}
.log-ok{color:#34d399}.log-block{color:#f87171}.log-mask{color:#fbbf24}.log-info{color:#94a3b8}.log-sql{color:#38bdf8}
.stats{display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.stat{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px 16px;text-align:center;min-width:80px}
.stat .n{font-size:22px;font-weight:700;color:#f1f5f9}.stat .l{font-size:10px;color:#64748b;text-transform:uppercase}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.tag-ok{background:#064e3b;color:#34d399}.tag-block{background:#7f1d1d;color:#f87171}.tag-mask{background:#78350f;color:#fbbf24}
a{color:#38bdf8;text-decoration:none}
</style>
</head>
<body>
<h1>Argus Test Runner</h1>
<div class="sub">Interactive test panel — run queries through the proxy and see policy enforcement live. <a href="/ui">Back to Dashboard</a></div>

<div class="stats">
<div class="stat"><div class="n" id="s-total">0</div><div class="l">Total</div></div>
<div class="stat"><div class="n" id="s-ok" style="color:#34d399">0</div><div class="l">Allowed</div></div>
<div class="stat"><div class="n" id="s-block" style="color:#f87171">0</div><div class="l">Blocked</div></div>
<div class="stat"><div class="n" id="s-mask" style="color:#fbbf24">0</div><div class="l">Masked</div></div>
<div class="stat"><div class="n" id="s-fail" style="color:#64748b">0</div><div class="l">Errors</div></div>
</div>

<div class="row">
<div class="col" style="max-width:340px">

<div class="panel">
<h2>Quick Tests</h2>
<button class="btn btn-green" onclick="run('admin_select')">Admin: SELECT employees</button>
<button class="btn btn-yellow" onclick="run('support_select')">Support: SELECT (masked)</button>
<button class="btn btn-red" onclick="run('user_drop')">Bob: DROP TABLE (blocked)</button>
<button class="btn btn-red" onclick="run('user_delete_all')">Bob: DELETE * (blocked)</button>
<button class="btn btn-yellow" onclick="run('analyst_select')">Analyst: SELECT (partial mask)</button>
<button class="btn btn-green" onclick="run('admin_join')">Admin: JOIN query</button>
<button class="btn btn-blue" onclick="run('mysql_select')">MySQL: Product list</button>
<button class="btn btn-blue" onclick="run('mysql_insert')">MySQL: Insert product</button>
<button class="btn btn-green" onclick="run('pg_insert')">PG: Insert order</button>
<button class="btn btn-green" onclick="run('pg_update')">PG: Update status</button>
<button class="btn btn-green" onclick="run('pg_multi')">PG: Multi-statement</button>
<button class="btn btn-purple" onclick="run('pg_analytics')">PG: Analytics (window)</button>
</div>

<div class="panel">
<h2>Batch Tests</h2>
<button class="btn btn-lg btn-green" onclick="runAll()" id="btn-all">Run All Tests</button>
<button class="btn btn-lg btn-purple" onclick="runStress()" id="btn-stress">Stress Test (50 queries)</button>
<button class="btn btn-lg btn-gray" onclick="clearLog()">Clear Log</button>
</div>

<div class="panel">
<h2>Custom SQL</h2>
<select id="custom-user" style="width:100%;padding:6px;margin-bottom:8px;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:4px">
<option value="admin">admin (full access)</option>
<option value="support_jane">support_jane (masked)</option>
<option value="analyst">analyst (partial mask)</option>
<option value="bob">bob (restricted)</option>
<option value="webapp">webapp (rate limited)</option>
</select>
<select id="custom-db" style="width:100%;padding:6px;margin-bottom:8px;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:4px">
<option value="pg">PostgreSQL</option>
<option value="mysql">MySQL</option>
</select>
<textarea id="custom-sql" rows="3" style="width:100%;padding:8px;background:#0f172a;color:#38bdf8;border:1px solid #334155;border-radius:4px;font-family:monospace;font-size:13px" placeholder="SELECT * FROM demo_employees LIMIT 5;"></textarea>
<button class="btn btn-blue" onclick="runCustom()" style="margin-top:6px;width:100%">Execute</button>
</div>

</div>
<div class="col">
<div class="panel" style="height:100%">
<h2>Test Log</h2>
<div id="log"></div>
</div>
</div>
</div>

<script>
const B=location.origin;
let stats={total:0,ok:0,block:0,mask:0,fail:0};
const log=document.getElementById('log');

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function updateStats(){
document.getElementById('s-total').textContent=stats.total;
document.getElementById('s-ok').textContent=stats.ok;
document.getElementById('s-block').textContent=stats.block;
document.getElementById('s-mask').textContent=stats.mask;
document.getElementById('s-fail').textContent=stats.fail;
}

function addLog(cls,tag,msg){
const d=document.createElement('div');
const ts=new Date().toLocaleTimeString();
const tagEl=document.createElement('span');
tagEl.className='tag '+cls;
tagEl.textContent=tag;
d.appendChild(document.createTextNode(ts+' '));
d.appendChild(tagEl);
d.appendChild(document.createTextNode(' '+msg));
log.insertBefore(d,log.firstChild);
}

async function apiTest(name,user,db,sql){
stats.total++;
try{
const r=await fetch(B+'/api/test/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,user:user,db:db,sql:sql})});
const d=await r.json();
if(d.action==='block'){stats.block++;addLog('tag-block','BLOCKED',esc(d.user)+'@'+esc(d.database)+': '+esc(d.sql)+' -> '+esc(d.reason))}
else if(d.masked){stats.mask++;addLog('tag-mask','MASKED',esc(d.user)+'@'+esc(d.database)+': '+esc(d.sql)+' ('+d.rows+' rows, '+d.columns_masked+' cols masked)')}
else if(d.error){stats.fail++;addLog('log-info','ERROR',esc(d.error))}
else{stats.ok++;addLog('tag-ok','ALLOW',esc(d.user)+'@'+esc(d.database)+': '+esc(d.sql)+' ('+d.rows+' rows, '+d.duration+')')}
}catch(e){stats.fail++;addLog('log-info','ERROR',esc(e.message))}
updateStats();
}

const TESTS={
admin_select:   ['admin','pg',"SELECT name, email, phone, ssn, salary FROM demo_employees ORDER BY name LIMIT 5"],
support_select: ['support_jane','pg',"SELECT name, email, phone, ssn, salary, password_hash FROM demo_employees ORDER BY name LIMIT 5"],
analyst_select: ['analyst','pg',"SELECT name, email, ssn, salary FROM demo_employees ORDER BY salary DESC LIMIT 5"],
user_drop:      ['bob','pg',"DROP TABLE demo_employees"],
user_delete_all:['bob','pg',"DELETE FROM demo_employees"],
admin_join:     ['admin','pg',"SELECT e.name, e.department, COUNT(o.id) AS orders, SUM(o.total) AS spent FROM demo_employees e LEFT JOIN demo_orders o ON e.id=o.employee_id GROUP BY e.id,e.name,e.department ORDER BY spent DESC NULLS LAST LIMIT 5"],
mysql_select:   ['argus_test','mysql',"SELECT name, price, stock, supplier_email FROM demo_inventory ORDER BY price DESC"],
mysql_insert:   ['argus_test','mysql',"INSERT INTO demo_inventory (sku,name,category,price,stock,supplier_email) VALUES ('TEST-'+FLOOR(RAND()*9999),'Test Product','Test',99.99,10,'test@supplier.com')"],
pg_insert:      ['admin','pg',"INSERT INTO demo_orders (employee_id,product,quantity,total,credit_card) VALUES (1,'Test Item',2,199.99,'4111-0000-0000-9999')"],
pg_update:      ['admin','pg',"UPDATE demo_orders SET status='shipped' WHERE id=(SELECT id FROM demo_orders WHERE status='pending' LIMIT 1)"],
pg_multi:       ['admin','pg',"SELECT COUNT(*) AS employees FROM demo_employees; SELECT COUNT(*) AS orders FROM demo_orders"],
pg_analytics:   ['admin','pg',"SELECT name, department, salary, RANK() OVER (PARTITION BY department ORDER BY salary DESC) AS dept_rank FROM demo_employees"],
};

function run(name){const t=TESTS[name];if(t)apiTest(name,t[0],t[1],t[2])}

async function runAll(){
const btn=document.getElementById('btn-all');btn.disabled=true;btn.textContent='Running...';
for(const name of Object.keys(TESTS)){await run(name);await new Promise(r=>setTimeout(r,300))}
btn.disabled=false;btn.textContent='Run All Tests';
}

async function runStress(){
const btn=document.getElementById('btn-stress');btn.disabled=true;btn.textContent='Running...';
const names=Object.keys(TESTS);
for(let i=0;i<50;i++){const name=names[i%names.length];await run(name);await new Promise(r=>setTimeout(r,100))}
btn.disabled=false;btn.textContent='Stress Test (50 queries)';
}

function runCustom(){
const user=document.getElementById('custom-user').value;
const db=document.getElementById('custom-db').value;
const sql=document.getElementById('custom-sql').value.trim();
if(!sql){addLog('log-info','INFO','Enter SQL first');return}
apiTest('custom',user,db,sql);
}

function clearLog(){log.replaceChildren();stats={total:0,ok:0,block:0,mask:0,fail:0};updateStats()}
</script>
</body>
</html>`)

// HandleTestRunnerUI serves the interactive test runner page.
func HandleTestRunnerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
	w.Write(testRunnerPage)
}
