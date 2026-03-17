package admin

import "net/http"

// dashboardPage is the embedded web dashboard HTML.
// All data is fetched from Argus REST API endpoints via fetch().
// No external dependencies — pure HTML/CSS/JS.
var dashboardPage = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,Roboto,sans-serif;background:#0f172a;color:#e2e8f0}
.hdr{background:#1e293b;padding:20px 30px;border-bottom:1px solid #334155;display:flex;align-items:center;justify-content:space-between}
.hdr h1{font-size:24px;color:#38bdf8}
.badge{padding:6px 16px;border-radius:20px;font-size:13px;font-weight:600}
.bg-ok{background:#064e3b;color:#34d399}.bg-warn{background:#78350f;color:#fbbf24}.bg-err{background:#7f1d1d;color:#f87171}
.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;padding:20px 30px}
.c{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px}
.c h3{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
.c .v{font-size:28px;font-weight:700;color:#f1f5f9}.c .s{font-size:12px;color:#64748b;margin-top:4px}
.sec{padding:0 30px 20px}.sec h2{font-size:15px;color:#cbd5e1;margin-bottom:10px}
.tgt{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px 16px;margin-bottom:8px;display:flex;justify-content:space-between}
.tgt .n{font-weight:600}.tgt .i{font-size:12px;color:#94a3b8}
.d{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}.d.g2{background:#34d399}.d.r2{background:#f87171}
table{width:100%;border-collapse:collapse}th{text-align:left;padding:8px;color:#94a3b8;font-size:11px;text-transform:uppercase;border-bottom:1px solid #334155}
td{padding:8px;color:#e2e8f0;font-size:13px;border-bottom:1px solid #1e293b}
.ft{text-align:center;padding:20px;color:#475569;font-size:11px}
</style>
</head>
<body>
<div class="hdr"><h1>Argus Dashboard</h1><span class="badge bg-ok" id="st">Loading</span></div>
<div class="g" id="cards"></div>
<div class="sec"><h2>Targets</h2><div id="tgts"></div></div>
<div class="sec"><h2>Sessions</h2><table><thead><tr><th>ID</th><th>User</th><th>DB</th><th>Duration</th><th>Cmds</th></tr></thead><tbody id="sess"></tbody></table></div>
<div class="ft">Argus - The Hundred-Eyed Database Guardian | Refreshes every 5s</div>
<script>
const B=window.location.origin;
function E(t){return document.getElementById(t)}
function T(el,txt){el.textContent=txt}
function mk(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt)e.textContent=txt;return e}
function card(p,t,v,s){const d=document.createElement('div');d.className='c';const h=mk('h3','',t);const val=mk('div','v',String(v));const sub=mk('div','s',s);d.appendChild(h);d.appendChild(val);d.appendChild(sub);p.appendChild(d)}
async function R(){
try{
const[h,d,s]=await Promise.all([fetch(B+'/healthz').then(r=>r.json()),fetch(B+'/api/dashboard').then(r=>r.json()),fetch(B+'/api/sessions').then(r=>r.json())]);
const st=E('st');T(st,h.status);st.className='badge '+(h.status==='healthy'?'bg-ok':'bg-err');
const o=d.overview||{},tr=d.traffic||{},p=d.pool||{};
const cc=E('cards');cc.replaceChildren();
card(cc,'Sessions',o.active_sessions||0,'Active proxy sessions');
card(cc,'Commands',tr.total_commands||0,'Total processed');
card(cc,'Blocked',tr.blocked_commands||0,'Policy violations');
card(cc,'Masked',tr.masked_results||0,'Result sets masked');
card(cc,'Connections',tr.total_connections||0,'Total connections');
card(cc,'Rows',tr.total_rows||0,'Rows transferred');
card(cc,'Pool',p.active_connections||0,'Active backend conns');
card(cc,'Uptime',o.uptime||'-','Since restart');
card(cc,'Memory',(o.memory_mb||0)+' MB','Heap allocation');
const tg=E('tgts');tg.replaceChildren();
Object.entries(h.pools||{}).forEach(function(kv){const n=kv[0],v=kv[1];const row=document.createElement('div');row.className='tgt';const left=document.createElement('div');const dot=mk('span','d '+(v.Healthy?'g2':'r2'));const nm=mk('span','n',n);left.appendChild(dot);left.appendChild(nm);const right=mk('div','i',v.Target+' | A:'+v.Active+' I:'+v.Idle+'/'+v.Max);row.appendChild(left);row.appendChild(right);tg.appendChild(row)});
const tb=E('sess');tb.replaceChildren();
if(!s||s.length===0){const r=document.createElement('tr');const td=document.createElement('td');td.colSpan=5;td.style.color='#64748b';T(td,'No active sessions');r.appendChild(td);tb.appendChild(r)}
else{s.forEach(function(x){const r=document.createElement('tr');[x.id.substr(0,8),x.username,x.database||'-',x.duration,String(x.command_count)].forEach(function(t){const td=document.createElement('td');T(td,t);r.appendChild(td)});tb.appendChild(r)})}
}catch(e){T(E('st'),'Error')}}
R();setInterval(R,5000);
</script>
</body>
</html>`)

// HandleDashboardUI serves the embedded web dashboard.
func HandleDashboardUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(dashboardPage)
}
