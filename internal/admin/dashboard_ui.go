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
<div class="sec"><h2>Pending Approvals</h2><div id="approvals" style="font-size:13px;color:#94a3b8">Loading...</div></div>
<div class="sec"><h2>Live Events <span id="ws-status" style="font-size:11px;color:#64748b">(connecting...)</span></h2><div id="events" style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px;max-height:400px;overflow-y:auto;font-family:monospace;font-size:12px"></div></div>
<div class="ft">Argus - The Hundred-Eyed Database Guardian | Dashboard refreshes every 5s | Live events via WebSocket</div>
<script>
const B=window.location.origin;
function E(t){return document.getElementById(t)}
function T(el,txt){el.textContent=txt}
function mk(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt)e.textContent=txt;return e}
function card(p,t,v,s){const d=document.createElement('div');d.className='c';const h=mk('h3','',t);const val=mk('div','v',String(v));const sub=mk('div','s',s);d.appendChild(h);d.appendChild(val);d.appendChild(sub);p.appendChild(d)}
async function R(){
try{
const[h,d,s,ap]=await Promise.all([fetch(B+'/healthz').then(r=>r.json()),fetch(B+'/api/dashboard').then(r=>r.json()),fetch(B+'/api/sessions').then(r=>r.json()),fetch(B+'/api/approvals').then(r=>r.json()).catch(function(){return[]})]);
const apDiv=E('approvals');apDiv.replaceChildren();
if(!ap||ap.length===0){T(apDiv,'No pending approvals')}
else{ap.forEach(function(a){const row=document.createElement('div');row.style.cssText='background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center';const info=mk('div','');info.innerHTML='<b style="color:#fbbf24">'+esc(a.username||'')+'</b>@'+esc(a.database||'')+' <span style="color:#94a3b8">'+esc((a.sql||'').substring(0,80))+'</span> <span style="color:#f87171">['+esc(a.risk_level||'')+']</span>';const btns=mk('div','');const appBtn=document.createElement('button');appBtn.textContent='Approve';appBtn.style.cssText='background:#065f46;color:#34d399;border:none;padding:6px 12px;border-radius:6px;cursor:pointer;margin-right:6px;font-size:12px';appBtn.onclick=function(){fetch(B+'/api/approvals/approve?id='+a.id,{method:'POST'}).then(function(){R()})};const denyBtn=document.createElement('button');denyBtn.textContent='Deny';denyBtn.style.cssText='background:#7f1d1d;color:#f87171;border:none;padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px';denyBtn.onclick=function(){fetch(B+'/api/approvals/deny?id='+a.id+'&approver=dashboard&reason=denied',{method:'POST'}).then(function(){R()})};btns.appendChild(appBtn);btns.appendChild(denyBtn);row.appendChild(info);row.appendChild(btns);apDiv.appendChild(row)})}
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
/* Live Events via WebSocket */
(function(){
const evDiv=E('events'),wsSt=E('ws-status');
let ws,reconn=1;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function addEv(data){
try{
const e=JSON.parse(data);
const row=document.createElement('div');
row.style.cssText='padding:4px 0;border-bottom:1px solid #1e293b';
const ts=new Date().toLocaleTimeString();
const parts=[];
if(e.type==='command'){
const color=e.action==='block'?'#f87171':e.action==='mask'?'#fbbf24':'#34d399';
parts.push(mk('span','',ts+' '));parts[0].style.color='#64748b';
const act=mk('span','',e.action);act.style.color=color;act.style.fontWeight='bold';
parts.push(document.createTextNode(' '));parts.push(act);
parts.push(document.createTextNode(' '+esc(e.username)+'@'+esc(e.database)+' '));
const cmd=mk('span','',esc(e.command));cmd.style.color='#38bdf8';parts.push(cmd);
parts.push(document.createTextNode(' ('+e.rows+' rows, '+(e.duration_us/1000).toFixed(1)+'ms)'));
}else if(e.type==='anomaly'){
parts.push(document.createTextNode(ts+' ANOMALY '+JSON.stringify(e.alert)));
row.style.color='#fbbf24';
}else if(e.type==='high_cost_query'){
parts.push(document.createTextNode(ts+' HIGH COST '+esc(e.username)+' cost='+e.cost));
row.style.color='#f87171';
}else if(e.type==='query_rewrite'){
parts.push(document.createTextNode(ts+' REWRITE '+esc(e.username)+' '+JSON.stringify(e.rewrites)));
row.style.color='#a78bfa';
}else{parts.push(document.createTextNode(ts+' '+JSON.stringify(e)))}
parts.forEach(function(p){row.appendChild(p)});
evDiv.insertBefore(row,evDiv.firstChild);
while(evDiv.children.length>200)evDiv.removeChild(evDiv.lastChild);
}catch(ex){const row=document.createElement('div');T(row,data);evDiv.insertBefore(row,evDiv.firstChild)}
}
function connect(){
const proto=location.protocol==='https:'?'wss:':'ws:';
ws=new WebSocket(proto+'//'+location.host+'/api/events/ws');
ws.onopen=function(){T(wsSt,'(connected)');wsSt.style.color='#34d399';reconn=1};
ws.onmessage=function(ev){addEv(ev.data)};
ws.onclose=function(){T(wsSt,'(disconnected)');wsSt.style.color='#f87171';setTimeout(connect,Math.min(reconn*1000,10000));reconn*=2};
ws.onerror=function(){ws.close()};
}
connect();
})();
</script>
</body>
</html>`)

// HandleDashboardUI serves the embedded web dashboard.
func HandleDashboardUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
	w.Write(dashboardPage)
}
