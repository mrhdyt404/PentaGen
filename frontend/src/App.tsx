import { useEffect, useState } from "react";
import { ShieldCheck, Radar, Bug, FileText, Activity, Plus, RefreshCw } from "lucide-react";

const API = "http://127.0.0.1:8000";
type Finding = {id:number; scan_id:number; title:string; severity:string; confidence:string; status:string; remediation:string};
export default function App() {
  const [health, setHealth] = useState("Connecting");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [targetUrl, setTargetUrl] = useState("");
  const [targetName, setTargetName] = useState("");
  const [authRef, setAuthRef] = useState("");
  const [expires, setExpires] = useState("");
  const [message, setMessage] = useState("");
  async function refresh() {
    try {
      const h = await fetch(`${API}/health`).then(r => r.json());
      setHealth(h.status);
      setFindings(await fetch(`${API}/api/v1/findings`).then(r => r.json()));
    } catch { setHealth("Offline"); }
  }
  useEffect(() => { refresh(); }, []);
  async function registerTarget(e: React.FormEvent) {
    e.preventDefault(); setMessage("");
    try {
      const r = await fetch(`${API}/api/v1/targets`, {method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify({name:targetName, base_url:targetUrl, authorization_reference:authRef, authorization_expires_at:expires})});
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || "Registration failed");
      setMessage(`Target registered: ${data.hostname}`); setTargetName(""); setTargetUrl(""); setAuthRef(""); setExpires("");
    } catch (err) { setMessage(err instanceof Error ? err.message : "Request failed"); }
  }
  return <main className="shell">
    <aside className="sidebar"><div className="brand"><div className="brand-icon"><ShieldCheck/></div><div><b>PentaGen</b><small>SECURITY INTELLIGENCE</small></div></div>
      <nav><a className="active"><Activity size={18}/> Overview</a><a><Radar size={18}/> Targets</a><a><Bug size={18}/> Findings</a><a><FileText size={18}/> Reports</a></nav>
      <div className="side-note">AI-assisted security assessment<br/>Authorized testing only</div>
    </aside>
    <section className="content">
      <header><div><span className="eyebrow">SECURITY OPERATIONS</span><h1>Overview</h1><p>Monitor authorized assessments and security findings.</p></div><button className="ghost" onClick={refresh}><RefreshCw size={16}/> Refresh</button></header>
      <div className="stats"><div className="stat"><span>API STATUS</span><strong className={health==="ok"?"good":""}>{health}</strong><small>Local development API</small></div><div className="stat"><span>FINDINGS</span><strong>{findings.length}</strong><small>Awaiting human review</small></div><div className="stat"><span>ASSESSMENT MODE</span><strong>Assisted</strong><small>Safe baseline profile</small></div></div>
      <div className="panel"><div className="panel-head"><div><h2>Register authorized target</h2><p>Only register systems you own or are explicitly authorized to test.</p></div></div>
        <form onSubmit={registerTarget} className="form">
          <label>Target name<input required minLength={2} value={targetName} onChange={e=>setTargetName(e.target.value)} placeholder="My staging application"/></label>
          <label>Base URL<input required type="url" value={targetUrl} onChange={e=>setTargetUrl(e.target.value)} placeholder="https://staging.example.com"/></label>
          <label>Authorization evidence reference<input required value={authRef} onChange={e=>setAuthRef(e.target.value)} placeholder="Ticket / contract / approval reference"/></label>
          <label>Authorization expiry<input required type="datetime-local" value={expires} onChange={e=>setExpires(e.target.value)} /></label>
          <button className="primary"><Plus size={16}/> Register target</button>
        </form>{message && <p className="message">{message}</p>}
      </div>
      <div className="panel"><div className="panel-head"><div><h2>Recent findings</h2><p>Preliminary results from safe baseline checks.</p></div><span className="pill">{findings.length} records</span></div>
        {findings.length===0?<div className="empty"><ShieldCheck size={30}/><b>No findings yet</b><span>Register an authorized target and run a safe baseline scan through the API.</span></div>:
        <div className="findings">{findings.map(f=><div className="finding" key={f.id}><div><b>{f.title}</b><small>Scan #{f.scan_id} · {f.confidence} confidence</small></div><span className={`severity ${f.severity}`}>{f.severity}</span></div>)}</div>}
      </div>
      <footer>PentaGen v0.1.0 · Development scaffold · Do not expose publicly</footer>
    </section>
  </main>;
}
