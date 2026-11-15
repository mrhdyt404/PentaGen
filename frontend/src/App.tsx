import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Award,
  CheckCircle,
  Clock,
  Download,
  FileCheck,
  FileText,
  Laptop,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";

const API = "http://127.0.0.1:8000";

type OverviewData = {
  total_targets: number;
  total_scans: number;
  active_scans: number;
  pending_approvals: number;
  paired_agents: number;
  total_findings: number;
  posture_score: number;
  security_grade: string;
  severity_distribution: Record<string, number>;
  status_distribution: Record<string, number>;
  recent_scans: Array<{ id: number; profile: string; status: string; target_id: number | null; created_at: string | null }>;
  recent_findings: Array<{ id: number; title: string; severity: string; confidence: string; status: string; location: string | null }>;
  recent_approvals: Array<{ id: number; requested_action: string; risk_level: string; status: string; created_at: string | null }>;
};

type TargetItem = {
  id: number;
  name: string;
  base_url: string;
  hostname: string;
  created_at: string;
};

type AgentNodeItem = {
  id: string;
  name: string;
  device_fingerprint: string;
  status: string;
  last_seen_at: string;
};

type ApprovalItem = {
  id: number;
  scan_id: number;
  requested_action: string;
  risk_level: string;
  status: string;
  reason: string | null;
  created_at: string;
};

export default function App() {
  const [activeTab, setActiveTab] = useState<"overview" | "targets" | "findings" | "approvals" | "agents" | "audit">("overview");
  const [token, setToken] = useState<string>(() => localStorage.getItem("pg_token") || "");
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [nodes, setNodes] = useState<AgentNodeItem[]>([]);
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [message, setMessage] = useState("");
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Form states
  const [targetName, setTargetName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [authRef, setAuthRef] = useState("");
  const [authExpiry, setAuthExpiry] = useState("");
  const [pairingTokenResult, setPairingTokenResult] = useState<string | null>(null);

  const authHeaders = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setMessage("");
    try {
      const res = await fetch(`${API}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: loginEmail, password: loginPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Authentication failed");
      setToken(data.access_token);
      localStorage.setItem("pg_token", data.access_token);
      setMessage("Authenticated successfully.");
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Login error");
    }
  }

  async function loadData() {
    setIsRefreshing(true);
    try {
      if (token) {
        const [ovRes, tgRes, ndRes, apRes] = await Promise.all([
          fetch(`${API}/api/v1/dashboard/overview`, { headers: authHeaders }).then((r) => r.json()),
          fetch(`${API}/api/v1/targets`, { headers: authHeaders }).then((r) => r.json()),
          fetch(`${API}/api/v1/agents/nodes`, { headers: authHeaders }).then((r) => r.json()),
          fetch(`${API}/api/v1/approvals`, { headers: authHeaders }).then((r) => r.json()),
        ]);
        if (ovRes && !ovRes.detail) setOverview(ovRes);
        if (Array.isArray(tgRes)) setTargets(tgRes);
        if (Array.isArray(ndRes)) setNodes(ndRes);
        if (Array.isArray(apRes)) setApprovals(apRes);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsRefreshing(false);
    }
  }

  useEffect(() => {
    if (token) loadData();
  }, [token]);

  async function handleCreateTarget(e: React.FormEvent) {
    e.preventDefault();
    setMessage("");
    try {
      const res = await fetch(`${API}/api/v1/targets`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({
          name: targetName,
          base_url: targetUrl,
          authorization_reference: authRef,
          authorization_expires_at: new Date(authExpiry).toISOString(),
          allowed_profiles: ["safe_baseline", "tls_check", "passive_recon"],
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Registration failed");
      setMessage(`Target registered: ${data.hostname}`);
      setTargetName("");
      setTargetUrl("");
      setAuthRef("");
      setAuthExpiry("");
      loadData();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Target creation failed");
    }
  }

  async function handleGeneratePairingToken() {
    setMessage("");
    try {
      const res = await fetch(`${API}/api/v1/agents/pairing/tokens`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ name_hint: "Desktop Workstation", expires_in_minutes: 30 }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to generate pairing token");
      setPairingTokenResult(data.token);
      setMessage("One-time pairing token generated. Enter it in Desktop Agent.");
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Pairing token request failed");
    }
  }

  async function handleDecideApproval(id: number, decision: "approve" | "reject") {
    try {
      const reason = window.prompt(`Enter reason for ${decision.toUpperCase()} decision:`, "Authorized by SecOps lead");
      if (!reason) return;
      const res = await fetch(`${API}/api/v1/approvals/${id}/decide`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ decision, reason }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Decision failed");
      }
      loadData();
      setMessage(`Approval #${id} marked as ${decision.toUpperCase()}.`);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Approval decision error");
    }
  }

  function downloadReport(scanId: number) {
    window.open(`${API}/api/v1/scans/${scanId}/report.pdf`, "_blank");
  }

  function downloadAudit(format: "jsonl" | "csv") {
    window.open(`${API}/api/v1/audit-logs/export?format=${format}`, "_blank");
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={24} />
          </div>
          <div>
            <b>PentaGen</b>
            <small>SECURITY OPERATIONS</small>
          </div>
        </div>
        <nav>
          <a className={activeTab === "overview" ? "active" : ""} onClick={() => setActiveTab("overview")}>
            <Activity size={18} /> Overview
          </a>
          <a className={activeTab === "targets" ? "active" : ""} onClick={() => setActiveTab("targets")}>
            <Search size={18} /> Targets & Scope
          </a>
          <a className={activeTab === "approvals" ? "active" : ""} onClick={() => setActiveTab("approvals")}>
            <FileCheck size={18} /> Approvals {overview?.pending_approvals ? `(${overview.pending_approvals})` : ""}
          </a>
          <a className={activeTab === "agents" ? "active" : ""} onClick={() => setActiveTab("agents")}>
            <Laptop size={18} /> Hybrid Agents
          </a>
          <a className={activeTab === "audit" ? "active" : ""} onClick={() => setActiveTab("audit")}>
            <FileText size={18} /> Audit & Reports
          </a>
        </nav>
        <div className="side-note">
          PentaGen v1.0 Professional Release<br />
          Assisted Execution · Strict Invariants
        </div>
      </aside>

      <section className="content">
        <header>
          <div>
            <span className="eyebrow">ENTERPRISE PLATFORM</span>
            <h1>{activeTab.toUpperCase()}</h1>
            <p>AI-Powered Security Assessment with Cryptographic Verification</p>
          </div>
          <div style={{ display: "flex", gap: "10px" }}>
            {token ? (
              <>
                <button className="ghost" onClick={loadData} disabled={isRefreshing}>
                  <RefreshCw size={16} className={isRefreshing ? "spin" : ""} /> Refresh
                </button>
                <button
                  className="ghost"
                  onClick={() => {
                    setToken("");
                    localStorage.removeItem("pg_token");
                  }}
                >
                  Logout
                </button>
              </>
            ) : null}
          </div>
        </header>

        {message && <div className="notice-banner">{message}</div>}

        {!token ? (
          <div className="panel" style={{ maxWidth: "480px", margin: "40px auto" }}>
            <div className="panel-head">
              <h2>Authenticate to PentaGen</h2>
            </div>
            <form onSubmit={handleLogin} className="form" style={{ gridTemplateColumns: "1fr" }}>
              <label>
                Email Address
                <input type="email" required value={loginEmail} onChange={(e) => setLoginEmail(e.target.value)} placeholder="owner@pentagen.example.com" />
              </label>
              <label>
                Password
                <input type="password" required value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} placeholder="••••••••••••" />
              </label>
              <button className="primary" type="submit">Sign In</button>
            </form>
          </div>
        ) : (
          <>
            {activeTab === "overview" && (
              <>
                <div className="stats">
                  <div className="stat">
                    <span>SECURITY POSTURE</span>
                    <strong style={{ color: overview?.security_grade === "A" ? "#34d399" : "#f87171" }}>
                      Grade {overview?.security_grade || "N/A"} ({overview?.posture_score ?? 100}/100)
                    </strong>
                    <small>Based on CVSS & finding severity</small>
                  </div>
                  <div className="stat">
                    <span>ASSESSMENT SCOPE</span>
                    <strong>{overview?.total_targets ?? 0} Targets</strong>
                    <small>{overview?.active_scans ?? 0} active / running scans</small>
                  </div>
                  <div className="stat">
                    <span>HUMAN APPROVALS</span>
                    <strong>{overview?.pending_approvals ?? 0} Pending</strong>
                    <small>{overview?.paired_agents ?? 0} paired desktop agents</small>
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-head">
                    <h2>Severity Distribution</h2>
                    <span className="pill">{overview?.total_findings ?? 0} total findings</span>
                  </div>
                  <div className="severity-bar-container">
                    <div className="severity-chip critical">Critical: {overview?.severity_distribution?.critical ?? 0}</div>
                    <div className="severity-chip high">High: {overview?.severity_distribution?.high ?? 0}</div>
                    <div className="severity-chip medium">Medium: {overview?.severity_distribution?.medium ?? 0}</div>
                    <div className="severity-chip low">Low: {overview?.severity_distribution?.low ?? 0}</div>
                    <div className="severity-chip info">Info: {overview?.severity_distribution?.info ?? 0}</div>
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-head">
                    <h2>Recent Scan Assessments</h2>
                  </div>
                  <div className="findings">
                    {overview?.recent_scans?.map((s) => (
                      <div className="finding" key={s.id}>
                        <div>
                          <b>Scan #{s.id} — Profile: {s.profile}</b>
                          <small>Status: {s.status.toUpperCase()} · Started: {s.created_at?.slice(0, 16) || "N/A"}</small>
                        </div>
                        <button className="ghost" onClick={() => downloadReport(s.id)}>
                          <Download size={14} /> PDF Report
                        </button>
                      </div>
                    ))}
                    {(!overview?.recent_scans || overview.recent_scans.length === 0) && (
                      <div className="empty">No assessment scans executed yet.</div>
                    )}
                  </div>
                </div>
              </>
            )}

            {activeTab === "targets" && (
              <>
                <div className="panel">
                  <div className="panel-head">
                    <h2>Register Authorized Target</h2>
                    <p>Enforce strict authorization validity windows and profiles.</p>
                  </div>
                  <form onSubmit={handleCreateTarget} className="form">
                    <label>
                      Target Name
                      <input required value={targetName} onChange={(e) => setTargetName(e.target.value)} placeholder="Production Web API" />
                    </label>
                    <label>
                      Target Base URL
                      <input required type="url" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} placeholder="https://api.example.com" />
                    </label>
                    <label>
                      Authorization Evidence Reference
                      <input required value={authRef} onChange={(e) => setAuthRef(e.target.value)} placeholder="Contract / JIRA Ticket Reference" />
                    </label>
                    <label>
                      Authorization Expiry Window
                      <input required type="datetime-local" value={authExpiry} onChange={(e) => setAuthExpiry(e.target.value)} />
                    </label>
                    <button className="primary" type="submit">
                      <Plus size={16} /> Register & Authorize
                    </button>
                  </form>
                </div>

                <div className="panel">
                  <div className="panel-head">
                    <h2>Authorized Target Assets</h2>
                    <span className="pill">{targets.length} targets</span>
                  </div>
                  <div className="findings">
                    {targets.map((t) => (
                      <div className="finding" key={t.id}>
                        <div>
                          <b>{t.name} ({t.hostname})</b>
                          <small>{t.base_url} · Registered {t.created_at.slice(0, 10)}</small>
                        </div>
                        <span className="pill">Authorized</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}

            {activeTab === "approvals" && (
              <div className="panel">
                <div className="panel-head">
                  <h2>Human Approval Queue</h2>
                  <p>Gated risk execution review for active tasks and desktop agents.</p>
                </div>
                <div className="findings">
                  {approvals.map((a) => (
                    <div className="finding" key={a.id}>
                      <div>
                        <b>Approval #{a.id} — Action: {a.requested_action}</b>
                        <small>Scan #{a.scan_id} · Risk Level: {a.risk_level.toUpperCase()} · Status: {a.status.toUpperCase()}</small>
                        {a.reason && <small>Decision Reason: {a.reason}</small>}
                      </div>
                      {a.status === "pending" ? (
                        <div style={{ display: "flex", gap: "8px" }}>
                          <button className="primary" onClick={() => handleDecideApproval(a.id, "approve")}>
                            <CheckCircle size={14} /> Approve
                          </button>
                          <button className="ghost" style={{ borderColor: "#ef4444", color: "#fca5a5" }} onClick={() => handleDecideApproval(a.id, "reject")}>
                            <XCircle size={14} /> Reject
                          </button>
                        </div>
                      ) : (
                        <span className={`severity ${a.status === "approved" ? "good" : "critical"}`}>{a.status}</span>
                      )}
                    </div>
                  ))}
                  {approvals.length === 0 && <div className="empty">No pending actions in approval queue.</div>}
                </div>
              </div>
            )}

            {activeTab === "agents" && (
              <div className="panel">
                <div className="panel-head">
                  <div>
                    <h2>Paired Desktop Agents</h2>
                    <p>Cryptographically authenticated agent devices for assisted security tasks.</p>
                  </div>
                  <button className="primary" onClick={handleGeneratePairingToken}>
                    <Plus size={16} /> Generate Pairing Token
                  </button>
                </div>

                {pairingTokenResult && (
                  <div className="token-reveal-box">
                    <b>One-Time Pairing Token (expires in 30m):</b>
                    <code>{pairingTokenResult}</code>
                  </div>
                )}

                <div className="findings">
                  {nodes.map((n) => (
                    <div className="finding" key={n.id}>
                      <div>
                        <b>{n.name} ({n.id})</b>
                        <small>Fingerprint: {n.device_fingerprint?.slice(0, 24)}... · Last Seen: {n.last_seen_at?.slice(0, 16)}</small>
                      </div>
                      <span className={`severity ${n.status === "active" ? "good" : "critical"}`}>{n.status}</span>
                    </div>
                  ))}
                  {nodes.length === 0 && <div className="empty">No desktop agents paired.</div>}
                </div>
              </div>
            )}

            {activeTab === "audit" && (
              <div className="panel">
                <div className="panel-head">
                  <div>
                    <h2>Audit Trail & Compliance Export</h2>
                    <p>Tamper-evident append-only logs with cryptographic SHA-256 integrity verification.</p>
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button className="ghost" onClick={() => downloadAudit("jsonl")}>
                      <Download size={14} /> Export JSONL
                    </button>
                    <button className="ghost" onClick={() => downloadAudit("csv")}>
                      <Download size={14} /> Export CSV
                    </button>
                  </div>
                </div>
                <div className="side-note">
                  Audit exports are accompanied by the <code>X-PentaGen-Audit-Digest</code> header validating the exact SHA-256 hash of the archive.
                </div>
              </div>
            )}
          </>
        )}

        <footer>PentaGen v1.0 · Hybrid Autonomous Security Assessment · All Rights Reserved</footer>
      </section>
    </main>
  );
}
