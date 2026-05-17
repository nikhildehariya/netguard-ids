import { useState, useEffect, useRef, useCallback } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

const API = "http://localhost:8080";

const COLORS = {
  NORMAL: "#22d3a0",
  BRUTE_FORCE: "#f97316",
  DOS_DDOS: "#ef4444",
  WEB_ATTACK: "#a78bfa",
  INFILTRATION: "#ec4899",
};

const SEV_COLOR = { none: "#22d3a0", high: "#f97316", critical: "#ef4444" };

const PRESETS = {
  "DoS GoldenEye": { "Dst Port": 80, "Protocol": 6, "Flow Duration": 6010454, "Tot Fwd Pkts": 4, "Tot Bwd Pkts": 4, "TotLen Fwd Pkts": 285, "TotLen Bwd Pkts": 972, "Fwd Pkt Len Max": 285, "Fwd Pkt Len Min": 0, "Fwd Pkt Len Mean": 71.25, "Fwd Pkt Len Std": 142.5, "Bwd Pkt Len Max": 972, "Bwd Pkt Len Min": 0, "Bwd Pkt Len Mean": 243.0, "Bwd Pkt Len Std": 486.0, "Flow Byts/s": 209.13, "Flow Pkts/s": 1.33, "Flow IAT Mean": 858636.28, "Flow IAT Std": 1865827.78, "Flow IAT Max": 5004855, "Flow IAT Min": 6, "Fwd IAT Tot": 1005599, "Fwd IAT Mean": 335199.66, "Fwd IAT Std": 576060.72, "Fwd IAT Max": 1000372, "Fwd IAT Min": 316, "Bwd IAT Tot": 6010448, "Bwd IAT Mean": 2003482.66, "Bwd IAT Std": 2646706.61, "Bwd IAT Max": 5005181, "Bwd IAT Min": 5229, "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0, "Fwd Header Len": 136, "Bwd Header Len": 136, "Fwd Pkts/s": 0.66, "Bwd Pkts/s": 0.66, "Pkt Len Min": 0, "Pkt Len Max": 972, "Pkt Len Mean": 139.66, "Pkt Len Std": 326.04, "Pkt Len Var": 106306.0, "FIN Flag Cnt": 0, "SYN Flag Cnt": 0, "RST Flag Cnt": 0, "PSH Flag Cnt": 1, "ACK Flag Cnt": 0, "URG Flag Cnt": 0, "CWE Flag Count": 0, "ECE Flag Cnt": 0, "Down/Up Ratio": 1, "Pkt Size Avg": 157.12, "Fwd Seg Size Avg": 71.25, "Bwd Seg Size Avg": 243.0, "Subflow Fwd Pkts": 4, "Subflow Fwd Byts": 285, "Subflow Bwd Pkts": 4, "Subflow Bwd Byts": 972, "Init Fwd Win Byts": 26883, "Init Bwd Win Byts": 219, "Fwd Act Data Pkts": 1, "Fwd Seg Size Min": 32, "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0 },
  "Brute Force SSH": { "Dst Port": 21, "Protocol": 6, "Flow Duration": 19, "Tot Fwd Pkts": 1, "Tot Bwd Pkts": 1, "TotLen Fwd Pkts": 0, "TotLen Bwd Pkts": 0, "Fwd Pkt Len Max": 0, "Fwd Pkt Len Min": 0, "Fwd Pkt Len Mean": 0, "Fwd Pkt Len Std": 0, "Bwd Pkt Len Max": 0, "Bwd Pkt Len Min": 0, "Bwd Pkt Len Mean": 0, "Bwd Pkt Len Std": 0, "Flow Byts/s": 0, "Flow Pkts/s": 105263.157, "Flow IAT Mean": 19, "Flow IAT Std": 0, "Flow IAT Max": 19, "Flow IAT Min": 19, "Fwd IAT Tot": 19, "Fwd IAT Mean": 19, "Fwd IAT Std": 0, "Fwd IAT Max": 0, "Fwd IAT Min": 0, "Bwd IAT Tot": 0, "Bwd IAT Mean": 0, "Bwd IAT Std": 0, "Bwd IAT Max": 0, "Bwd IAT Min": 0, "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0, "Fwd Header Len": 40, "Bwd Header Len": 20, "Fwd Pkts/s": 52631.578, "Bwd Pkts/s": 52631.578, "Pkt Len Min": 0, "Pkt Len Max": 0, "Pkt Len Mean": 0, "Pkt Len Std": 0, "Pkt Len Var": 0, "FIN Flag Cnt": 0, "SYN Flag Cnt": 0, "RST Flag Cnt": 0, "PSH Flag Cnt": 1, "ACK Flag Cnt": 0, "URG Flag Cnt": 0, "CWE Flag Count": 0, "ECE Flag Cnt": 0, "Down/Up Ratio": 0, "Pkt Size Avg": 0, "Fwd Seg Size Avg": 0, "Bwd Seg Size Avg": 0, "Subflow Fwd Pkts": 1, "Subflow Fwd Byts": 0, "Subflow Bwd Pkts": 1, "Subflow Bwd Byts": 0, "Init Fwd Win Byts": 26883, "Init Bwd Win Byts": 0, "Fwd Act Data Pkts": 0, "Fwd Seg Size Min": 40, "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0 },
  "Normal HTTPS": { "Dst Port": 443, "Protocol": 6, "Flow Duration": 100000, "Tot Fwd Pkts": 10, "Tot Bwd Pkts": 10, "Flow Pkts/s": 0.5, "TotLen Fwd Pkts": 0, "TotLen Bwd Pkts": 0, "Fwd Pkt Len Max": 0, "Fwd Pkt Len Min": 0, "Fwd Pkt Len Mean": 0, "Fwd Pkt Len Std": 0, "Bwd Pkt Len Max": 0, "Bwd Pkt Len Min": 0, "Bwd Pkt Len Mean": 0, "Bwd Pkt Len Std": 0, "Flow Byts/s": 0, "Flow IAT Mean": 0, "Flow IAT Std": 0, "Flow IAT Max": 0, "Flow IAT Min": 0, "Fwd IAT Tot": 0, "Fwd IAT Mean": 0, "Fwd IAT Std": 0, "Fwd IAT Max": 0, "Fwd IAT Min": 0, "Bwd IAT Tot": 0, "Bwd IAT Mean": 0, "Bwd IAT Std": 0, "Bwd IAT Max": 0, "Bwd IAT Min": 0, "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0, "Fwd Header Len": 0, "Bwd Header Len": 0, "Fwd Pkts/s": 0, "Bwd Pkts/s": 0, "Pkt Len Min": 0, "Pkt Len Max": 0, "Pkt Len Mean": 0, "Pkt Len Std": 0, "Pkt Len Var": 0, "FIN Flag Cnt": 0, "SYN Flag Cnt": 0, "RST Flag Cnt": 0, "PSH Flag Cnt": 0, "ACK Flag Cnt": 0, "URG Flag Cnt": 0, "CWE Flag Count": 0, "ECE Flag Cnt": 0, "Down/Up Ratio": 0, "Pkt Size Avg": 0, "Fwd Seg Size Avg": 0, "Bwd Seg Size Avg": 0, "Subflow Fwd Pkts": 0, "Subflow Fwd Byts": 0, "Subflow Bwd Pkts": 0, "Subflow Bwd Byts": 0, "Init Fwd Win Byts": 0, "Init Bwd Win Byts": 0, "Fwd Act Data Pkts": 0, "Fwd Seg Size Min": 0, "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0 },
};

// ── Tiny reusable components ──────────────────────────────────

function Pill({ children, color = "#22d3a0" }) {
  return (
    <span style={{
      background: color + "22", color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 600,
      letterSpacing: "0.06em", textTransform: "uppercase", fontFamily: "monospace"
    }}>{children}</span>
  );
}

function StatCard({ label, value, sub, accent }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 12, padding: "18px 20px", position: "relative", overflow: "hidden"
    }}>
      {accent && <div style={{ position: "absolute", top: 0, left: 0, width: 3, height: "100%", background: accent, borderRadius: "12px 0 0 12px" }} />}
      <div style={{ fontSize: 11, color: "#64748b", letterSpacing: "0.1em", textTransform: "uppercase", fontWeight: 600, marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color: "#f1f5f9", fontFamily: "monospace", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: "#475569", marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function SectionTitle({ label, title }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 10, color: "#38bdf8", letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 17, fontWeight: 600, color: "#f1f5f9" }}>{title}</div>
    </div>
  );
}

function Divider() {
  return <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", margin: "28px 0" }} />;
}

// ── Login Screen ──────────────────────────────────────────────
// ── Token Storage ────────────────────────────────────────────
const TokenStore = {
  getAccess:   () => sessionStorage.getItem("ng_access"),
  getRefresh:  () => localStorage.getItem("ng_refresh"),
  getUser:     () => { try { return JSON.parse(sessionStorage.getItem("ng_user") || "null"); } catch { return null; } },
  set: (access, refresh, user) => {
    sessionStorage.setItem("ng_access", access);
    localStorage.setItem("ng_refresh", refresh);
    sessionStorage.setItem("ng_user", JSON.stringify(user));
  },
  clear: () => {
    sessionStorage.removeItem("ng_access");
    sessionStorage.removeItem("ng_user");
    localStorage.removeItem("ng_refresh");
  }
};

const ROLE_COLORS = { admin: "#ef4444", analyst: "#f97316", viewer: "#22d3a0" };
const ROLE_BADGES = { admin: "🛡️ Admin", analyst: "🔍 Analyst", viewer: "👁️ Viewer" };

function AuthScreen({ onLogin }) {
  const [mode, setMode] = useState("login"); // "login"
  const [form, setForm] = useState({ username: "", email: "", password: "", confirmPassword: "" });
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [locked, setLocked] = useState(false);

  const inp = (field) => ({
    value: form[field],
    onChange: e => setForm(p => ({ ...p, [field]: e.target.value })),
    onKeyDown: e => e.key === "Enter" && !locked && handleSubmit(),
    style: {
      width: "100%", background: "rgba(255,255,255,0.05)",
      border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10,
      padding: "12px 14px", color: "#f1f5f9", fontSize: 14, outline: "none",
      transition: "border-color 0.2s"
    }
  });

  const handleSubmit = async () => {
    setErr(""); setLoading(true);
    try {
      const res = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: form.username, password: form.password })
      });
      const data = await res.json();
      if (!res.ok) {
        setAttempts(a => a + 1);
        if (res.status === 423) { setLocked(true); setErr(data.detail); }
        else setErr(data.detail || "Invalid credentials");
        return;
      }
      TokenStore.set(data.access_token, data.refresh_token, data.user);
      onLogin(data.user);
    } catch {
      setErr("Cannot connect to API. Is the server running?");
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = { width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 10, padding: "12px 14px", color: "#f1f5f9", fontSize: 14, outline: "none" };
  const labelStyle = { fontSize: 11, color: "#64748b", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: 8, fontWeight: 600 };

  return (
    <div style={{ minHeight: "100vh", background: "linear-gradient(135deg, #020810 0%, #050f1e 50%, #020810 100%)", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "'Space Grotesk', system-ui, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #020810; }
        input:-webkit-autofill { -webkit-box-shadow: 0 0 0 1000px #0a1628 inset !important; -webkit-text-fill-color: #f1f5f9 !important; }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: #050f1e; } ::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 2px; }
        .auth-input:focus { border-color: rgba(14,165,233,0.5) !important; }
      `}</style>
      <div style={{ width: 420, padding: "0 20px" }}>

        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={{ width: 68, height: 68, borderRadius: 20, background: "linear-gradient(135deg, #0ea5e9, #2563eb)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 18px", boxShadow: "0 0 50px rgba(14,165,233,0.25)" }}>
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.02em" }}>NetGuard IDS</div>
          <div style={{ fontSize: 13, color: "#475569", marginTop: 6, letterSpacing: "0.02em" }}>IoT Intrusion Detection System v2.0</div>
        </div>

        {/* Card */}
        <div style={{ background: "rgba(10,22,40,0.8)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 24, padding: "32px 28px", backdropFilter: "blur(20px)", boxShadow: "0 20px 60px rgba(0,0,0,0.4)" }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9", marginBottom: 4 }}>Welcome back</div>
          <div style={{ fontSize: 13, color: "#475569", marginBottom: 28 }}>Sign in to your account to continue</div>

          {/* Lockout warning */}
          {locked && (
            <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 10, padding: "12px 14px", marginBottom: 16, fontSize: 13, color: "#f87171" }}>
              🔒 Account temporarily locked due to too many failed attempts.
            </div>
          )}

          {/* Attempts warning */}
          {attempts >= 3 && !locked && (
            <div style={{ background: "rgba(249,115,22,0.1)", border: "1px solid rgba(249,115,22,0.3)", borderRadius: 10, padding: "10px 14px", marginBottom: 16, fontSize: 12, color: "#fb923c" }}>
              ⚠️ {5 - attempts} attempts remaining before lockout
            </div>
          )}

          <div style={{ marginBottom: 16 }}>
            <label style={labelStyle}>Username</label>
            <input {...inp("username")} className="auth-input" placeholder="Enter username" style={inputStyle} />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={labelStyle}>Password</label>
            <div style={{ position: "relative" }}>
              <input {...inp("password")} type={showPass ? "text" : "password"} className="auth-input" placeholder="Enter password" style={{ ...inputStyle, paddingRight: 44 }} />
              <button onClick={() => setShowPass(s => !s)} style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "#475569", cursor: "pointer", fontSize: 16, padding: 4 }}>
                {showPass ? "🙈" : "👁️"}
              </button>
            </div>
          </div>

          {err && (
            <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 8, padding: "10px 14px", marginBottom: 16, fontSize: 13, color: "#f87171", textAlign: "center" }}>
              {err}
            </div>
          )}

          <button onClick={handleSubmit} disabled={loading || locked} style={{
            width: "100%", background: (loading || locked) ? "rgba(14,165,233,0.3)" : "linear-gradient(135deg, #0ea5e9, #2563eb)",
            border: "none", borderRadius: 12, padding: "14px", color: "white", fontSize: 14, fontWeight: 700,
            cursor: (loading || locked) ? "not-allowed" : "pointer", letterSpacing: "0.03em", transition: "all 0.2s",
            boxShadow: (loading || locked) ? "none" : "0 4px 20px rgba(14,165,233,0.3)"
          }}>
            {loading ? "Authenticating..." : locked ? "🔒 Locked" : "Sign In →"}
          </button>
        </div>

        {/* Role info */}
        <div style={{ marginTop: 20, background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)", borderRadius: 14, padding: "16px 20px" }}>
          <div style={{ fontSize: 11, color: "#334155", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600, marginBottom: 12 }}>Access Levels</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              { role: "admin",   perms: "Full access — users, block, reports, capture" },
              { role: "analyst", perms: "Monitor, capture, block, export reports" },
              { role: "viewer",  perms: "Read-only dashboard access" },
            ].map(({ role, perms }) => (
              <div key={role} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: ROLE_COLORS[role], background: ROLE_COLORS[role] + "20", border: `1px solid ${ROLE_COLORS[role]}40`, borderRadius: 4, padding: "2px 8px", letterSpacing: "0.06em", textTransform: "uppercase", flexShrink: 0 }}>{role}</span>
                <span style={{ fontSize: 11, color: "#475569" }}>{perms}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ textAlign: "center", marginTop: 16, fontSize: 11, color: "#1e3a5f" }}>
          Protected by JWT · bcrypt · Rate limiting
        </div>
      </div>
    </div>
  );
}

function LoginScreen({ onLogin }) { return <AuthScreen onLogin={onLogin} />; }

// ── Radar animation ───────────────────────────────────────────
function RadarPulse({ active }) {
  return (
    <div style={{ position: "relative", width: 48, height: 48, flexShrink: 0 }}>
      <div style={{
        width: 10, height: 10, borderRadius: "50%",
        background: active ? "#22d3a0" : "#475569",
        position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)",
        boxShadow: active ? "0 0 8px #22d3a0" : "none"
      }} />
      {active && [1, 2, 3].map(i => (
        <div key={i} style={{
          position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)",
          width: 10 + i * 12, height: 10 + i * 12, borderRadius: "50%",
          border: "1px solid #22d3a0",
          opacity: 0.15 / i,
          animation: `pulse-${i} 2s ease-out infinite`,
          animationDelay: `${i * 0.4}s`
        }} />
      ))}
    </div>
  );
}

// ── Users Panel (Admin only) ─────────────────────────────────
function UsersPanel({ token, currentUser }) {
  const [users, setUsers] = useState([]);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "viewer" });
  const [msg, setMsg] = useState("");
  const [loading, setLoading] = useState(false);

  const authHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  const loadUsers = async () => {
    const r = await fetch(`${API}/auth/users`, { headers: authHeaders }).catch(() => null);
    if (r?.ok) { const d = await r.json(); setUsers(d.users || []); }
  };

  useEffect(() => { loadUsers(); }, []);

  const createUser = async () => {
    setLoading(true);
    const r = await fetch(`${API}/auth/users`, { method: "POST", headers: authHeaders, body: JSON.stringify(form) }).catch(() => null);
    if (r?.ok) { const d = await r.json(); setMsg(d.message); setShowCreate(false); setForm({ username: "", email: "", password: "", role: "viewer" }); loadUsers(); }
    else { const d = await r?.json(); setMsg(d?.detail || "Failed"); }
    setLoading(false);
  };

  const changeRole = async (username, role) => {
    await fetch(`${API}/auth/users/${username}/role`, { method: "PATCH", headers: authHeaders, body: JSON.stringify({ role }) });
    loadUsers();
  };

  const toggleActive = async (username) => {
    await fetch(`${API}/auth/users/${username}/toggle`, { method: "PATCH", headers: authHeaders });
    loadUsers();
  };

  const deleteUser = async (username) => {
    if (!confirm(`Delete user "${username}"?`)) return;
    await fetch(`${API}/auth/users/${username}`, { method: "DELETE", headers: authHeaders });
    loadUsers();
  };

  const inputStyle = { width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, padding: "10px 12px", color: "#f1f5f9", fontSize: 13, outline: "none", marginBottom: 12 };
  const labelStyle = { fontSize: 11, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.08em", display: "block", marginBottom: 6, fontWeight: 600 };

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 11, color: "#38bdf8", letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>User Management</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9" }}>{users.length} Registered Users</div>
        </div>
        <button onClick={() => setShowCreate(s => !s)} style={{ background: "linear-gradient(135deg,#0ea5e9,#2563eb)", border: "none", borderRadius: 10, padding: "10px 20px", color: "white", fontSize: 13, fontWeight: 700, cursor: "pointer" }}>
          + Create User
        </button>
      </div>

      {msg && <div style={{ background: "rgba(34,211,160,0.1)", border: "1px solid rgba(34,211,160,0.2)", borderRadius: 8, padding: "10px 14px", marginBottom: 16, fontSize: 13, color: "#22d3a0" }}>{msg}</div>}

      {/* Create User Form */}
      {showCreate && (
        <div style={{ background: "rgba(10,22,40,0.8)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 16, padding: "24px", marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: "#f1f5f9", marginBottom: 20 }}>Create New User</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div><label style={labelStyle}>Username</label><input value={form.username} onChange={e => setForm(p => ({ ...p, username: e.target.value }))} placeholder="username" style={inputStyle} /></div>
            <div><label style={labelStyle}>Email</label><input value={form.email} onChange={e => setForm(p => ({ ...p, email: e.target.value }))} placeholder="user@example.com" type="email" style={inputStyle} /></div>
            <div><label style={labelStyle}>Password</label><input value={form.password} onChange={e => setForm(p => ({ ...p, password: e.target.value }))} placeholder="min 8 chars" type="password" style={inputStyle} /></div>
            <div>
              <label style={labelStyle}>Role</label>
              <select value={form.role} onChange={e => setForm(p => ({ ...p, role: e.target.value }))} style={{ ...inputStyle, colorScheme: "dark" }}>
                <option value="viewer">Viewer — Read only</option>
                <option value="analyst">Analyst — Monitor + Block</option>
                <option value="admin">Admin — Full access</option>
              </select>
            </div>
          </div>
          <div style={{ display: "flex", gap: 10, marginTop: 4 }}>
            <button onClick={() => setShowCreate(false)} style={{ flex: 1, padding: "10px", borderRadius: 8, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "#64748b", fontSize: 13, cursor: "pointer" }}>Cancel</button>
            <button onClick={createUser} disabled={loading} style={{ flex: 2, padding: "10px", borderRadius: 8, background: "linear-gradient(135deg,#0ea5e9,#2563eb)", border: "none", color: "white", fontSize: 13, fontWeight: 700, cursor: "pointer" }}>
              {loading ? "Creating..." : "Create User"}
            </button>
          </div>
        </div>
      )}

      {/* Users Table */}
      <div style={{ background: "rgba(10,22,40,0.6)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 16, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr 120px 100px 160px", padding: "12px 20px", borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(0,0,0,0.2)" }}>
          {["USERNAME", "EMAIL", "ROLE", "STATUS", "ACTIONS"].map(h => (
            <div key={h} style={{ fontSize: 10, fontWeight: 700, color: "#334155", letterSpacing: "0.1em" }}>{h}</div>
          ))}
        </div>
        {users.map((u, i) => (
          <div key={u.id} style={{ display: "grid", gridTemplateColumns: "1fr 1.5fr 120px 100px 160px", padding: "14px 20px", borderBottom: i < users.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", alignItems: "center", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "#f1f5f9" }}>
              {u.username}
              {u.username === currentUser?.username && <span style={{ fontSize: 10, color: "#38bdf8", marginLeft: 6 }}>(you)</span>}
            </div>
            <div style={{ fontSize: 12, color: "#475569", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.email}</div>
            <div>
              {u.username === "admin" ? (
                <span style={{ fontSize: 10, fontWeight: 700, color: ROLE_COLORS[u.role], background: ROLE_COLORS[u.role] + "20", borderRadius: 4, padding: "3px 8px", textTransform: "uppercase", letterSpacing: "0.06em" }}>{u.role}</span>
              ) : (
                <select value={u.role} onChange={e => changeRole(u.username, e.target.value)} style={{ background: "#0a1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 6, padding: "4px 8px", color: ROLE_COLORS[u.role] || "#94a3b8", fontSize: 11, cursor: "pointer", colorScheme: "dark" }}>
                  <option value="viewer">Viewer</option>
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              )}
            </div>
            <div>
              <span style={{ fontSize: 10, fontWeight: 700, color: u.is_active ? "#22d3a0" : "#ef4444", background: u.is_active ? "rgba(34,211,160,0.1)" : "rgba(239,68,68,0.1)", borderRadius: 4, padding: "3px 8px", textTransform: "uppercase" }}>
                {u.is_active ? "Active" : "Disabled"}
              </span>
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              {u.username !== "admin" && u.username !== currentUser?.username && (
                <>
                  <button onClick={() => toggleActive(u.username)} style={{ fontSize: 11, padding: "5px 10px", borderRadius: 6, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "#94a3b8", cursor: "pointer" }}>
                    {u.is_active ? "Disable" : "Enable"}
                  </button>
                  <button onClick={() => deleteUser(u.username)} style={{ fontSize: 11, padding: "5px 10px", borderRadius: 6, background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)", color: "#f87171", cursor: "pointer" }}>
                    Delete
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}


// ── Main Dashboard ────────────────────────────────────────────
export default function App() {
  const [auth, setAuth] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState({ total: 0, by_class: {}, attack_rate: 0 });
  const [interfaces, setInterfaces] = useState([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [captureMode, setCaptureMode] = useState("wifi"); // "wifi" | "span" | "manual"

  // Pre-configured interfaces — update SPAN_GUID when you get it from college
  const WIFI_GUID = "\\Device\\NPF_{0F823FF5-FB72-48B3-B29B-6BC2C635ED21}";
  const SPAN_GUID = "\\Device\\NPF_{9500E94C-87BD-4320-BD21-1D31761B841F}"; // ← replace this at college
  const [captureRunning, setCaptureRunning] = useState(false);
  const [captureLog, setCaptureLog] = useState("");
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [blockInput, setBlockInput] = useState("");
  const [blockReason, setBlockReason] = useState("");
  const [blockTTL, setBlockTTL] = useState("");
  const [blockAudit, setBlockAudit] = useState([]);
  const [showAudit, setShowAudit] = useState(false);
  const [devices, setDevices] = useState([]);
  const [devicesLoading, setDevicesLoading] = useState(false);
  const [devicesScanTime, setDevicesScanTime] = useState(null);
  const [valPreset, setValPreset] = useState("DoS GoldenEye");
  const [valResult, setValResult] = useState(null);
  const [valLoading, setValLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [pdfBytes, setPdfBytes] = useState(null);
  const [pdfName, setPdfName] = useState("report.pdf");
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportMode, setReportMode] = useState("last"); // "last" | "hours" | "range"
  const [reportHours, setReportHours] = useState("6");
  const [reportStart, setReportStart] = useState("");
  const [reportEnd, setReportEnd] = useState("");

  const showToast = (msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const fetchAll = useCallback(async () => {
    try {
      const token = TokenStore.getAccess();
      const authH = { Authorization: `Bearer ${token}` };
      const [hRes, sRes, cRes, bRes, iRes] = await Promise.all([
        fetch(`${API}/history?limit=1000`, { headers: authH }).then(r => r.json()).catch(() => []),
        fetch(`${API}/stats`, { headers: authH }).then(r => r.json()).catch(() => ({})),
        fetch(`${API}/capture/status`, { headers: authH }).then(r => r.json()).catch(() => ({})),
        fetch(`${API}/blocked-ips`, { headers: authH }).then(r => r.json()).catch(() => ({ items: [] })),
        fetch(`${API}/capture/interfaces`, { headers: authH }).then(r => r.json()).catch(() => ({ interfaces: [] })),
      ]);
      setApiOnline(true);
      setHistory(Array.isArray(hRes) ? hRes : []);
      setStats(sRes || { total: 0, by_class: {}, attack_rate: 0 });
      setCaptureRunning(cRes?.running || false);
      setCaptureLog(cRes?.last_log || "");
      setBlockedIPs(bRes?.items || []);
      const ifaces = (iRes?.interfaces || []).map(i => typeof i === "string" ? { id: i, label: i } : i);
      setInterfaces(ifaces);
      if (ifaces.length && !selectedIface) setSelectedIface(ifaces[0].id);
    } catch {
      setApiOnline(false);
    }
  }, [selectedIface]);

  useEffect(() => {
    if (!auth) return;
    fetchAll();
    const t = setInterval(fetchAll, 8000);
    return () => clearInterval(t);
  }, [auth, fetchAll]);

  // Auto-login if valid session exists
  useEffect(() => {
    const user = TokenStore.getUser();
    const token = TokenStore.getAccess();
    if (user && token) {
      setCurrentUser(user);
      setAuth(true);
    }
  }, []);

  // Derived data
  const bc = stats.by_class || {};
  const attacks = history.filter(r => r.prediction !== "NORMAL");
  const timelineData = (() => {
    if (!history.length) return [];
    const buckets = {};
    history.forEach(r => {
      const t = new Date(r.timestamp);
      const key = `${t.getHours()}:${String(t.getMinutes()).padStart(2, "0")}`;
      if (!buckets[key]) buckets[key] = { time: key, NORMAL: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, WEB_ATTACK: 0, INFILTRATION: 0 };
      buckets[key][r.prediction] = (buckets[key][r.prediction] || 0) + 1;
    });
    return Object.values(buckets).slice(-20);
  })();

  const pieData = Object.entries(bc).map(([name, value]) => ({ name, value }));

  // Capture control
  const toggleCapture = async () => {
    if (captureRunning) {
      const r = await fetch(`${API}/capture/stop`, { method: "POST", headers: { Authorization: `Bearer ${TokenStore.getAccess()}` } }).then(x => x.json()).catch(() => ({}));
      if (r.stopped) { setCaptureRunning(false); showToast("Capture stopped"); }
      else showToast(r.message || "Failed", "error");
    } else {
      if (!selectedIface) return showToast("No interface selected", "error");
      const r = await fetch(`${API}/capture/start`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${TokenStore.getAccess()}` }, body: JSON.stringify({ interface: selectedIface, packet_limit: 0 }) }).then(x => x.json()).catch(() => ({}));
      if (r.started) { setCaptureRunning(true); showToast("Capture started on " + selectedIface); }
      else showToast(r.message || "Failed to start", "error");
    }
  };

  const blockIP = async () => {
    if (!blockInput.trim()) return;
    const token = TokenStore.getAccess();
    const r = await fetch(`${API}/blocked-ips`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ ip: blockInput, reason: blockReason || "Manual block from dashboard", ttl_seconds: blockTTL || null, layer: "firewall" })
    }).then(x => x.json()).catch(() => ({}));
    if (r.detail) showToast(r.detail, "error");
    else showToast(r.message || "Blocked");
    setBlockInput(""); setBlockReason(""); fetchAll();
  };

  const unblockIP = async (ip) => {
    const token = TokenStore.getAccess();
    const r = await fetch(`${API}/blocked-ips/${ip}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` }
    }).then(x => x.json()).catch(() => ({}));
    if (r.detail) showToast(r.detail, "error");
    else showToast(`Unblocked ${ip}`);
    fetchAll();
  };

  const runValidation = async () => {
    setValLoading(true); setValResult(null);
    try {
      const r = await fetch(`${API}/predict`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...PRESETS[valPreset], test_mode: true }) }).then(x => x.json());
      setValResult(r);
    } catch { showToast("API unreachable", "error"); }
    setValLoading(false);
  };

  const handleCaptureMode = (mode) => {
    setCaptureMode(mode);
    if (mode === "wifi") setSelectedIface(WIFI_GUID);
    else if (mode === "span") setSelectedIface(SPAN_GUID);
    // manual: let user pick from dropdown
  };

  const generateReport = async () => {
    try {
      let url = `${API}/reports/export?limit=500`;
      if (reportMode === "hours" && reportHours) {
        url = `${API}/reports/export?hours=${reportHours}`;
      } else if (reportMode === "range" && reportStart && reportEnd) {
        url = `${API}/reports/export?start=${encodeURIComponent(reportStart)}&end=${encodeURIComponent(reportEnd)}`;
      }
      const r = await fetch(url, { headers: { Authorization: `Bearer ${TokenStore.getAccess()}` } });
      if (r.ok) {
        const blob = await r.blob();
        const objUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        const cd = r.headers.get("content-disposition") || "";
        a.download = cd.includes("filename=") ? cd.split("filename=")[1].replace(/"/g, "") : "netguard_report.pdf";
        a.href = objUrl; a.click();
        showToast("Report downloaded"); setShowReportModal(false);
      }
    } catch { showToast("Report failed", "error"); }
  };

  if (!auth) return <LoginScreen onLogin={(user) => { setCurrentUser(user); setAuth(true); }} />;

  const TABS = [
    { id: "overview",  icon: "⌂", label: "Overview" },
    { id: "capture",   icon: "⚡", label: "Capture" },
    { id: "incidents", icon: "△", label: "Incidents" },
    { id: "validate",  icon: "◎", label: "Validate" },
    { id: "blocklist", icon: "⊘", label: "Blocklist" },
    ...(currentUser?.role === "admin" ? [{ id: "users", icon: "👥", label: "Users" }] : []),
  ];

  return (
    <div style={{ minHeight: "100vh", background: "#020810", color: "#e2e8f0", fontFamily: "'Space Grotesk', system-ui, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #020810; }
        select { appearance: none; cursor: pointer; background: #0a1628; color: #f1f5f9; }
        button { cursor: pointer; font-family: inherit; }
        input { font-family: inherit; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #050f1e; }
        ::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 2px; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes scanline { 0% { top: -2px; } 100% { top: 100%; } }
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        .tab-btn { background: none; border: none; padding: 8px 16px; color: #475569; font-size: 13px; font-weight: 500; border-radius: 8px; transition: all 0.15s; letter-spacing: 0.03em; }
        .tab-btn:hover { color: #94a3b8; background: rgba(255,255,255,0.04); }
        .tab-btn.active { color: #38bdf8; background: rgba(56,189,248,0.1); }
        .action-btn { background: rgba(14,165,233,0.12); border: 1px solid rgba(14,165,233,0.25); color: #38bdf8; border-radius: 8px; padding: 9px 16px; font-size: 13px; font-weight: 600; transition: all 0.15s; letter-spacing: 0.02em; }
        .action-btn:hover { background: rgba(14,165,233,0.2); border-color: rgba(14,165,233,0.4); }
        .danger-btn { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25); color: #f87171; border-radius: 8px; padding: 9px 16px; font-size: 13px; font-weight: 600; transition: all 0.15s; }
        .danger-btn:hover { background: rgba(239,68,68,0.18); }
        .success-btn { background: rgba(34,211,160,0.1); border: 1px solid rgba(34,211,160,0.25); color: #22d3a0; border-radius: 8px; padding: 9px 16px; font-size: 13px; font-weight: 600; transition: all 0.15s; }
        .success-btn:hover { background: rgba(34,211,160,0.18); }
        .dark-input { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px 14px; color: #f1f5f9; font-size: 13px; outline: none; width: 100%; transition: border-color 0.15s; }
        .dark-input:focus { border-color: rgba(56,189,248,0.4); }

select { color-scheme: dark; } select.dark-input { background: #0a1628 !important; color: #f1f5f9 !important; } select.dark-input option { background: #0a1628 !important; color: #f1f5f9 !important; }
        .panel { background: rgba(255,255,255,0.025); border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 20px 22px; }
      `}</style>

      {/* Toast */}
      {toast && (
        <div style={{
          position: "fixed", top: 20, right: 20, zIndex: 9999,
          background: toast.type === "error" ? "rgba(239,68,68,0.95)" : "rgba(34,211,160,0.95)",
          color: "white", padding: "12px 20px", borderRadius: 10, fontSize: 13, fontWeight: 600,
          animation: "fadeIn 0.2s ease", boxShadow: "0 8px 32px rgba(0,0,0,0.4)"
        }}>{toast.msg}</div>
      )}

      {/* Sidebar */}
      <div style={{
        position: "fixed", left: 0, top: 0, width: 220, height: "100vh",
        background: "rgba(5,15,30,0.95)", borderRight: "1px solid rgba(255,255,255,0.06)",
        display: "flex", flexDirection: "column", zIndex: 100, backdropFilter: "blur(20px)"
      }}>
        {/* Logo */}
        <div style={{ padding: "24px 20px 20px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: "linear-gradient(135deg, #0ea5e9, #2563eb)",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "0 0 20px rgba(14,165,233,0.25)", flexShrink: 0
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.01em" }}>NetGuard</div>
              <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.08em" }}>IDS v2.0</div>
            </div>
          </div>
        </div>

        {/* API Status */}
        <div style={{ padding: "0 16px 16px" }}>
          <div style={{
            background: apiOnline ? "rgba(34,211,160,0.08)" : "rgba(239,68,68,0.08)",
            border: `1px solid ${apiOnline ? "rgba(34,211,160,0.2)" : "rgba(239,68,68,0.2)"}`,
            borderRadius: 8, padding: "8px 12px", display: "flex", alignItems: "center", gap: 8
          }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: apiOnline ? "#22d3a0" : "#ef4444", animation: apiOnline ? "blink 2s infinite" : "none" }} />
            <span style={{ fontSize: 12, color: apiOnline ? "#22d3a0" : "#f87171", fontWeight: 600 }}>
              {apiOnline ? "API Online" : "API Offline"}
            </span>
          </div>
        </div>

        <div style={{ height: 1, background: "rgba(255,255,255,0.05)", margin: "0 16px" }} />

        {/* Nav */}
        <nav style={{ padding: "12px 10px", flex: 1 }}>
          {[
            { id: "overview", icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6", label: "Overview" },
            { id: "capture", icon: "M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z", label: "Capture" },
            { id: "incidents", icon: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z", label: "Incidents" },
            { id: "validate", icon: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z", label: "Validate" },
            { id: "blocklist", icon: "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636", label: "Blocklist" },
            { id: "devices", icon: "M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18", label: "Devices" },
            ...(currentUser?.role === "admin" ? [{ id: "users", icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z", label: "Users" }] : []),
          ].map(({ id, icon, label }) => (
            <button key={id} onClick={() => setActiveTab(id)} style={{
              width: "100%", display: "flex", alignItems: "center", gap: 10, padding: "9px 12px",
              borderRadius: 8, border: "none", background: activeTab === id ? "rgba(56,189,248,0.1)" : "none",
              color: activeTab === id ? "#38bdf8" : "#475569", fontSize: 13, fontWeight: 500,
              marginBottom: 2, transition: "all 0.15s", textAlign: "left"
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d={icon} />
              </svg>
              {label}
            </button>
          ))}
        </nav>

        {/* Capture status */}
        <div style={{ padding: "0 16px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 12px", background: "rgba(255,255,255,0.03)", borderRadius: 8 }}>
            <RadarPulse active={captureRunning} />
            <div>
              <div style={{ fontSize: 11, color: captureRunning ? "#22d3a0" : "#475569", fontWeight: 600 }}>
                {captureRunning ? "Capturing" : "Idle"}
              </div>
              <div style={{ fontSize: 10, color: "#334155" }}>Packet capture</div>
            </div>
          </div>
        </div>

        {/* Threat legend */}
        <div style={{ padding: "0 16px 16px" }}>
          <div style={{ fontSize: 10, color: "#334155", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 10 }}>Threat Classes</div>
          {Object.entries(COLORS).map(([k, c]) => (
            <div key={k} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7 }}>
              <div style={{ width: 6, height: 6, borderRadius: "50%", background: c, flexShrink: 0 }} />
              <span style={{ fontSize: 11, color: "#475569" }}>{k.replace("_", " ")}</span>
            </div>
          ))}
        </div>

        <div style={{ height: 1, background: "rgba(255,255,255,0.05)", margin: "0 16px 12px" }} />
        <div style={{ padding: "0 16px 20px" }}>
          {currentUser && (
            <div style={{ marginBottom: 8, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, padding: "10px 12px" }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#f1f5f9", marginBottom: 3 }}>👤 {currentUser.username}</div>
              <span style={{ fontSize: 10, fontWeight: 700, color: ROLE_COLORS[currentUser.role] || "#64748b", background: (ROLE_COLORS[currentUser.role] || "#64748b") + "20", borderRadius: 4, padding: "2px 7px", letterSpacing: "0.06em", textTransform: "uppercase" }}>
                {currentUser.role}
              </span>
            </div>
          )}
          <button onClick={() => {
            const rt = TokenStore.getRefresh();
            if (rt) fetch(`${API}/auth/logout`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: rt }) }).catch(() => {});
            TokenStore.clear();
            setAuth(false);
            setCurrentUser(null);
          }} style={{ width: "100%", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.15)", borderRadius: 8, padding: "9px", color: "#f87171", fontSize: 12, fontWeight: 600, transition: "all 0.15s", cursor: "pointer" }}>
            Sign Out
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ marginLeft: 220, padding: "28px 32px", minHeight: "100vh" }}>

        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 32 }}>
          <div>
            <div style={{ fontSize: 10, color: "#38bdf8", letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700, marginBottom: 6 }}>Security Operations Dashboard</div>
            <h1 style={{ fontSize: 28, fontWeight: 700, color: "#f1f5f9", letterSpacing: "-0.02em", lineHeight: 1.1 }}>
              IoT Intrusion Detection
            </h1>
            <div style={{ fontSize: 13, color: "#475569", marginTop: 6 }}>
              {new Date().toLocaleString()} · {stats.total?.toLocaleString() || 0} events tracked · {(stats.attack_rate || 0).toFixed(1)}% attack pressure
            </div>
          </div>
          <button onClick={() => setShowReportModal(true)} className="action-btn" style={{ flexShrink: 0 }}>
            ↓ Export Report
          </button>
        </div>

        {/* ── OVERVIEW TAB ── */}
        {activeTab === "overview" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            {/* Metrics */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12, marginBottom: 24 }}>
              <StatCard label="Total Events" value={(stats.total || 0).toLocaleString()} accent="#38bdf8" />
              <StatCard label="Attack Rate" value={`${(stats.attack_rate || 0).toFixed(1)}%`} accent="#f97316" />
              <StatCard label="DoS / DDoS" value={bc.DOS_DDOS || 0} accent="#ef4444" />
              <StatCard label="Brute Force" value={bc.BRUTE_FORCE || 0} accent="#f97316" />
              <StatCard label="Web Attacks" value={bc.WEB_ATTACK || 0} accent="#a78bfa" />
              <StatCard label="Infiltration" value={bc.INFILTRATION || 0} accent="#ec4899" />
            </div>

            {/* Charts row */}
            <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 16 }}>
              <div className="panel">
                <SectionTitle label="Traffic Analytics" title="Live Timeline" />
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={timelineData}>
                    <defs>
                      {Object.entries(COLORS).map(([k, c]) => (
                        <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor={c} stopOpacity={0.3} />
                          <stop offset="95%" stopColor={c} stopOpacity={0} />
                        </linearGradient>
                      ))}
                    </defs>
                    <XAxis dataKey="time" tick={{ fill: "#334155", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "#334155", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 }} />
                    {Object.entries(COLORS).map(([k, c]) => (
                      <Area key={k} type="monotone" dataKey={k} stroke={c} strokeWidth={1.5} fill={`url(#g-${k})`} dot={false} />
                    ))}
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
                <SectionTitle label="Distribution" title="By Class" />
                <div style={{ flex: 1, display: "flex", alignItems: "center" }}>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={pieData.length ? pieData : [{ name: "NORMAL", value: 1 }]}
                        cx="50%" cy="50%" innerRadius={55} outerRadius={80} dataKey="value" stroke="none">
                        {(pieData.length ? pieData : [{ name: "NORMAL" }]).map((e, i) => (
                          <Cell key={i} fill={COLORS[e.name] || "#334155"} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
                  {Object.entries(COLORS).map(([k, c]) => (
                    <div key={k} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                      <div style={{ width: 6, height: 6, borderRadius: "50%", background: c }} />
                      <span style={{ fontSize: 10, color: "#475569" }}>{k.replace("_", " ")}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Recent attacks */}
            <div className="panel">
              <SectionTitle label="Incident Feed" title="Recent Attack Events" />
              {attacks.length === 0 ? (
                <div style={{ color: "#22d3a0", fontSize: 13, padding: "12px 0" }}>✓ Network is clean — no attacks detected</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {attacks.slice(0, 8).map((r, i) => (
                    <div key={i} style={{
                      display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 14px",
                      background: "rgba(255,255,255,0.02)", borderRadius: 8,
                      borderLeft: `3px solid ${SEV_COLOR[r.severity] || "#475569"}`
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        <Pill color={COLORS[r.prediction]}>{r.prediction?.replace("_", " ")}</Pill>
                        <span style={{ fontSize: 12, color: "#64748b" }}>{r.source_ip || "unknown"}</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                        <span style={{ fontSize: 12, color: SEV_COLOR[r.severity], fontFamily: "monospace" }}>{(r.confidence * 100).toFixed(1)}%</span>
                        <span style={{ fontSize: 11, color: "#334155", fontFamily: "monospace" }}>{String(r.timestamp || "").slice(11, 19)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── CAPTURE TAB ── */}
        {activeTab === "capture" && (
          <div style={{ animation: "fadeIn 0.3s ease", maxWidth: 700 }}>
            <div className="panel" style={{ marginBottom: 16 }}>
              <SectionTitle label="Live Capture" title="Capture Mode" />

              {/* Mode Selector */}
              <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                {[
                  { key: "wifi", label: "📶 WiFi Monitor", desc: "Killer Wi-Fi 6E" },
                  { key: "span", label: "🔌 SPAN / Ethernet", desc: "Switch mirror port" },
                  { key: "manual", label: "⚙️ Manual", desc: "Choose interface" },
                ].map(({ key, label, desc }) => (
                  <button key={key} onClick={() => handleCaptureMode(key)} style={{
                    flex: 1, padding: "10px 8px", borderRadius: 10, cursor: "pointer",
                    background: captureMode === key ? "rgba(14,165,233,0.15)" : "rgba(255,255,255,0.03)",
                    border: captureMode === key ? "1px solid rgba(14,165,233,0.5)" : "1px solid rgba(255,255,255,0.07)",
                    transition: "all 0.15s", textAlign: "center"
                  }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: captureMode === key ? "#38bdf8" : "#64748b" }}>{label}</div>
                    <div style={{ fontSize: 10, color: captureMode === key ? "#0ea5e9" : "#334155", marginTop: 2 }}>{desc}</div>
                  </button>
                ))}
              </div>

              {/* SPAN not configured warning */}
              {captureMode === "span" && selectedIface === "SPAN_GUID_PLACEHOLDER" && (
                <div style={{ background: "rgba(249,115,22,0.08)", border: "1px solid rgba(249,115,22,0.2)", borderRadius: 8, padding: "10px 14px", marginBottom: 12, fontSize: 12, color: "#f97316" }}>
                  ⚠️ SPAN GUID not configured yet — update <code style={{ color: "#fbbf24" }}>SPAN_GUID</code> in App.jsx at college
                </div>
              )}

              {/* Interface dropdown — only in manual mode */}
              <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
                {captureMode === "manual" ? (
                  <select value={selectedIface} onChange={e => setSelectedIface(e.target.value)}
                    className="dark-input" style={{ flex: 1 }}>
                    {interfaces.map(i => (
                      <option key={i.id} value={i.id}>{i.label || i.id}</option>
                    ))}
                  </select>
                ) : (
                  <div style={{ flex: 1, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 8, padding: "10px 14px", fontSize: 12, color: "#475569", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {selectedIface || "No interface selected"}
                  </div>
                )}
                <button onClick={toggleCapture}
                  className={captureRunning ? "danger-btn" : "success-btn"}
                  style={{ flexShrink: 0, padding: "10px 24px" }}>
                  {captureRunning ? "⏹ Stop" : "▶ Start"}
                </button>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", background: "rgba(255,255,255,0.02)", borderRadius: 10 }}>
                <RadarPulse active={captureRunning} />
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: captureRunning ? "#22d3a0" : "#475569" }}>
                    {captureRunning ? "Capture Active" : "Capture Stopped"}
                  </div>
                  {captureLog && <div style={{ fontSize: 11, color: "#334155", marginTop: 4, fontFamily: "monospace" }}>{captureLog.split("\n").slice(-1)[0]}</div>}
                </div>
              </div>
            </div>

            <div className="panel">
              <SectionTitle label="Statistics" title="Session Summary" />
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                <StatCard label="Flows Analyzed" value={(stats.total || 0).toLocaleString()} />
                <StatCard label="Attacks Detected" value={attacks.length} accent="#ef4444" />
                <StatCard label="Attack Rate" value={`${(stats.attack_rate || 0).toFixed(1)}%`} accent="#f97316" />
              </div>
            </div>
          </div>
        )}

        {/* ── INCIDENTS TAB ── */}
        {activeTab === "incidents" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <div className="panel">
              <SectionTitle label="Incident Feed" title={`All Attack Events (${attacks.length})`} />
              {attacks.length === 0 ? (
                <div style={{ color: "#22d3a0", fontSize: 13, padding: "20px 0", textAlign: "center" }}>✓ No attacks detected — network is clean</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {attacks.map((r, i) => (
                    <div key={i} style={{
                      display: "grid", gridTemplateColumns: "1fr 1fr 80px 80px 120px 100px", gap: 12,
                      padding: "11px 14px", background: "rgba(255,255,255,0.02)", borderRadius: 8,
                      borderLeft: `3px solid ${SEV_COLOR[r.severity] || "#475569"}`, alignItems: "center"
                    }}>
                      <Pill color={COLORS[r.prediction]}>{r.prediction?.replace("_", " ")}</Pill>
                      <span style={{ fontSize: 12, color: "#64748b", fontFamily: "monospace" }}>{r.source_ip || "—"}</span>
                      <span style={{ fontSize: 12, color: SEV_COLOR[r.severity], fontFamily: "monospace", fontWeight: 600 }}>{(r.confidence * 100).toFixed(1)}%</span>
                      <Pill color={SEV_COLOR[r.severity]}>{r.severity?.toUpperCase()}</Pill>
                      <span style={{ fontSize: 11, color: "#334155", fontFamily: "monospace" }}>{String(r.timestamp || "").slice(0, 19).replace("T", " ")}</span>
                      {(currentUser?.role === "admin" || currentUser?.role === "analyst") && r.source_ip && r.source_ip !== "unknown" ? (
                        <button onClick={async () => {
                          const token = TokenStore.getAccess();
                          const res = await fetch(`${API}/blocked-ips`, {
                            method: "POST",
                            headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
                            body: JSON.stringify({ ip: r.source_ip, reason: `Auto-block: ${r.prediction} detected (${(r.confidence*100).toFixed(1)}%)`, layer: "firewall" })
                          }).then(x => x.json()).catch(() => ({}));
                          showToast(res.message || res.detail || "Done");
                          fetchAll();
                        }} style={{
                          fontSize: 11, padding: "5px 10px", borderRadius: 6, cursor: "pointer", fontWeight: 700,
                          background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)",
                          color: "#f87171", transition: "all 0.15s"
                        }}>🚫 Block IP</button>
                      ) : <span />}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── VALIDATE TAB ── */}
        {activeTab === "validate" && (
          <div style={{ animation: "fadeIn 0.3s ease", maxWidth: 700 }}>
            <div className="panel">
              <SectionTitle label="Classifier Validation" title="Run Preset Attack" />
              <div style={{ display: "flex", gap: 12, marginBottom: 20 }}>
                <select value={valPreset} onChange={e => setValPreset(e.target.value)} className="dark-input" style={{ flex: 1 }}>
                  {Object.keys(PRESETS).map(k => <option key={k} value={k}>{k}</option>)}
                </select>
                <button onClick={runValidation} disabled={valLoading} className="action-btn" style={{ flexShrink: 0, padding: "10px 24px" }}>
                  {valLoading ? "Running..." : "⚡ Run"}
                </button>
              </div>

              <div style={{ fontSize: 12, color: "#334155", fontFamily: "monospace", marginBottom: valResult ? 20 : 0 }}>
                Fields: {Object.keys(PRESETS[valPreset]).length} · Test mode: enabled
              </div>

              {valResult && (
                <div style={{ marginTop: 20 }}>
                  <div style={{
                    padding: "14px 18px", borderRadius: 10, marginBottom: 20,
                    background: `${SEV_COLOR[valResult.severity] || "#22d3a0"}18`,
                    border: `1px solid ${SEV_COLOR[valResult.severity] || "#22d3a0"}44`
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <Pill color={COLORS[valResult.prediction] || "#22d3a0"}>{valResult.prediction?.replace("_", " ")}</Pill>
                      <span style={{ fontSize: 13, color: "#94a3b8" }}>
                        Confidence: <strong style={{ color: "#f1f5f9", fontFamily: "monospace" }}>{((valResult.confidence || 0) * 100).toFixed(1)}%</strong>
                      </span>
                      <Pill color={SEV_COLOR[valResult.severity]}>{valResult.severity?.toUpperCase()}</Pill>
                    </div>
                  </div>

                  <div style={{ fontSize: 11, color: "#475569", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 12 }}>Score Breakdown</div>
                  {Object.entries(valResult.all_scores || {}).map(([label, score]) => (
                    <div key={label} style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
                      <div style={{ width: 120, fontSize: 12, color: "#64748b" }}>{label.replace("_", " ")}</div>
                      <div style={{ flex: 1, background: "rgba(255,255,255,0.06)", borderRadius: 4, height: 6 }}>
                        <div style={{ width: `${score * 100}%`, background: COLORS[label] || "#475569", height: 6, borderRadius: 4, transition: "width 0.5s ease" }} />
                      </div>
                      <div style={{ width: 48, textAlign: "right", fontSize: 12, color: COLORS[label] || "#475569", fontFamily: "monospace" }}>
                        {(score * 100).toFixed(1)}%
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── BLOCKLIST TAB ── */}
        {activeTab === "blocklist" && (
          <div style={{ animation: "fadeIn 0.3s ease", maxWidth: 700 }}>
            <div className="panel" style={{ marginBottom: 16 }}>
              <SectionTitle label="IP Blocking" title="Block an IP Address" />
              <div style={{ display: "flex", gap: 12, marginBottom: 10 }}>
                <input value={blockInput} onChange={e => setBlockInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && blockIP()}
                  className="dark-input" placeholder="192.168.1.50" style={{ flex: 1 }} />
                <button onClick={blockIP} className="danger-btn" style={{ flexShrink: 0, padding: "10px 24px" }}>
                  Block IP
                </button>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <div style={{ flex: 2 }}>
                  <input value={blockReason} onChange={e => setBlockReason(e.target.value)}
                    className="dark-input" placeholder="Reason (optional)" />
                </div>
                <div style={{ flex: 1 }}>
                  <select value={blockTTL} onChange={e => setBlockTTL(e.target.value)}
                    className="dark-input" style={{ background: "#0a1628", colorScheme: "dark" }}>
                    <option value="">Permanent</option>
                    <option value="3600">1 Hour</option>
                    <option value="21600">6 Hours</option>
                    <option value="86400">24 Hours</option>
                    <option value="604800">7 Days</option>
                  </select>
                </div>
              </div>
              {currentUser?.role !== "admin" && currentUser?.role !== "analyst" && (
                <div style={{ fontSize: 12, color: "#f97316", marginTop: 8 }}>⚠️ You need Analyst or Admin role to block IPs</div>
              )}
            </div>

            <div className="panel">
              <SectionTitle label="Blocklist" title={`Blocked IPs (${blockedIPs.length})`} />
              {blockedIPs.length === 0 ? (
                <div style={{ color: "#475569", fontSize: 13, padding: "12px 0" }}>No IPs currently blocked.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {blockedIPs.map((b, i) => (
                    <div key={i} style={{
                      padding: "12px 16px", background: "rgba(239,68,68,0.05)", borderRadius: 10,
                      border: "1px solid rgba(239,68,68,0.15)"
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div>
                          <span style={{ fontSize: 14, fontFamily: "monospace", color: "#f87171", fontWeight: 700 }}>{b.ip}</span>
                          <span style={{ fontSize: 10, color: "#475569", marginLeft: 10, background: "rgba(255,255,255,0.05)", borderRadius: 4, padding: "2px 6px", textTransform: "uppercase", letterSpacing: "0.06em" }}>{b.layer || "firewall"}</span>
                        </div>
                        {(currentUser?.role === "admin" || currentUser?.role === "analyst") && (
                          <button onClick={() => unblockIP(b.ip)} className="action-btn" style={{ padding: "6px 14px", fontSize: 12 }}>
                            Unblock
                          </button>
                        )}
                      </div>
                      <div style={{ marginTop: 8, display: "flex", gap: 16, flexWrap: "wrap" }}>
                        {b.reason && <span style={{ fontSize: 11, color: "#64748b" }}>📋 {b.reason}</span>}
                        {b.blocked_by && <span style={{ fontSize: 11, color: "#64748b" }}>👤 {b.blocked_by}</span>}
                        {b.blocked_at && <span style={{ fontSize: 11, color: "#334155", fontFamily: "monospace" }}>🕐 {b.blocked_at.slice(0,19).replace("T"," ")}</span>}
                        {b.expires_at && <span style={{ fontSize: 11, color: "#f97316" }}>⏱ expires {b.expires_at.slice(0,19).replace("T"," ")}</span>}
                        {!b.expires_at && <span style={{ fontSize: 11, color: "#475569" }}>∞ permanent</span>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── DEVICES TAB ── */}
        {activeTab === "devices" && (
        <div style={{ animation: "fadeIn 0.2s ease" }}>
          <div className="panel" style={{ marginBottom: 20 }}>
            <SectionTitle label="Network Scanner" title="Connected Devices" />
            <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
              <button className="action-btn" disabled={devicesLoading} onClick={async () => {
                setDevicesLoading(true);
                try {
                  const r = await fetch(`${API}/network/scan/arp`, {
                    method: "POST",
                    headers: { Authorization: `Bearer ${TokenStore.getAccess()}` }
                  }).then(x => x.json());
                  setDevices(r.devices || []);
                  setDevicesScanTime(r.timestamp);
                } catch { }
                setDevicesLoading(false);
              }}>
                {devicesLoading ? "⏳ Scanning..." : "⚡ Quick ARP Scan"}
              </button>
              <button className="action-btn" disabled={devicesLoading} onClick={async () => {
                setDevicesLoading(true);
                try {
                  const r = await fetch(`${API}/network/scan`, {
                    method: "POST",
                    headers: { Authorization: `Bearer ${TokenStore.getAccess()}` }
                  }).then(x => x.json());
                  setDevices(r.devices || []);
                  setDevicesScanTime(r.timestamp);
                } catch { }
                setDevicesLoading(false);
              }}>
                {devicesLoading ? "⏳ Scanning..." : "🔍 Full ARP + Nmap Scan"}
              </button>
              {devicesScanTime && (
                <span style={{ fontSize: 11, color: "#475569", alignSelf: "center" }}>
                  Last scan: {devicesScanTime.replace("T", " ")}
                </span>
              )}
            </div>

            {devicesLoading && (
              <div style={{ textAlign: "center", padding: "40px 0", color: "#38bdf8" }}>
                <div style={{ fontSize: 24, marginBottom: 12 }}>📡</div>
                <div style={{ fontSize: 13, color: "#475569" }}>Scanning network... this may take 10-30 seconds</div>
              </div>
            )}

            {!devicesLoading && devices.length === 0 && (
              <div style={{ textAlign: "center", padding: "40px 0", color: "#475569" }}>
                <div style={{ fontSize: 32, marginBottom: 12 }}>🌐</div>
                <div style={{ fontSize: 13 }}>Click "Quick ARP Scan" to discover devices on your network</div>
              </div>
            )}

            {!devicesLoading && devices.length > 0 && (
              <div>
                <div style={{ fontSize: 12, color: "#475569", marginBottom: 14 }}>
                  Found <span style={{ color: "#38bdf8", fontWeight: 700 }}>{devices.length}</span> devices on network
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {devices.map((d, i) => (
                    <div key={i} style={{
                      padding: "14px 16px",
                      background: d.is_self ? "rgba(56,189,248,0.06)" : d.is_gateway ? "rgba(34,211,160,0.06)" : "rgba(255,255,255,0.02)",
                      border: `1px solid ${d.is_self ? "rgba(56,189,248,0.2)" : d.is_gateway ? "rgba(34,211,160,0.15)" : "rgba(255,255,255,0.06)"}`,
                      borderRadius: 10
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                          <div style={{ fontSize: 20 }}>
                            {d.is_self ? "💻" : d.is_gateway ? "🌐" : "📱"}
                          </div>
                          <div>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                              <span style={{ fontSize: 15, fontFamily: "monospace", color: "#38bdf8", fontWeight: 700 }}>{d.ip}</span>
                              {d.is_self && <span style={{ fontSize: 10, background: "rgba(56,189,248,0.15)", color: "#38bdf8", borderRadius: 4, padding: "2px 6px", fontWeight: 700 }}>THIS DEVICE</span>}
                              {d.is_gateway && <span style={{ fontSize: 10, background: "rgba(34,211,160,0.15)", color: "#22d3a0", borderRadius: 4, padding: "2px 6px", fontWeight: 700 }}>GATEWAY</span>}
                            </div>
                            <div style={{ fontSize: 12, color: "#64748b", marginTop: 3 }}>
                              {d.hostname !== "unknown" && <span style={{ marginRight: 12 }}>🏷️ {d.hostname}</span>}
                              {d.vendor !== "Unknown" && <span>🏭 {d.vendor}</span>}
                            </div>
                          </div>
                        </div>
                        <div style={{ textAlign: "right" }}>
                          <div style={{ fontSize: 11, fontFamily: "monospace", color: "#475569" }}>{d.mac || "—"}</div>
                          <div style={{ fontSize: 10, color: d.status === "online" ? "#22d3a0" : "#ef4444", marginTop: 3, fontWeight: 600 }}>
                            ● {d.status?.toUpperCase()}
                          </div>
                        </div>
                      </div>
                      {d.open_ports && d.open_ports.length > 0 && (
                        <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap" }}>
                          {d.open_ports.slice(0, 8).map((p, pi) => (
                            <span key={pi} style={{
                              fontSize: 10, fontFamily: "monospace",
                              background: "rgba(167,139,250,0.1)", color: "#a78bfa",
                              border: "1px solid rgba(167,139,250,0.2)",
                              borderRadius: 4, padding: "2px 7px"
                            }}>{p.port}/{p.proto} {p.service}</span>
                          ))}
                          {d.open_ports.length > 8 && (
                            <span style={{ fontSize: 10, color: "#475569" }}>+{d.open_ports.length - 8} more</span>
                          )}
                        </div>
                      )}
                      {d.os && d.os !== "unknown" && (
                        <div style={{ marginTop: 6, fontSize: 11, color: "#475569" }}>🖥️ OS: {d.os}</div>
                      )}
                      <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                        {(currentUser?.role === "admin" || currentUser?.role === "analyst") && !d.is_self && !d.is_gateway && (
                          <button className="danger-btn" style={{ padding: "5px 12px", fontSize: 11 }}
                            onClick={() => {
                              setBlockInput(d.ip);
                              setBlockReason(`Suspicious device: ${d.hostname || d.ip}`);
                              setActiveTab("blocklist");
                            }}>
                            🚫 Block IP
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

        {/* ── USERS TAB (admin only) ── */}
        {activeTab === "users" && currentUser?.role === "admin" && (
          <UsersPanel token={TokenStore.getAccess()} currentUser={currentUser} />
        )}

      </div>

      {/* Report Modal */}
      {showReportModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ background: "#0a1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 16, padding: "28px 28px", width: 420, boxShadow: "0 20px 60px rgba(0,0,0,0.5)" }}>
            <div style={{ fontSize: 16, fontWeight: 700, color: "#f1f5f9", marginBottom: 6 }}>Export Report</div>
            <div style={{ fontSize: 12, color: "#475569", marginBottom: 20 }}>Select time window for the report</div>

            {/* Mode selector */}
            <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
              {[["last", "Last 500 Events"], ["hours", "Last N Hours"], ["range", "Custom Range"]].map(([m, label]) => (
                <button key={m} onClick={() => setReportMode(m)} style={{
                  flex: 1, padding: "8px 6px", borderRadius: 8, fontSize: 11, fontWeight: 600, cursor: "pointer",
                  background: reportMode === m ? "rgba(14,165,233,0.2)" : "rgba(255,255,255,0.04)",
                  border: reportMode === m ? "1px solid rgba(14,165,233,0.5)" : "1px solid rgba(255,255,255,0.08)",
                  color: reportMode === m ? "#38bdf8" : "#64748b", transition: "all 0.15s"
                }}>{label}</button>
              ))}
            </div>

            {/* Hours input */}
            {reportMode === "hours" && (
              <div style={{ marginBottom: 20 }}>
                <label style={{ fontSize: 11, color: "#64748b", letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 8 }}>Hours Back</label>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                  {["1", "3", "6", "12", "24", "48"].map(h => (
                    <button key={h} onClick={() => setReportHours(h)} style={{
                      padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: "pointer", fontWeight: 600,
                      background: reportHours === h ? "rgba(14,165,233,0.2)" : "rgba(255,255,255,0.04)",
                      border: reportHours === h ? "1px solid rgba(14,165,233,0.5)" : "1px solid rgba(255,255,255,0.08)",
                      color: reportHours === h ? "#38bdf8" : "#94a3b8"
                    }}>{h}h</button>
                  ))}
                </div>
                <input type="number" value={reportHours} onChange={e => setReportHours(e.target.value)}
                  placeholder="Custom hours..." min="0.5" step="0.5"
                  style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, padding: "10px 12px", color: "#f1f5f9", fontSize: 13, outline: "none" }} />
              </div>
            )}

            {/* Range input */}
            {reportMode === "range" && (
              <div style={{ marginBottom: 20 }}>
                <label style={{ fontSize: 11, color: "#64748b", letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 8 }}>Start Time</label>
                <input type="datetime-local" value={reportStart} onChange={e => setReportStart(e.target.value)}
                  style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, padding: "10px 12px", color: "#f1f5f9", fontSize: 13, outline: "none", marginBottom: 12, colorScheme: "dark" }} />
                <label style={{ fontSize: 11, color: "#64748b", letterSpacing: "0.08em", textTransform: "uppercase", display: "block", marginBottom: 8 }}>End Time</label>
                <input type="datetime-local" value={reportEnd} onChange={e => setReportEnd(e.target.value)}
                  style={{ width: "100%", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, padding: "10px 12px", color: "#f1f5f9", fontSize: 13, outline: "none", colorScheme: "dark" }} />
              </div>
            )}

            {/* Buttons */}
            <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
              <button onClick={() => setShowReportModal(false)} style={{
                flex: 1, padding: "11px", borderRadius: 8, background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.08)", color: "#64748b", fontSize: 13, fontWeight: 600, cursor: "pointer"
              }}>Cancel</button>
              <button onClick={generateReport} style={{
                flex: 2, padding: "11px", borderRadius: 8,
                background: "linear-gradient(135deg, #0ea5e9, #2563eb)",
                border: "none", color: "white", fontSize: 13, fontWeight: 600, cursor: "pointer"
              }}>↓ Generate Report</button>
            </div>
          </div>
        </div>
      )}
</div>
  );
}