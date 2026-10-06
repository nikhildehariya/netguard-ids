import { useState, useEffect, useRef, useCallback } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

import { COLORS, SEV_COLOR, Pill, StatCard, SectionTitle, Divider } from "./components/Common";
import OverviewTab from "./components/OverviewTab";
import CaptureTab, { RadarPulse } from "./components/CaptureTab";
import IncidentsTab from "./components/IncidentsTab";
import ValidateTab from "./components/ValidateTab";
import BlocklistTab from "./components/BlocklistTab";
import DevicesTab from "./components/DevicesTab";
import UsersTab from "./components/UsersTab";
import AssistantTab from "./components/AssistantTab";
import ExplainModal from "./components/ExplainModal";

const API = `http://${(!window.location.hostname || window.location.hostname === "localhost") ? "127.0.0.1" : window.location.hostname}:8081`;


const PRESETS = {
  "DoS GoldenEye": { "Dst Port": 80, "Protocol": 6, "Flow Duration": 6010454, "Tot Fwd Pkts": 4, "Tot Bwd Pkts": 4, "TotLen Fwd Pkts": 285, "TotLen Bwd Pkts": 972, "Fwd Pkt Len Max": 285, "Fwd Pkt Len Min": 0, "Fwd Pkt Len Mean": 71.25, "Fwd Pkt Len Std": 142.5, "Bwd Pkt Len Max": 972, "Bwd Pkt Len Min": 0, "Bwd Pkt Len Mean": 243.0, "Bwd Pkt Len Std": 486.0, "Flow Byts/s": 209.13, "Flow Pkts/s": 1.33, "Flow IAT Mean": 858636.28, "Flow IAT Std": 1865827.78, "Flow IAT Max": 5004855, "Flow IAT Min": 6, "Fwd IAT Tot": 1005599, "Fwd IAT Mean": 335199.66, "Fwd IAT Std": 576060.72, "Fwd IAT Max": 1000372, "Fwd IAT Min": 316, "Bwd IAT Tot": 6010448, "Bwd IAT Mean": 2003482.66, "Bwd IAT Std": 2646706.61, "Bwd IAT Max": 5005181, "Bwd IAT Min": 5229, "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0, "Fwd Header Len": 136, "Bwd Header Len": 136, "Fwd Pkts/s": 0.66, "Bwd Pkts/s": 0.66, "Pkt Len Min": 0, "Pkt Len Max": 972, "Pkt Len Mean": 139.66, "Pkt Len Std": 326.04, "Pkt Len Var": 106306.0, "FIN Flag Cnt": 0, "SYN Flag Cnt": 0, "RST Flag Cnt": 0, "PSH Flag Cnt": 1, "ACK Flag Cnt": 0, "URG Flag Cnt": 0, "CWE Flag Count": 0, "ECE Flag Cnt": 0, "Down/Up Ratio": 1, "Pkt Size Avg": 157.12, "Fwd Seg Size Avg": 71.25, "Bwd Seg Size Avg": 243.0, "Subflow Fwd Pkts": 4, "Subflow Fwd Byts": 285, "Subflow Bwd Pkts": 4, "Subflow Bwd Byts": 972, "Init Fwd Win Byts": 26883, "Init Bwd Win Byts": 219, "Fwd Act Data Pkts": 1, "Fwd Seg Size Min": 32, "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0 },
  "Brute Force SSH": { "Dst Port": 21, "Protocol": 6, "Flow Duration": 19, "Tot Fwd Pkts": 1, "Tot Bwd Pkts": 1, "TotLen Fwd Pkts": 0, "TotLen Bwd Pkts": 0, "Fwd Pkt Len Max": 0, "Fwd Pkt Len Min": 0, "Fwd Pkt Len Mean": 0, "Fwd Pkt Len Std": 0, "Bwd Pkt Len Max": 0, "Bwd Pkt Len Min": 0, "Bwd Pkt Len Mean": 0, "Bwd Pkt Len Std": 0, "Flow Byts/s": 0, "Flow Pkts/s": 105263.157, "Flow IAT Mean": 19, "Flow IAT Std": 0, "Flow IAT Max": 19, "Flow IAT Min": 19, "Fwd IAT Tot": 19, "Fwd IAT Mean": 19, "Fwd IAT Std": 0, "Fwd IAT Max": 0, "Fwd IAT Min": 0, "Bwd IAT Tot": 0, "Bwd IAT Mean": 0, "Bwd IAT Std": 0, "Bwd IAT Max": 0, "Bwd IAT Min": 0, "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0, "Fwd Header Len": 40, "Bwd Header Len": 20, "Fwd Pkts/s": 52631.578, "Bwd Pkts/s": 52631.578, "Pkt Len Min": 0, "Pkt Len Max": 0, "Pkt Len Mean": 0, "Pkt Len Std": 0, "Pkt Len Var": 0, "FIN Flag Cnt": 0, "SYN Flag Cnt": 0, "RST Flag Cnt": 0, "PSH Flag Cnt": 1, "ACK Flag Cnt": 0, "URG Flag Cnt": 0, "CWE Flag Count": 0, "ECE Flag Cnt": 0, "Down/Up Ratio": 0, "Pkt Size Avg": 0, "Fwd Seg Size Avg": 0, "Bwd Seg Size Avg": 0, "Subflow Fwd Pkts": 1, "Subflow Fwd Byts": 0, "Subflow Bwd Pkts": 1, "Subflow Bwd Byts": 0, "Init Fwd Win Byts": 26883, "Init Bwd Win Byts": 0, "Fwd Act Data Pkts": 0, "Fwd Seg Size Min": 40, "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0 },
  "Normal HTTPS": { "Dst Port": 443, "Protocol": 6, "Flow Duration": 100000, "Tot Fwd Pkts": 10, "Tot Bwd Pkts": 10, "Flow Pkts/s": 0.5, "TotLen Fwd Pkts": 0, "TotLen Bwd Pkts": 0, "Fwd Pkt Len Max": 0, "Fwd Pkt Len Min": 0, "Fwd Pkt Len Mean": 0, "Fwd Pkt Len Std": 0, "Bwd Pkt Len Max": 0, "Bwd Pkt Len Min": 0, "Bwd Pkt Len Mean": 0, "Bwd Pkt Len Std": 0, "Flow Byts/s": 0, "Flow IAT Mean": 0, "Flow IAT Std": 0, "Flow IAT Max": 0, "Flow IAT Min": 0, "Fwd IAT Tot": 0, "Fwd IAT Mean": 0, "Fwd IAT Std": 0, "Fwd IAT Max": 0, "Fwd IAT Min": 0, "Bwd IAT Tot": 0, "Bwd IAT Mean": 0, "Bwd IAT Std": 0, "Bwd IAT Max": 0, "Bwd IAT Min": 0, "Fwd PSH Flags": 0, "Bwd PSH Flags": 0, "Fwd URG Flags": 0, "Bwd URG Flags": 0, "Fwd Header Len": 0, "Bwd Header Len": 0, "Fwd Pkts/s": 0, "Bwd Pkts/s": 0, "Pkt Len Min": 0, "Pkt Len Max": 0, "Pkt Len Mean": 0, "Pkt Len Std": 0, "Pkt Len Var": 0, "FIN Flag Cnt": 0, "SYN Flag Cnt": 0, "RST Flag Cnt": 0, "PSH Flag Cnt": 0, "ACK Flag Cnt": 0, "URG Flag Cnt": 0, "CWE Flag Count": 0, "ECE Flag Cnt": 0, "Down/Up Ratio": 0, "Pkt Size Avg": 0, "Fwd Seg Size Avg": 0, "Bwd Seg Size Avg": 0, "Subflow Fwd Pkts": 0, "Subflow Fwd Byts": 0, "Subflow Bwd Pkts": 0, "Subflow Bwd Byts": 0, "Init Fwd Win Byts": 0, "Init Bwd Win Byts": 0, "Fwd Act Data Pkts": 0, "Fwd Seg Size Min": 0, "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0 },
};

// ── Login Screen ──────────────────────────────────────────────
// ── Token Storage ────────────────────────────────────────────
export const TokenStore = {
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
    if (!form.username.trim() || !form.password.trim()) {
      setErr("Please enter both username and password");
      return;
    }
    setErr("");
    setLoading(true);
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const res = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: form.username.trim(), password: form.password }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      const data = await res.json();
      if (!res.ok) {
        setAttempts(a => a + 1);
        if (res.status === 423) { setLocked(true); setErr(data.detail); }
        else setErr(data.detail || "Invalid credentials");
        setLoading(false);
        return;
      }
      TokenStore.set(data.access_token, data.refresh_token, data.user);
      onLogin(data.user);
    } catch (e) {
      if (e.name === "AbortError") {
        setErr("Login timed out. Please check API server connection.");
      } else {
        setErr("Cannot connect to API. Is the server running?");
      }
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
          <div style={{ fontSize: 13, color: "#475569", marginTop: 6, letterSpacing: "0.02em" }}>IoT Intrusion Detection System v2.1</div>
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
  const [devicesScanMode, setDevicesScanMode] = useState(null); // "arp" | "full" | null
  const [devicesScanError, setDevicesScanError] = useState("");
  const [valPreset, setValPreset] = useState("DoS GoldenEye");
  const [valResult, setValResult] = useState(null);
  const [valLoading, setValLoading] = useState(false);
  const [toast, setToast] = useState(null);
  const [license, setLicense] = useState({ status: "active", client: "", expires_at: "" });
  const [licenseInput, setLicenseInput] = useState("");
  const [licensingError, setLicensingError] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [themeMode, setThemeMode] = useState(() => localStorage.getItem("ng_theme") || "dark");
  const [pdfBytes, setPdfBytes] = useState(null);
  const [pdfName, setPdfName] = useState("report.pdf");
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportMode, setReportMode] = useState("last"); // "last" | "hours" | "range"
  const [reportHours, setReportHours] = useState("6");
  const [reportStart, setReportStart] = useState("");
  const [reportEnd, setReportEnd] = useState("");
  const [explainModalOpen, setExplainModalOpen] = useState(false);
  const [explainTargetRecord, setExplainTargetRecord] = useState(null);
  const [explainTargetPred, setExplainTargetPred] = useState(null);

  const handleOpenExplain = (record, pred) => {
    setExplainTargetRecord(record);
    setExplainTargetPred(pred);
    setExplainModalOpen(true);
  };

  const showToast = (msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const handleLogout = useCallback(() => {
    const rt = TokenStore.getRefresh();
    if (rt) fetch(`${API}/auth/logout`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: rt }) }).catch(() => {});
    TokenStore.clear();
    setAuth(false);
    setCurrentUser(null);
  }, []);

  const fetchLicenseStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/license/status`).then(r => r.json());
      setLicense(res || { status: "active" });
    } catch {
      // Offline fallback
    }
  }, []);

  useEffect(() => {
    fetchLicenseStatus();
  }, [fetchLicenseStatus]);

  const handleActivateLicense = async () => {
    if (!licenseInput.trim()) return;
    try {
      const r = await fetch(`${API}/api/license/activate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: licenseInput })
      });
      const res = await r.json();
      if (r.ok) {
        showToast("License activated successfully!");
        setLicense({ status: "active", client: res.client, expires_at: res.expires_at });
        setLicenseInput("");
        setLicensingError("");
      } else {
        setLicensingError(res.detail || "Invalid license key");
      }
    } catch {
      setLicensingError("Failed to communicate with licensing server");
    }
  };

  const toggleTheme = () => {
    const next = themeMode === "dark" ? "soft" : "dark";
    setThemeMode(next);
    localStorage.setItem("ng_theme", next);
  };

  useEffect(() => {
    document.body.classList.toggle("ng-soft-theme", themeMode === "soft");
    document.documentElement.classList.toggle("ng-soft-theme", themeMode === "soft");
  }, [themeMode]);

  const fetchAll = useCallback(async () => {
    try {
      const token = TokenStore.getAccess();
      const authH = { Authorization: `Bearer ${token}` };

      const checkAuth = async (res) => {
        if (res.status === 401) {
          throw new Error("UNAUTHORIZED");
        }
        if (res.status === 403) {
          return null; // Permission error for role — do not log out
        }
        return res.json();
      };

      const [hRes, sRes, cRes, bRes, iRes] = await Promise.all([
        fetch(`${API}/history?limit=1000&mode=live`, { headers: authH }).then(checkAuth).catch(e => { if (e.message === "UNAUTHORIZED") throw e; return []; }),
        fetch(`${API}/stats?mode=live`, { headers: authH }).then(checkAuth).catch(e => { if (e.message === "UNAUTHORIZED") throw e; return {}; }),
        fetch(`${API}/capture/status`, { headers: authH }).then(checkAuth).catch(e => { if (e.message === "UNAUTHORIZED") throw e; return {}; }),
        fetch(`${API}/blocked-ips`, { headers: authH }).then(checkAuth).catch(e => { if (e.message === "UNAUTHORIZED") throw e; return { items: [] }; }),
        fetch(`${API}/capture/interfaces`, { headers: authH }).then(checkAuth).catch(e => { if (e.message === "UNAUTHORIZED") throw e; return { interfaces: [] }; }),
      ]);
      setApiOnline(true);
      setHistory(Array.isArray(hRes) ? hRes : []);
      setStats(sRes || { total: 0, by_class: {}, attack_rate: 0 });
      setCaptureRunning(cRes?.running || false);
      setCaptureLog(cRes?.last_log || "");
      setBlockedIPs(bRes?.items || []);
      const ifaces = (iRes?.interfaces || []).map(i => typeof i === "string" ? { id: i, label: i } : i);
      setInterfaces(ifaces);
      if (ifaces.length && !selectedIface) {
        if (captureMode === "wifi") {
          const wifi = ifaces.find(i => 
            (i.name && i.name.toLowerCase().includes("wi-fi")) || 
            (i.description && i.description.toLowerCase().includes("wi-fi")) ||
            (i.name && i.name.toLowerCase().includes("wireless")) ||
            (i.description && i.description.toLowerCase().includes("wireless"))
          );
          if (wifi) setSelectedIface(wifi.id);
          else setSelectedIface(ifaces[0].id);
        } else if (captureMode === "span") {
          setSelectedIface(SPAN_GUID);
        } else {
          const active = ifaces.find(i => i.ips && i.ips.length && i.ips.some(ip => !ip.startsWith("127.") && !ip.startsWith("169.254")));
          if (active) setSelectedIface(active.id);
          else setSelectedIface(ifaces[0].id);
        }
      }
    } catch (e) {
      if (e.message === "UNAUTHORIZED") {
        handleLogout();
        showToast("Session expired. Please sign in again.", "error");
      } else {
        setApiOnline(false);
      }
    }
  }, [selectedIface, handleLogout]);

  useEffect(() => {
    if (!auth) return;
    fetchAll();
    const intervalMs = 1000; // 1-second real-time enterprise telemetry pulse
    const t = setInterval(fetchAll, intervalMs);
    return () => clearInterval(t);
  }, [auth, fetchAll]);

  // Auto-login with token verification
  useEffect(() => {
    const verifySession = async () => {
      const user = TokenStore.getUser();
      const token = TokenStore.getAccess();
      const refreshToken = TokenStore.getRefresh();

      if (!token) {
        setAuth(false);
        setCurrentUser(null);
        return;
      }

      try {
        const res = await fetch(`${API}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) {
          const me = await res.json();
          setCurrentUser(user || { username: me.username, role: me.role });
          setAuth(true);
          return;
        }

        if (res.status === 401 && refreshToken) {
          const refRes = await fetch(`${API}/auth/refresh`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ refresh_token: refreshToken })
          });
          if (refRes.ok) {
            const refData = await refRes.json();
            TokenStore.set(refData.access_token, refData.refresh_token, refData.user || user);
            setCurrentUser(refData.user || user);
            setAuth(true);
            return;
          }
        }
      } catch {
        // API offline — allow user to access UI if local token exists
        if (user && token) {
          setCurrentUser(user);
          setAuth(true);
          return;
        }
      }

      TokenStore.clear();
      setAuth(false);
      setCurrentUser(null);
    };

    verifySession();
  }, []);


  // Derived data
  const bc = stats.by_class || {};
  const attacks = history.filter(r => r.prediction !== "NORMAL");
  const timelineData = (() => {
    const buckets = [];
    const now = new Date();
    // Generate 10 rolling minute buckets up to current time
    for (let i = 9; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60 * 1000);
      const timeStr = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
      buckets.push({
        time: timeStr,
        minuteKey: `${d.getFullYear()}-${d.getMonth()}-${d.getDate()} ${d.getHours()}:${d.getMinutes()}`,
        NORMAL: 0,
        BRUTE_FORCE: 0,
        DOS_DDOS: 0,
        WEB_ATTACK: 0,
        INFILTRATION: 0
      });
    }

    history.forEach(r => {
      if (!r || !r.timestamp) return;
      let raw = String(r.timestamp);
      if (!raw.endsWith("Z") && !raw.includes("+") && raw.includes("T")) {
        raw += "Z";
      }
      const t = new Date(raw);
      if (isNaN(t.getTime())) return;
      const minuteKey = `${t.getFullYear()}-${t.getMonth()}-${t.getDate()} ${t.getHours()}:${t.getMinutes()}`;
      const bucket = buckets.find(b => b.minuteKey === minuteKey);
      if (bucket) {
        const pred = r.prediction || "NORMAL";
        bucket[pred] = (bucket[pred] || 0) + 1;
      }
    });

    const hasLiveData = buckets.some(b => b.NORMAL + b.BRUTE_FORCE + b.DOS_DDOS + b.WEB_ATTACK + b.INFILTRATION > 0);
    if (!hasLiveData && history.length > 0) {
      const step = Math.max(1, Math.floor(history.length / 10));
      return Array.from({ length: 10 }).map((_, idx) => {
        const slice = history.slice(idx * step, (idx + 1) * step);
        const point = { time: `T-${10 - idx}m`, NORMAL: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, WEB_ATTACK: 0, INFILTRATION: 0 };
        slice.forEach(r => {
          const pred = r.prediction || "NORMAL";
          point[pred] = (point[pred] || 0) + 1;
        });
        return point;
      });
    }

    return buckets.map(({ minuteKey, ...rest }) => rest);
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
      const token = TokenStore.getAccess();
      const r = await fetch(`${API}/predict`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ ...PRESETS[valPreset], test_mode: true })
      }).then(x => x.json());

      if (r.detail) {
        showToast(r.detail, "error");
        setValResult(null);
      } else {
        setValResult(r);
        fetchAll();
      }
    } catch {
      showToast("API unreachable", "error");
    }
    setValLoading(false);
  };

  const handleCaptureMode = (mode) => {
    setCaptureMode(mode);
    if (mode === "wifi") {
      const wifiAdapter = interfaces.find(i => 
        (i.name && i.name.toLowerCase().includes("wi-fi")) || 
        (i.description && i.description.toLowerCase().includes("wi-fi")) ||
        (i.name && i.name.toLowerCase().includes("wireless")) ||
        (i.description && i.description.toLowerCase().includes("wireless")) ||
        (i.label && i.label.toLowerCase().includes("wi-fi")) ||
        (i.label && i.label.toLowerCase().includes("wireless"))
      );
      if (wifiAdapter) {
        setSelectedIface(wifiAdapter.id);
        showToast("Auto-detected Wi-Fi: " + (wifiAdapter.name || "Interface"));
      } else {
        const active = interfaces.find(i => i.ips && i.ips.length && i.ips.some(ip => !ip.startsWith("127.") && !ip.startsWith("169.254")));
        if (active) setSelectedIface(active.id);
        else if (interfaces.length) setSelectedIface(interfaces[0].id);
      }
    } else if (mode === "span") {
      const ethAdapter = interfaces.find(i =>
        (i.name && i.name.toLowerCase().includes("ethernet")) ||
        (i.description && i.description.toLowerCase().includes("ethernet")) ||
        (i.label && i.label.toLowerCase().includes("ethernet"))
      );
      if (ethAdapter) {
        setSelectedIface(ethAdapter.id);
        showToast("Auto-selected Ethernet: " + (ethAdapter.name || "Interface"));
      } else {
        const active = interfaces.find(i => i.ips && i.ips.length && i.ips.some(ip => !ip.startsWith("127.") && !ip.startsWith("169.254")));
        if (active) setSelectedIface(active.id);
        else if (interfaces.length) setSelectedIface(interfaces[0].id);
      }
    } else if (mode === "manual") {
      const active = interfaces.find(i => i.ips && i.ips.length && i.ips.some(ip => !ip.startsWith("127.") && !ip.startsWith("169.254")));
      if (active) setSelectedIface(active.id);
      else if (interfaces.length) setSelectedIface(interfaces[0].id);
    }
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

  if (license.status === "expired") {
    return (
      <div style={{ minHeight: "100vh", background: "linear-gradient(135deg, #090514 0%, #030107 100%)", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "'Space Grotesk', system-ui, sans-serif", color: "#e2e8f0", padding: 20 }}>
        <div style={{ width: 480, background: "rgba(20,10,35,0.7)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: 24, padding: 40, backdropFilter: "blur(20px)", boxShadow: "0 20px 50px rgba(0,0,0,0.6), 0 0 40px rgba(239,68,68,0.05)", textAlign: "center" }}>
          
          {/* Warning Icon */}
          <div style={{ width: 72, height: 72, borderRadius: "50%", background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 24px", color: "#ef4444", fontSize: 32 }}>
            ⚠️
          </div>

          <h2 style={{ fontSize: 24, fontWeight: 700, color: "#f87171", marginBottom: 12 }}>NetGuard Threat Protection Suspended</h2>
          
          <p style={{ fontSize: 14, color: "#94a3b8", lineHeight: "1.5em", marginBottom: 24 }}>
            Your NetGuard subscription/license has expired or is invalid. Active packet sniffing, intrusion detection alerts, and automatic firewalls are currently locked.
          </p>

          <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: 12, padding: 16, marginBottom: 28, border: "1px solid rgba(255,255,255,0.03)" }}>
            <div style={{ fontSize: 11, color: "#475569", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 4 }}>Reason</div>
            <div style={{ fontSize: 13, color: "#f87171", fontWeight: 500 }}>{license.message || "License Expired"}</div>
            
            <div style={{ height: 1, background: "rgba(255,255,255,0.05)", margin: "12px 0" }} />
            
            <div style={{ fontSize: 11, color: "#475569", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 700, marginBottom: 4 }}>Contact Security Provider</div>
            <div style={{ fontSize: 13, color: "#38bdf8", fontWeight: 600 }}>Nikhil Dehariya</div>
            <div style={{ fontSize: 11, color: "#64748b", marginTop: 2 }}>Email: nikhil@netguard.com</div>
          </div>

          {/* License input */}
          <div style={{ textAlign: "left", marginBottom: 16 }}>
            <label style={{ fontSize: 11, color: "#64748b", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: 8, fontWeight: 600 }}>Enter Activation License Key</label>
            <input type="text" value={licenseInput} onChange={e => setLicenseInput(e.target.value)} placeholder="NETGUARD-YYYYMMDD-XXXXXX" style={{ width: "100%", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, padding: "12px 14px", color: "#f1f5f9", fontSize: 14, outline: "none", fontFamily: "monospace" }} />
          </div>

          {licensingError && (
            <div style={{ color: "#ef4444", fontSize: 12, marginBottom: 16, background: "rgba(239,68,68,0.08)", padding: "8px 12px", borderRadius: 8, border: "1px solid rgba(239,68,68,0.15)" }}>
              ❌ {licensingError}
            </div>
          )}

          <button onClick={handleActivateLicense} style={{ width: "100%", background: "linear-gradient(135deg, #ef4444, #b91c1c)", border: "none", borderRadius: 12, padding: "14px", color: "white", fontSize: 14, fontWeight: 700, cursor: "pointer", boxShadow: "0 4px 20px rgba(239,68,68,0.2)" }}>
            Activate License Key →
          </button>
        </div>
      </div>
    );
  }

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
    <div className={`theme-${themeMode}`} style={{ minHeight: "100vh", background: "#020810", color: "#e2e8f0", fontFamily: "'Space Grotesk', system-ui, sans-serif" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #020810; }
        html.ng-soft-theme,
        body.ng-soft-theme,
        body.ng-soft-theme #root {
          background: #eaf2fb !important;
        }
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

        .nav-btn {
          width: 100%; display: flex; align-items: center; gap: 10px; padding: 10px 14px;
          border-radius: 0 10px 10px 0; border: none; background: none;
          color: #64748b; font-size: 13px; font-weight: 600;
          margin-bottom: 4px; transition: all 0.2s ease; text-align: left;
          border-left: 3px solid transparent;
        }
        .nav-btn:hover {
          color: #94a3b8;
          background: rgba(255, 255, 255, 0.02);
        }
        .nav-btn.active {
          border-left: 3px solid #38bdf8;
          background: linear-gradient(90deg, rgba(56,189,248,0.1) 0%, rgba(56,189,248,0) 100%);
          color: #38bdf8;
          text-shadow: 0 0 8px rgba(56,189,248,0.4);
        }

        .mode-btn {
          flex: 1; padding: 10px 8px; border-radius: 10px; cursor: pointer;
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid rgba(255, 255, 255, 0.07);
          transition: all 0.15s; text-align: center;
        }
        .mode-btn:hover {
          background: rgba(255, 255, 255, 0.06);
          border-color: rgba(255, 255, 255, 0.12);
        }
        .mode-btn.active {
          background: rgba(14, 165, 233, 0.15);
          border-color: rgba(14, 165, 233, 0.5);
        }
        .mode-btn .title {
          font-size: 12px; font-weight: 700; color: #94a3b8;
        }
        .mode-btn .desc {
          font-size: 10px; color: #475569; margin-top: 2px;
        }
        .mode-btn.active .title {
          color: #38bdf8;
        }
        .mode-btn.active .desc {
          color: #0ea5e9;
        }

select { color-scheme: dark; } select.dark-input { background: #0a1628 !important; color: #f1f5f9 !important; } select.dark-input option { background: #0a1628 !important; color: #f1f5f9 !important; }
        .panel {
          background: rgba(10,22,45,0.3);
          border: 1px solid rgba(255,255,255,0.05);
          border-radius: 16px;
          padding: 24px;
          box-shadow: 0 10px 30px rgba(0,0,0,0.3);
          backdrop-filter: blur(10px);
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .panel:hover {
          border-color: rgba(255,255,255,0.08);
          box-shadow: 0 15px 40px rgba(0,0,0,0.4);
        }
        .glow-card:hover {
          transform: translateY(-3px);
          background: rgba(14,165,233,0.04) !important;
          border-color: rgba(14,165,233,0.3) !important;
          box-shadow: 0 12px 30px rgba(0,0,0,0.5), 0 0 20px rgba(14,165,233,0.08) !important;
        }
        .theme-soft {
          background: #eaf2fb !important;
          color: #132033 !important;
        }
        .theme-soft,
        .theme-soft > div,
        .theme-soft nav,
        .theme-soft aside {
          background: #eaf2fb !important;
          color: #132033 !important;
        }
        .theme-soft > div[style*="margin-left"] {
          background: #eaf2fb !important;
        }
        .theme-soft div[style*="position: fixed"],
        .theme-soft div[style*="rgba(5,15,30"],
        .theme-soft div[style*="#020810"],
        .theme-soft div[style*="#050f1e"] {
          background: #f8fbff !important;
          color: #132033 !important;
          border-color: rgba(15,23,42,0.12) !important;
        }
        .theme-soft .panel,
        .theme-soft [style*="#020810"],
        .theme-soft [style*="#050f1e"],
        .theme-soft [style*="#0a1628"],
        .theme-soft [style*="rgba(10,22,40"],
        .theme-soft [style*="rgba(255,255,255,0.02)"],
        .theme-soft [style*="rgba(255,255,255,0.03)"],
        .theme-soft [style*="rgba(255,255,255,0.025)"],
        .theme-soft [style*="rgba(0,0,0,0.2)"] {
          background: #ffffff !important;
          color: #132033 !important;
          border-color: rgba(15,23,42,0.12) !important;
          box-shadow: none !important;
        }
        .theme-soft [style*="color: white"],
        .theme-soft [style*="color:white"],
        .theme-soft [style*="white"] {
          color: #132033 !important;
        }
        .theme-soft [style*="rgba(56,189,248,0.1)"],
        .theme-soft [style*="rgba(14,165,233,0.15)"],
        .theme-soft [style*="rgba(56,189,248,0.06)"] {
          background: #dff3ff !important;
          color: #075985 !important;
          border-color: rgba(14,165,233,0.28) !important;
        }
        .theme-soft [style*="rgba(34,211,160,0.08)"],
        .theme-soft [style*="rgba(34,211,160,0.1)"],
        .theme-soft [style*="rgba(34,211,160,0.06)"] {
          background: #dcfce7 !important;
          color: #047857 !important;
          border-color: rgba(16,185,129,0.28) !important;
        }
        .theme-soft [style*="rgba(239,68,68,0.08)"],
        .theme-soft [style*="rgba(239,68,68,0.1)"] {
          background: #fff1f2 !important;
          color: #be123c !important;
          border-color: rgba(244,63,94,0.28) !important;
        }
        .theme-soft h1,
        .theme-soft h2,
        .theme-soft h3,
        .theme-soft span,
        .theme-soft label,
        .theme-soft code,
        .theme-soft [style*="#f1f5f9"] {
          color: #132033 !important;
        }
        .theme-soft .panel *,
        .theme-soft div[style*="position: fixed"] *,
        .theme-soft div[style*="rgba(5,15,30"] *,
        .theme-soft div[style*="rgba(10,22,40"] *,
        .theme-soft div[style*="rgba(255,255,255,0.025)"] *,
        .theme-soft div[style*="rgba(255,255,255,0.03)"] *,
        .theme-soft div[style*="rgba(255,255,255,0.04)"] * {
          color: #132033 !important;
          opacity: 1 !important;
        }
        .theme-soft .nav-btn {
          color: #475569 !important;
        }
        .theme-soft .nav-btn:hover {
          background: rgba(15, 23, 42, 0.04) !important;
          color: #1e293b !important;
        }
        .theme-soft .nav-btn.active {
          border-left-color: #0284c7 !important;
          background: linear-gradient(90deg, rgba(14,165,233,0.12) 0%, rgba(14,165,233,0) 100%) !important;
          color: #0284c7 !important;
          text-shadow: none !important;
        }

        .theme-soft .mode-btn {
          background: #ffffff !important;
          border-color: rgba(15, 23, 42, 0.12) !important;
        }
        .theme-soft .mode-btn:hover {
          background: #f1f5f9 !important;
        }
        .theme-soft .mode-btn.active {
          background: #dff3ff !important;
          border-color: rgba(14, 165, 233, 0.4) !important;
        }
        .theme-soft .mode-btn .title {
          color: #475569 !important;
        }
        .theme-soft .mode-btn .desc {
          color: #64748b !important;
        }
        .theme-soft .mode-btn.active .title {
          color: #0284c7 !important;
        }
        .theme-soft .mode-btn.active .desc {
          color: #0369a1 !important;
        }
        .theme-soft [style*="font-size: 28"],
        .theme-soft [style*="fontSize: 28"],
        .theme-soft [style*="font-family: monospace"],
        .theme-soft [style*="fontFamily: monospace"] {
          color: #0f172a !important;
        }
        .theme-soft [style*="#475569"],
        .theme-soft [style*="#64748b"] {
          color: #4b647f !important;
        }
        .theme-soft .action-btn {
          background: #e6f4ff !important;
          color: #0369a1 !important;
          border-color: rgba(14,165,233,0.35) !important;
        }
        .theme-soft .danger-btn {
          background: #fff1f2 !important;
          color: #be123c !important;
          border-color: rgba(244,63,94,0.35) !important;
        }
        .theme-soft .success-btn {
          background: #dcfce7 !important;
          color: #047857 !important;
          border-color: rgba(16,185,129,0.35) !important;
        }
        .theme-soft input,
        .theme-soft select,
        .theme-soft .dark-input {
          background: #ffffff !important;
          color: #132033 !important;
          border-color: rgba(15,23,42,0.18) !important;
        }
        .theme-soft option {
          background: #ffffff !important;
          color: #132033 !important;
        }
        .theme-soft select,
        .theme-soft select.dark-input,
        .theme-soft select[style] {
          appearance: auto !important;
          background-color: #ffffff !important;
          color: #132033 !important;
          color-scheme: light !important;
          border: 1px solid rgba(15,23,42,0.18) !important;
        }
        .theme-soft select option,
        .theme-soft select.dark-input option {
          background-color: #ffffff !important;
          color: #132033 !important;
        }
        .theme-soft div[style*="gridTemplateColumns"],
        .theme-soft div[style*="grid-template-columns"],
        .theme-soft div[style*="rgba(10,22,40,0.6)"] {
          background: #ffffff !important;
          color: #132033 !important;
          border-color: rgba(15,23,42,0.12) !important;
        }
        .theme-soft div[style*="rgba(0,0,0,0.2)"] {
          background: #e8f1fb !important;
        }
        .theme-soft div[style*="rgba(255,255,255,0.01)"],
        .theme-soft div[style*="rgba(255,255,255,0.02)"] {
          background: #f8fbff !important;
        }
        .theme-soft [style*="#38bdf8"] {
          color: #0284c7 !important;
        }
        .theme-soft [style*="#22d3a0"] {
          color: #059669 !important;
        }
        .theme-soft [style*="#f87171"] {
          color: #dc2626 !important;
        }
        .theme-soft [style*="#f97316"] {
          color: #ea580c !important;
        }
        .theme-soft [style*="#a78bfa"] {
          color: #7c3aed !important;
        }
        .theme-soft [style*="#ec4899"] {
          color: #db2777 !important;
        }
        .theme-soft .recharts-text,
        .theme-soft .recharts-cartesian-axis-tick-value {
          fill: #334155 !important;
        }
        .theme-soft .recharts-tooltip-wrapper div {
          background: #ffffff !important;
          color: #132033 !important;
          border-color: rgba(15,23,42,0.18) !important;
        }
        .theme-soft .soft-readable,
        .theme-soft .users-table,
        .theme-soft .users-table div,
        .theme-soft .users-name {
          color: #0f172a !important;
          opacity: 1 !important;
        }
        .theme-soft .users-table {
          background: #ffffff !important;
          border-color: rgba(15,23,42,0.16) !important;
        }
        .theme-soft .users-table > div {
          background: #ffffff !important;
          border-color: rgba(15,23,42,0.12) !important;
        }
        .theme-soft .users-table > div:first-child {
          background: #eef5fc !important;
        }
        .theme-soft .users-table .users-name {
          font-weight: 700 !important;
        }
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
              <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.08em" }}>IDS v2.1</div>
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
            { id: "assistant", icon: "M13 10V3L4 14h7v7l9-11h-7z", label: "AI Assistant" },
            ...(currentUser?.role === "admin" ? [{ id: "users", icon: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z", label: "Users" }] : []),
          ].map(({ id, icon, label }) => (
            <button key={id} onClick={() => setActiveTab(id)} className={`nav-btn ${activeTab === id ? "active" : ""}`}>
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
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", justifyContent: "flex-end" }}>
            <button onClick={toggleTheme} className="action-btn" style={{ flexShrink: 0 }}>
              {themeMode === "dark" ? "☀ Soft Mode" : "🌙 Dark Mode"}
            </button>
            <button onClick={() => setShowReportModal(true)} className="action-btn" style={{ flexShrink: 0 }}>
              ↓ Export Report
            </button>
          </div>
        </div>

        {/* ── TABS RENDERING ── */}
        {activeTab === "overview" && (
          <OverviewTab stats={stats} bc={bc} timelineData={timelineData} pieData={pieData} attacks={attacks} />
        )}
        {activeTab === "capture" && (
          <CaptureTab
            captureMode={captureMode}
            handleCaptureMode={handleCaptureMode}
            selectedIface={selectedIface}
            setSelectedIface={setSelectedIface}
            interfaces={interfaces}
            toggleCapture={toggleCapture}
            captureRunning={captureRunning}
            captureLog={captureLog}
            stats={stats}
            attacks={attacks}
          />
        )}
        {activeTab === "incidents" && (
          <IncidentsTab
            attacks={attacks}
            currentUser={currentUser}
            API={API}
            showToast={showToast}
            fetchAll={fetchAll}
            onExplain={handleOpenExplain}
          />
        )}
        {activeTab === "validate" && (
          <ValidateTab
            valPreset={valPreset}
            setValPreset={setValPreset}
            PRESETS={PRESETS}
            runValidation={runValidation}
            valLoading={valLoading}
            valResult={valResult}
            onExplain={handleOpenExplain}
          />
        )}
        {activeTab === "blocklist" && (
          <BlocklistTab
            blockInput={blockInput}
            setBlockInput={setBlockInput}
            blockIP={blockIP}
            blockReason={blockReason}
            setBlockReason={setBlockReason}
            blockTTL={blockTTL}
            setBlockTTL={setBlockTTL}
            currentUser={currentUser}
            blockedIPs={blockedIPs}
            unblockIP={unblockIP}
          />
        )}
        {activeTab === "devices" && (
          <DevicesTab
            devicesLoading={devicesLoading}
            setDevicesLoading={setDevicesLoading}
            devicesScanMode={devicesScanMode}
            setDevicesScanMode={setDevicesScanMode}
            devicesScanError={devicesScanError}
            setDevicesScanError={setDevicesScanError}
            devices={devices}
            setDevices={setDevices}
            devicesScanTime={devicesScanTime}
            setDevicesScanTime={setDevicesScanTime}
            showToast={showToast}
            currentUser={currentUser}
            setBlockInput={setBlockInput}
            setBlockReason={setBlockReason}
            setActiveTab={setActiveTab}
            API={API}
          />
        )}
        {activeTab === "assistant" && (
          <AssistantTab token={TokenStore.getAccess()} API={API} themeMode={themeMode} />
        )}
        {activeTab === "users" && currentUser?.role === "admin" && (
          <UsersTab token={TokenStore.getAccess()} currentUser={currentUser} themeMode={themeMode} API={API} />
        )}

      </div>

      {/* Explainable AI Modal */}
      <ExplainModal
        isOpen={explainModalOpen}
        onClose={() => setExplainModalOpen(false)}
        record={explainTargetRecord}
        prediction={explainTargetPred}
        token={TokenStore.getAccess()}
        API={API}
        themeMode={themeMode}
      />

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
