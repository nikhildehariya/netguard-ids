import React, { useState, useEffect } from "react";

const ROLE_COLORS = { admin: "#ef4444", analyst: "#f97316", viewer: "#22d3a0" };

export default function UsersTab({ token, currentUser, themeMode, API }) {
  const [users, setUsers] = useState([]);
  const [alertEmail, setAlertEmail] = useState("");
  const [configuredAlertEmail, setConfiguredAlertEmail] = useState("");
  const [defaultAdminEmail, setDefaultAdminEmail] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "viewer", full_name: "", phone: "", designation: "" });
  const [msg, setMsg] = useState("");
  const [loading, setLoading] = useState(false);
  const [savingAlert, setSavingAlert] = useState(false);

  const authHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  const loadUsers = async () => {
    const r = await fetch(`${API}/auth/users`, { headers: authHeaders }).catch(() => null);
    if (r?.ok) { const d = await r.json(); setUsers(d.users || []); }
  };

  const loadAlertSettings = async () => {
    const r = await fetch(`${API}/admin/alert-settings`, { headers: authHeaders }).catch(() => null);
    if (r?.ok) {
      const d = await r.json();
      setAlertEmail(d.alert_to_email || "");
      setConfiguredAlertEmail(d.configured_alert_to_email || "");
      setDefaultAdminEmail(d.default_admin_email || "");
    }
  };

  useEffect(() => {
    loadUsers();
    loadAlertSettings();
  }, []);

  const createUser = async () => {
    setLoading(true);
    const r = await fetch(`${API}/auth/users`, { method: "POST", headers: authHeaders, body: JSON.stringify(form) }).catch(() => null);
    if (r?.ok) { const d = await r.json(); setMsg(d.message); setShowCreate(false); setForm({ username: "", email: "", password: "", role: "viewer", full_name: "", phone: "", designation: "" }); loadUsers(); }
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

  const saveAlertRecipient = async () => {
    setSavingAlert(true);
    const r = await fetch(`${API}/admin/alert-settings`, {
      method: "PATCH",
      headers: authHeaders,
      body: JSON.stringify({ alert_to_email: alertEmail }),
    }).catch(() => null);
    if (r?.ok) {
      const d = await r.json();
      setAlertEmail(d.alert_to_email || "");
      setConfiguredAlertEmail(d.configured_alert_to_email || "");
      setDefaultAdminEmail(d.default_admin_email || "");
      setMsg("Alert recipient email updated successfully.");
    } else {
      const d = await r?.json();
      setMsg(d?.detail || "Failed to update alert recipient.");
    }
    setSavingAlert(false);
  };

  const isSoft = themeMode === "soft";
  const inputStyle = {
    width: "100%",
    background: isSoft ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.05)",
    border: isSoft ? "1px solid rgba(148,163,184,0.3)" : "1px solid rgba(255,255,255,0.1)",
    borderRadius: 8,
    padding: "10px 12px",
    color: isSoft ? "#0f172a" : "#f1f5f9",
    fontSize: 13,
    outline: "none",
    marginBottom: 12
  };
  const labelStyle = { fontSize: 11, color: isSoft ? "#334155" : "#64748b", textTransform: "uppercase", letterSpacing: "0.08em", display: "block", marginBottom: 6, fontWeight: 600 };

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <div style={{ fontSize: 11, color: "#38bdf8", letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>User Management</div>
          <div className="soft-readable" style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9" }}>{users.length} Registered Users</div>
        </div>
        <button onClick={() => setShowCreate(s => !s)} style={{ background: "linear-gradient(135deg,#0ea5e9,#2563eb)", border: "none", borderRadius: 10, padding: "10px 20px", color: "white", fontSize: 13, fontWeight: 700, cursor: "pointer" }}>
          + Create User
        </button>
      </div>

      {msg && <div style={{ background: "rgba(34,211,160,0.1)", border: "1px solid rgba(34,211,160,0.2)", borderRadius: 8, padding: "10px 14px", marginBottom: 16, fontSize: 13, color: "#22d3a0" }}>{msg}</div>}

      <div style={{ background: isSoft ? "rgba(255,255,255,0.55)" : "rgba(10,22,40,0.8)", border: isSoft ? "1px solid rgba(148,163,184,0.25)" : "1px solid rgba(255,255,255,0.08)", borderRadius: 16, padding: "24px", marginBottom: 20 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: isSoft ? "#0f172a" : "#f1f5f9", marginBottom: 6 }}>Notification Settings</div>
        <div style={{ fontSize: 12, color: isSoft ? "#475569" : "#64748b", marginBottom: 16 }}>
          Security alert emails will be sent to this address.
        </div>
        <label style={labelStyle}>Alert Recipient Email</label>
        <input
          value={alertEmail}
          onChange={e => setAlertEmail(e.target.value)}
          placeholder="admin@example.com"
          type="email"
          style={inputStyle}
        />
        <div style={{ fontSize: 11, color: isSoft ? "#64748b" : "#475569", marginBottom: 12 }}>
          {configuredAlertEmail
            ? `Configured recipient: ${configuredAlertEmail}`
            : `Fallback (first active admin): ${defaultAdminEmail || "not available"}`}
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={saveAlertRecipient}
            disabled={savingAlert}
            style={{
              padding: "10px 14px",
              borderRadius: 8,
              background: "linear-gradient(135deg,#0ea5e9,#2563eb)",
              border: "none",
              color: "white",
              fontSize: 12,
              fontWeight: 700,
              cursor: "pointer"
            }}
          >
            {savingAlert ? "Saving..." : "Save Recipient"}
          </button>
          <button
            onClick={loadAlertSettings}
            style={{
              padding: "10px 14px",
              borderRadius: 8,
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.08)",
              color: "#94a3b8",
              fontSize: 12,
              cursor: "pointer"
            }}
          >
            Reload
          </button>
        </div>
      </div>

      {/* Create User Form */}
      {showCreate && (
        <div style={{ background: isSoft ? "rgba(255,255,255,0.55)" : "rgba(10,22,40,0.8)", border: isSoft ? "1px solid rgba(148,163,184,0.25)" : "1px solid rgba(255,255,255,0.08)", borderRadius: 16, padding: "24px", marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: isSoft ? "#0f172a" : "#f1f5f9", marginBottom: 20 }}>Create New User</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div><label style={labelStyle}>Username</label><input value={form.username} onChange={e => setForm(p => ({ ...p, username: e.target.value }))} placeholder="username" style={inputStyle} /></div>
            <div><label style={labelStyle}>Email</label><input value={form.email} onChange={e => setForm(p => ({ ...p, email: e.target.value }))} placeholder="user@example.com" type="email" style={inputStyle} /></div>
            <div><label style={labelStyle}>Password</label><input value={form.password} onChange={e => setForm(p => ({ ...p, password: e.target.value }))} placeholder="min 8 chars" type="password" style={inputStyle} /></div>
            <div><label style={labelStyle}>Full Name</label><input value={form.full_name} onChange={e => setForm(p => ({ ...p, full_name: e.target.value }))} placeholder="Full Name" style={inputStyle} /></div>
            <div><label style={labelStyle}>Phone Number</label><input value={form.phone} onChange={e => setForm(p => ({ ...p, phone: e.target.value }))} placeholder="+91..." style={inputStyle} /></div>
            <div><label style={labelStyle}>Department/Designation</label><input value={form.designation} onChange={e => setForm(p => ({ ...p, designation: e.target.value }))} placeholder="e.g. IT Security" style={inputStyle} /></div>
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
      <div className="users-table" style={{ background: "rgba(10,22,40,0.6)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 16, overflow: "hidden" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1.5fr 120px 100px 160px", padding: "12px 20px", borderBottom: "1px solid rgba(255,255,255,0.05)", background: "rgba(0,0,0,0.2)" }}>
          {["USER DETAILS", "CONTACT INFO", "ROLE", "STATUS", "ACTIONS"].map(h => (
            <div key={h} style={{ fontSize: 10, fontWeight: 700, color: "#334155", letterSpacing: "0.1em" }}>{h}</div>
          ))}
        </div>
        {users.map((u, i) => (
          <div key={u.id} style={{ display: "grid", gridTemplateColumns: "1.2fr 1.5fr 120px 100px 160px", padding: "14px 20px", borderBottom: i < users.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", alignItems: "center", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,0.01)" }}>
            <div className="users-name" style={{ fontSize: 13, color: "#f1f5f9" }}>
              <div style={{ fontWeight: 600, display: "flex", alignItems: "center" }}>
                {u.username}
                {u.username === currentUser?.username && <span style={{ fontSize: 9, color: "#38bdf8", marginLeft: 6, background: "rgba(56,189,248,0.15)", padding: "1px 5px", borderRadius: 4 }}>(you)</span>}
              </div>
              <div style={{ fontSize: 11, color: isSoft ? "#475569" : "#94a3b8", marginTop: 2 }}>{u.full_name || "—"}</div>
              <div style={{ fontSize: 10, color: "#0ea5e9", marginTop: 2, fontWeight: 500 }}>{u.designation || "—"}</div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: isSoft ? "#334155" : "#cbd5e1", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.email}</div>
              <div style={{ fontSize: 11, color: isSoft ? "#64748b" : "#64748b", marginTop: 2 }}>{u.phone || "—"}</div>
            </div>
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
