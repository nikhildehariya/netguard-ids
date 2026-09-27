import React from "react";
import { SectionTitle } from "./Common";

export default function BlocklistTab({
  blockInput,
  setBlockInput,
  blockIP,
  blockReason,
  setBlockReason,
  blockTTL,
  setBlockTTL,
  currentUser,
  blockedIPs,
  unblockIP,
}) {
  return (
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
                  {b.blocked_at && <span style={{ fontSize: 11, color: "#334155", fontFamily: "monospace" }}>🕐 {b.blocked_at.slice(0, 19).replace("T", " ")}</span>}
                  {b.expires_at && <span style={{ fontSize: 11, color: "#f97316" }}>⏱ expires {b.expires_at.slice(0, 19).replace("T", " ")}</span>}
                  {!b.expires_at && <span style={{ fontSize: 11, color: "#475569" }}>∞ permanent</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
