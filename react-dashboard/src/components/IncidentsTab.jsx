import React from "react";
import { COLORS, SEV_COLOR, SectionTitle, Pill } from "./Common";
import { TokenStore } from "../App";

export default function IncidentsTab({
  attacks,
  currentUser,
  API,
  showToast,
  fetchAll,
  onExplain,
}) {
  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div className="panel">
        <SectionTitle label="Incident Feed" title={`All Attack Events (${attacks.length})`} />
        {attacks.length === 0 ? (
          <div style={{ color: "#22d3a0", fontSize: 13, padding: "20px 0", textAlign: "center" }}>✓ No attacks detected — network is clean</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {attacks.map((r, i) => (
              <div key={i} style={{
                display: "grid", gridTemplateColumns: "140px 1fr 70px 80px 120px 110px 90px", gap: 10,
                padding: "11px 14px", background: "rgba(255,255,255,0.02)", borderRadius: 8,
                borderLeft: `3px solid ${SEV_COLOR[r.severity] || "#475569"}`, alignItems: "center"
              }}>
                <Pill color={COLORS[r.prediction]}>{r.prediction?.replace("_", " ")}</Pill>
                <span style={{ fontSize: 12, color: "#64748b", fontFamily: "monospace" }}>{r.source_ip || "—"}</span>
                <span style={{ fontSize: 12, color: SEV_COLOR[r.severity], fontFamily: "monospace", fontWeight: 600 }}>{(r.confidence * 100).toFixed(1)}%</span>
                <Pill color={SEV_COLOR[r.severity]}>{r.severity?.toUpperCase()}</Pill>
                <span style={{ fontSize: 11, color: "#334155", fontFamily: "monospace" }}>{String(r.timestamp || "").slice(0, 19).replace("T", " ")}</span>
                
                {/* XAI Why Detected Button */}
                <button
                  onClick={() => onExplain && onExplain(r, { prediction: r.prediction, confidence: r.confidence, severity: r.severity })}
                  style={{
                    fontSize: 11, padding: "5px 8px", borderRadius: 6, cursor: "pointer", fontWeight: 700,
                    background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.3)",
                    color: "#38bdf8", transition: "all 0.15s"
                  }}
                >
                  🔍 Why?
                </button>

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
                    fontSize: 11, padding: "5px 8px", borderRadius: 6, cursor: "pointer", fontWeight: 700,
                    background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)",
                    color: "#f87171", transition: "all 0.15s"
                  }}>🚫 Block</button>
                ) : <span />}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
