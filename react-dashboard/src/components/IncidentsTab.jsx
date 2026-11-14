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
                display: "grid", gridTemplateColumns: "140px 1fr 65px 80px 120px auto", gap: 10,
                padding: "11px 14px", background: "rgba(255,255,255,0.02)", borderRadius: 8,
                borderLeft: `3px solid ${SEV_COLOR[r.severity] || "#475569"}`, alignItems: "center"
              }}>
                <Pill color={COLORS[r.prediction]}>{r.prediction?.replace("_", " ")}</Pill>
                <div style={{ display: "flex", alignItems: "center", gap: 6, overflow: "hidden" }}>
                  <span style={{ fontSize: 12, color: "#64748b", fontFamily: "monospace" }}>{r.source_ip || "—"}</span>
                  {(r.threat_intel || r.prediction === "C2_COMMUNICATION") && (
                    <span style={{ fontSize: 9, padding: "2px 5px", borderRadius: 4, background: "rgba(239,68,68,0.18)", color: "#f87171", border: "1px solid rgba(239,68,68,0.35)", fontWeight: 700, whiteSpace: "nowrap" }}>
                      🛡️ C2 Threat Intel
                    </span>
                  )}
                  {r.prediction?.includes("MIRAI") && (
                    <span style={{ fontSize: 9, padding: "2px 5px", borderRadius: 4, background: "rgba(249,115,22,0.18)", color: "#fb923c", border: "1px solid rgba(249,115,22,0.35)", fontWeight: 700, whiteSpace: "nowrap" }}>
                      🤖 Botnet Swarm
                    </span>
                  )}
                </div>
                <span style={{ fontSize: 12, color: SEV_COLOR[r.severity], fontFamily: "monospace", fontWeight: 600 }}>{(r.confidence * 100).toFixed(1)}%</span>
                <Pill color={SEV_COLOR[r.severity]}>{r.severity?.toUpperCase()}</Pill>
                <span style={{ fontSize: 11, color: "#334155", fontFamily: "monospace" }}>{String(r.timestamp || "").slice(0, 19).replace("T", " ")}</span>
                
                <div style={{ display: "flex", gap: 6, justifyContent: "flex-end", flexWrap: "wrap" }}>
                  {/* XAI Why Detected Button */}
                  <button
                    onClick={() => onExplain && onExplain(r, { prediction: r.prediction, confidence: r.confidence, severity: r.severity })}
                    style={{
                      fontSize: 11, padding: "5px 8px", borderRadius: 6, cursor: "pointer", fontWeight: 700,
                      background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.3)",
                      color: "#38bdf8", transition: "all 0.15s"
                    }}
                    title="Explain prediction via TreeSHAP feature attribution"
                  >
                    🔍 Why?
                  </button>

                  {/* Forensic PCAP Capture/Download Button */}
                  <button
                    onClick={async () => {
                      try {
                        const token = TokenStore.getAccess();
                        const res = await fetch(`${API}/forensics/trigger-dump?source_ip=${encodeURIComponent(r.source_ip || "127.0.0.1")}&label=${encodeURIComponent(r.prediction || "ALERT")}`, {
                          method: "POST",
                          headers: { Authorization: `Bearer ${token}` }
                        }).then(x => x.json()).catch(() => ({}));
                        if (res?.success && res?.pcap_path) {
                          showToast(`Forensic PCAP captured: ${res.pcap_path}`);
                          window.open(`${API}/forensics/download/${encodeURIComponent(res.pcap_path)}?token=${encodeURIComponent(token || "")}`, "_blank");
                        } else {
                          showToast(res?.message || "Triggered forensic PCAP snapshot");
                        }
                      } catch {
                        showToast("PCAP snapshot request dispatched");
                      }
                    }}
                    style={{
                      fontSize: 11, padding: "5px 8px", borderRadius: 6, cursor: "pointer", fontWeight: 700,
                      background: "rgba(168,85,247,0.1)", border: "1px solid rgba(168,85,247,0.3)",
                      color: "#c084fc", transition: "all 0.15s"
                    }}
                    title="Export 60-second raw packet PCAP for Wireshark inspection"
                  >
                    📦 PCAP
                  </button>

                  {/* Active Learning False Positive Retrain Button */}
                  {(currentUser?.role === "admin" || currentUser?.role === "analyst") && (
                    <button
                      onClick={async () => {
                        try {
                          const token = TokenStore.getAccess();
                          const res = await fetch(`${API}/retrain/feedback`, {
                            method: "POST",
                            headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
                            body: JSON.stringify({
                              flow_features: r.features || {},
                              original_prediction: r.prediction,
                              analyst_label: "BENIGN",
                              source_ip: r.source_ip || "unknown"
                            })
                          }).then(x => x.json()).catch(() => ({}));
                          showToast(res.message || "Feedback queued for Active Learning Retraining");
                        } catch {
                          showToast("Feedback submitted to retraining pipeline");
                        }
                      }}
                      style={{
                        fontSize: 11, padding: "5px 8px", borderRadius: 6, cursor: "pointer", fontWeight: 700,
                        background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)",
                        color: "#34d399", transition: "all 0.15s"
                      }}
                      title="Report false positive to Active Learning queue for incremental model retraining"
                    >
                      🔄 Retrain
                    </button>
                  )}

                  {/* Firewall / eBPF / SOAR Block Button */}
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
                    }}
                    title="Push dynamic block to Windows Firewall, eBPF XDP table, and SOAR switch quarantine"
                    >🚫 Block</button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
