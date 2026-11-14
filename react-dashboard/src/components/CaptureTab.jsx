import React, { useState, useEffect } from "react";
import { SectionTitle, StatCard } from "./Common";
import { TokenStore } from "../App";

// Radar animation subcomponent
export function RadarPulse({ active }) {
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

export default function CaptureTab({
  captureMode,
  handleCaptureMode,
  selectedIface,
  setSelectedIface,
  interfaces,
  toggleCapture,
  captureRunning,
  captureLog,
  stats,
  attacks,
  API,
}) {
  const [ebpfStatus, setEbpfStatus] = useState(null);

  useEffect(() => {
    if (!API) return;
    let isMounted = true;
    const fetchEbpf = async () => {
      try {
        const token = TokenStore.getAccess();
        const res = await fetch(`${API}/capture/ebpf/status`, {
          headers: { Authorization: `Bearer ${token}` }
        }).then(r => r.json()).catch(() => null);
        if (isMounted && res) setEbpfStatus(res);
      } catch {
        // silent fallback
      }
    };
    fetchEbpf();
    const id = setInterval(fetchEbpf, 10000);
    return () => { isMounted = false; clearInterval(id); };
  }, [API]);

  return (
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
            <button key={key} onClick={() => handleCaptureMode(key)} className={`mode-btn ${captureMode === key ? "active" : ""}`}>
              <div className="title">{label}</div>
              <div className="desc">{desc}</div>
            </button>
          ))}
        </div>

        {/* SPAN not configured warning */}
        {captureMode === "span" && (!selectedIface || selectedIface.includes("PLACEHOLDER")) && (
          <div style={{ background: "rgba(249,115,22,0.08)", border: "1px solid rgba(249,115,22,0.2)", borderRadius: 8, padding: "10px 14px", marginBottom: 12, fontSize: 12, color: "#f97316" }}>
            ⚠️ SPAN switch mirror interface not configured — set <code style={{ color: "#fbbf24" }}>SPAN_GUID</code> in configuration or select interface below.
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

      <div className="panel" style={{ marginBottom: 16 }}>
        <SectionTitle label="Statistics" title="Session Summary" />
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          <StatCard label="Flows Analyzed" value={(stats.total || 0).toLocaleString()} />
          <StatCard label="Attacks Detected" value={attacks.length} accent="#ef4444" />
          <StatCard label="Attack Rate" value={`${(stats.attack_rate || 0).toFixed(1)}%`} accent="#f97316" />
        </div>
      </div>

      {/* eBPF / XDP Kernel Acceleration Card */}
      <div className="panel">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <SectionTitle label="Kernel Acceleration" title="eBPF / XDP Line-Rate Offload" />
          <span style={{
            fontSize: 11, padding: "3px 8px", borderRadius: 6, fontWeight: 700,
            background: ebpfStatus?.driver_mode ? "rgba(34,211,160,0.12)" : "rgba(255,255,255,0.05)",
            color: ebpfStatus?.driver_mode ? "#22d3a0" : "#94a3b8",
            border: `1px solid ${ebpfStatus?.driver_mode ? "rgba(34,211,160,0.3)" : "rgba(255,255,255,0.1)"}`
          }}>
            ⚡ {ebpfStatus?.driver_mode?.toUpperCase() || "XDP EMULATION"}
          </span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ fontSize: 11, color: "#64748b" }}>Offload Capability</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#f1f5f9", marginTop: 4 }}>10Gbps+ Zero-Copy</div>
          </div>
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ fontSize: 11, color: "#64748b" }}>Kernel Drops</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#ef4444", marginTop: 4 }}>
              {ebpfStatus?.packets_dropped?.toLocaleString() || "0"} pkts
            </div>
          </div>
          <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ fontSize: 11, color: "#64748b" }}>BPF Table Entries</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#38bdf8", marginTop: 4 }}>
              {ebpfStatus?.blocked_ip_count || "0"} IPs
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
