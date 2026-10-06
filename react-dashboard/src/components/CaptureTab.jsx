import React from "react";
import { SectionTitle, StatCard } from "./Common";

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
}) {
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
  );
}
