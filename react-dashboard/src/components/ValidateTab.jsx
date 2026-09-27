import React from "react";
import { COLORS, SEV_COLOR, SectionTitle, Pill } from "./Common";

export default function ValidateTab({
  valPreset,
  setValPreset,
  PRESETS,
  runValidation,
  valLoading,
  valResult,
  onExplain,
}) {
  return (
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
              border: `1px solid ${SEV_COLOR[valResult.severity] || "#22d3a0"}44`,
              display: "flex", alignItems: "center", justifyContent: "space-between"
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <Pill color={COLORS[valResult.prediction] || "#22d3a0"}>{valResult.prediction?.replace("_", " ")}</Pill>
                <span style={{ fontSize: 13, color: "#94a3b8" }}>
                  Confidence: <strong style={{ color: "#f1f5f9", fontFamily: "monospace" }}>{((valResult.confidence || 0) * 100).toFixed(1)}%</strong>
                </span>
                <Pill color={SEV_COLOR[valResult.severity]}>{valResult.severity?.toUpperCase()}</Pill>
              </div>

              {/* XAI Why Detected Button */}
              <button
                onClick={() => onExplain && onExplain(PRESETS[valPreset], valResult)}
                style={{
                  fontSize: 12, padding: "6px 12px", borderRadius: 8, cursor: "pointer", fontWeight: 700,
                  background: "linear-gradient(135deg, #0ea5e9, #2563eb)", border: "none",
                  color: "#fff", transition: "all 0.15s"
                }}
              >
                🔍 Why Detected?
              </button>
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
  );
}
