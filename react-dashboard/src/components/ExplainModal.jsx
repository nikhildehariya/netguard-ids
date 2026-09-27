import React, { useState, useEffect } from "react";
import { Pill, SEV_COLOR } from "./Common";

export default function ExplainModal({ isOpen, onClose, record, prediction, token, API, themeMode }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);

  const isSoft = themeMode === "soft";

  useEffect(() => {
    if (!isOpen || !record) return;

    const fetchExplanation = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${API}/explain`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({ record, prediction })
        });
        if (res.ok) {
          const result = await res.json();
          setData(result);
        }
      } catch {}
      setLoading(false);
    };

    fetchExplanation();
  }, [isOpen, record, prediction, token, API]);

  if (!isOpen) return null;

  return (
    <div style={{
      position: "fixed",
      top: 0, left: 0, right: 0, bottom: 0,
      background: "rgba(2,8,16,0.8)",
      backdropFilter: "blur(8px)",
      zIndex: 9999,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 20
    }}>
      <div style={{
        width: 600,
        maxHeight: "90vh",
        overflowY: "auto",
        background: isSoft ? "#ffffff" : "#0a1628",
        border: isSoft ? "1px solid #cbd5e1" : "1px solid #1e3a5f",
        borderRadius: 20,
        padding: 28,
        boxShadow: "0 25px 50px -12px rgba(0,0,0,0.5)",
        fontFamily: "'Space Grotesk', system-ui, sans-serif"
      }}>
        {/* Header */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 11, color: "#38bdf8", letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>
              Explainable AI (XAI) Attribution
            </div>
            <div style={{ fontSize: 20, fontWeight: 700, color: isSoft ? "#0f172a" : "#f1f5f9" }}>
              Why Detected: {prediction?.prediction || data?.prediction || "Threat Event"}
            </div>
          </div>
          <button onClick={onClose} style={{
            background: "none", border: "none", color: "#64748b", fontSize: 20, cursor: "pointer", padding: 4
          }}>✕</button>
        </div>

        {loading ? (
          <div style={{ padding: "40px 0", textAlign: "center", color: "#38bdf8", fontSize: 14 }}>
            🔍 Analyzing feature contributions and computing tree decision weights...
          </div>
        ) : data ? (
          <div>
            {/* Severity & Confidence Bar */}
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "14px 18px", background: isSoft ? "#f8fafc" : "rgba(255,255,255,0.03)",
              border: isSoft ? "1px solid #e2e8f0" : "1px solid rgba(255,255,255,0.06)",
              borderRadius: 12, marginBottom: 20
            }}>
              <div>
                <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Model Confidence</div>
                <div style={{ fontSize: 18, fontWeight: 800, color: "#38bdf8" }}>{data.confidence_pct}</div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: "#64748b", textTransform: "uppercase" }}>Severity Level</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: SEV_COLOR[data.severity] || "#22d3a0" }}>
                  {data.severity?.toUpperCase()}
                </div>
              </div>
            </div>

            {/* Human Summary */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#38bdf8", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6 }}>
                Detection Evidence & Rationale
              </div>
              <div style={{
                fontSize: 13, color: isSoft ? "#334155" : "#cbd5e1",
                lineHeight: "1.6", background: isSoft ? "#f1f5f9" : "rgba(14,165,233,0.05)",
                borderLeft: "3px solid #0ea5e9", padding: "12px 16px", borderRadius: 8
              }}>
                {data.summary}
              </div>
            </div>

            {/* Feature Attribution List */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#38bdf8", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 10 }}>
                Top Contributing Feature Signals
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {data.top_features?.map((f, idx) => (
                  <div key={idx} style={{
                    padding: "12px 14px",
                    background: isSoft ? "#f8fafc" : "rgba(255,255,255,0.02)",
                    border: isSoft ? "1px solid #e2e8f0" : "1px solid rgba(255,255,255,0.05)",
                    borderRadius: 10
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontSize: 13, fontWeight: 600, color: isSoft ? "#0f172a" : "#f1f5f9" }}>{f.label}</span>
                      <span style={{ fontSize: 12, fontFamily: "monospace", color: "#38bdf8", fontWeight: 700 }}>{f.value}</span>
                    </div>
                    {/* Impact Bar */}
                    <div style={{ width: "100%", background: isSoft ? "#e2e8f0" : "rgba(255,255,255,0.1)", height: 6, borderRadius: 3, overflow: "hidden" }}>
                      <div style={{
                        width: `${Math.min(f.contribution * 100, 100)}%`,
                        height: "100%",
                        background: f.severity === "critical" ? "#ef4444" : f.severity === "high" ? "#f97316" : "#0ea5e9"
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#38bdf8", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 8 }}>
                Recommended Response Actions
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {data.recommendations?.map((r, idx) => (
                  <div key={idx} style={{ fontSize: 12, color: isSoft ? "#475569" : "#94a3b8", display: "flex", gap: 8 }}>
                    <span style={{ color: "#22d3a0" }}>✓</span>
                    <span>{r}</span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        ) : (
          <div style={{ fontSize: 13, color: "#ef4444" }}>Failed to load feature attribution details.</div>
        )}

        {/* Footer */}
        <div style={{ marginTop: 24, textAlign: "right" }}>
          <button onClick={onClose} style={{
            background: "linear-gradient(135deg, #0ea5e9, #2563eb)",
            border: "none", borderRadius: 8, padding: "10px 20px",
            color: "#fff", fontWeight: 700, fontSize: 13, cursor: "pointer"
          }}>
            Close XAI View
          </button>
        </div>
      </div>
    </div>
  );
}
