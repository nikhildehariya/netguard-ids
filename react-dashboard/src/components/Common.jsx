import React from "react";

export const COLORS = {
  NORMAL: "#22d3a0",
  BRUTE_FORCE: "#f97316",
  DOS_DDOS: "#ef4444",
  WEB_ATTACK: "#a78bfa",
  INFILTRATION: "#ec4899",
};

export const SEV_COLOR = { none: "#22d3a0", high: "#f97316", critical: "#ef4444" };

export function Pill({ children, color = "#22d3a0" }) {
  return (
    <span style={{
      background: color + "22", color, border: `1px solid ${color}44`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 600,
      letterSpacing: "0.06em", textTransform: "uppercase", fontFamily: "monospace"
    }}>{children}</span>
  );
}

export function StatCard({ label, value, sub, accent }) {
  return (
    <div className="glow-card" style={{
      background: "rgba(10,22,45,0.4)",
      border: accent ? `1px solid ${accent}33` : "1px solid rgba(255,255,255,0.06)",
      borderRadius: 16,
      padding: "20px 22px",
      position: "relative",
      overflow: "hidden",
      boxShadow: accent ? `0 4px 20px ${accent}08` : "none",
      transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
      backdropFilter: "blur(10px)"
    }}>
      {accent && <div style={{ position: "absolute", top: 0, left: 0, width: 4, height: "100%", background: accent, boxShadow: `0 0 12px ${accent}` }} />}
      <div style={{ fontSize: 11, color: "#64748b", letterSpacing: "0.12em", textTransform: "uppercase", fontWeight: 700, marginBottom: 10 }}>{label}</div>
      <div style={{ fontSize: 32, fontWeight: 700, color: "#f1f5f9", fontFamily: "'Space Mono', monospace", lineHeight: 1, letterSpacing: "-0.03em" }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: "#475569", marginTop: 8, letterSpacing: "0.02em" }}>{sub}</div>}
    </div>
  );
}

export function SectionTitle({ label, title }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 10, color: "#38bdf8", letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 17, fontWeight: 600, color: "#f1f5f9" }}>{title}</div>
    </div>
  );
}

export function Divider() {
  return <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", margin: "28px 0" }} />;
}
