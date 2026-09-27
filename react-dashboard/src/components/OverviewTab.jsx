import React from "react";
import { AreaChart, Area, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { COLORS, SEV_COLOR, StatCard, SectionTitle, Pill } from "./Common";

export default function OverviewTab({ stats, bc, timelineData, pieData, attacks }) {
  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      {/* Metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12, marginBottom: 24 }}>
        <StatCard label="Total Events" value={(stats.total || 0).toLocaleString()} accent="#38bdf8" />
        <StatCard label="Attack Rate" value={`${(stats.attack_rate || 0).toFixed(1)}%`} accent="#f97316" />
        <StatCard label="DoS / DDoS" value={bc.DOS_DDOS || 0} accent="#ef4444" />
        <StatCard label="Brute Force" value={bc.BRUTE_FORCE || 0} accent="#f97316" />
        <StatCard label="Web Attacks" value={bc.WEB_ATTACK || 0} accent="#a78bfa" />
        <StatCard label="Infiltration" value={bc.INFILTRATION || 0} accent="#ec4899" />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginBottom: 16 }}>
        <div className="panel">
          <SectionTitle label="Traffic Analytics" title="Live Timeline" />
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timelineData}>
              <defs>
                {Object.entries(COLORS).map(([k, c]) => (
                  <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={c} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={c} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <XAxis dataKey="time" tick={{ fill: "#334155", fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#334155", fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 }} />
              {Object.entries(COLORS).map(([k, c]) => (
                <Area key={k} type="monotone" dataKey={k} stroke={c} strokeWidth={1.5} fill={`url(#g-${k})`} dot={false} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
          <SectionTitle label="Distribution" title="By Class" />
          <div style={{ flex: 1, display: "flex", alignItems: "center" }}>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData.length ? pieData : [{ name: "NORMAL", value: 1 }]}
                  cx="50%" cy="50%" innerRadius={55} outerRadius={80} dataKey="value" stroke="none">
                  {(pieData.length ? pieData : [{ name: "NORMAL" }]).map((e, i) => (
                    <Cell key={i} fill={COLORS[e.name] || "#334155"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
            {Object.entries(COLORS).map(([k, c]) => (
              <div key={k} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: c }} />
                <span style={{ fontSize: 10, color: "#475569" }}>{k.replace("_", " ")}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent attacks */}
      <div className="panel">
        <SectionTitle label="Incident Feed" title="Recent Attack Events" />
        {attacks.length === 0 ? (
          <div style={{ color: "#22d3a0", fontSize: 13, padding: "12px 0" }}>✓ Network is clean — no attacks detected</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {attacks.slice(0, 8).map((r, i) => (
              <div key={i} style={{
                display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 14px",
                background: "rgba(255,255,255,0.02)", borderRadius: 8,
                borderLeft: `3px solid ${SEV_COLOR[r.severity] || "#475569"}`
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <Pill color={COLORS[r.prediction]}>{r.prediction?.replace("_", " ")}</Pill>
                  <span style={{ fontSize: 12, color: "#64748b" }}>{r.source_ip || "unknown"}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                  <span style={{ fontSize: 12, color: SEV_COLOR[r.severity], fontFamily: "monospace" }}>{(r.confidence * 100).toFixed(1)}%</span>
                  <span style={{ fontSize: 11, color: "#334155", fontFamily: "monospace" }}>{String(r.timestamp || "").slice(11, 19)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
