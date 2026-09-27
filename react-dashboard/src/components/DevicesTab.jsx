import React from "react";
import { SectionTitle } from "./Common";
import { TokenStore } from "../App";

export default function DevicesTab({
  devicesLoading,
  setDevicesLoading,
  devicesScanMode,
  setDevicesScanMode,
  devicesScanError,
  setDevicesScanError,
  devices,
  setDevices,
  devicesScanTime,
  setDevicesScanTime,
  showToast,
  currentUser,
  setBlockInput,
  setBlockReason,
  setActiveTab,
  API,
}) {
  return (
    <div style={{ animation: "fadeIn 0.2s ease" }}>
      <div className="panel" style={{ marginBottom: 20 }}>
        <SectionTitle label="Network Scanner" title="Connected Devices" />
        <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
          <button className="action-btn" disabled={devicesLoading} onClick={async () => {
            setDevicesLoading(true);
            setDevicesScanMode("arp");
            setDevicesScanError("");
            try {
              const ctrl = new AbortController();
              const tid = setTimeout(() => ctrl.abort(), 90000); // 90s timeout
              const res = await fetch(`${API}/network/scan/arp`, {
                method: "POST",
                headers: { Authorization: `Bearer ${TokenStore.getAccess()}` },
                signal: ctrl.signal,
              });
              clearTimeout(tid);
              const r = await res.json().catch(() => ({}));
              if (!res.ok) throw new Error(r.detail || "ARP scan failed");
              setDevices(r.devices || []);
              setDevicesScanTime(r.timestamp);
              showToast(`Quick scan found ${r.total || 0} devices`);
            } catch (e) {
              const msg = e.name === "AbortError" ? "Quick scan timed out" : (e.message || "Quick scan failed");
              setDevicesScanError(msg);
              showToast(msg, "error");
            }
            setDevicesLoading(false);
            setDevicesScanMode(null);
          }}>
            {devicesLoading && devicesScanMode === "arp" ? "⏳ Scanning (30-60s)..." : "⚡ Quick ARP Scan"}
          </button>
          <button className="action-btn" disabled={devicesLoading} onClick={async () => {
            setDevicesLoading(true);
            setDevicesScanMode("full");
            setDevicesScanError("");
            try {
              const ctrl = new AbortController();
              const tid = setTimeout(() => ctrl.abort(), 180000); // 3 min timeout
              const res = await fetch(`${API}/network/scan`, {
                method: "POST",
                headers: { Authorization: `Bearer ${TokenStore.getAccess()}` },
                signal: ctrl.signal,
              });
              clearTimeout(tid);
              const r = await res.json().catch(() => ({}));
              if (!res.ok) throw new Error(r.detail || "Full scan failed");
              if (!r.devices) throw new Error("Full scan timed out before results were ready");
              setDevices(r.devices || []);
              setDevicesScanTime(r.timestamp);
              showToast(`Full scan found ${r.total || 0} devices`);
            } catch (e) {
              const msg = e.name === "AbortError" ? "Full scan timed out" : (e.message || "Full scan failed");
              setDevicesScanError(msg);
              showToast(msg, "error");
            }
            setDevicesLoading(false);
            setDevicesScanMode(null);
          }}>
            {devicesLoading && devicesScanMode === "full" ? "⏳ Scanning (60-120s)..." : "🔍 Full ARP + Nmap Scan"}
          </button>
          {devicesScanTime && (
            <span style={{ fontSize: 11, color: "#475569", alignSelf: "center" }}>
              Last scan: {devicesScanTime.replace("T", " ")}
            </span>
          )}
        </div>

        {devicesScanError && !devicesLoading && (
          <div style={{
            background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.22)",
            borderRadius: 10, padding: "10px 14px", marginBottom: 14,
            color: "#f87171", fontSize: 12
          }}>
            {devicesScanError}
          </div>
        )}

        {devicesLoading && (
          <div style={{ textAlign: "center", padding: "40px 0", color: "#38bdf8" }}>
            <div style={{ fontSize: 24, marginBottom: 12 }}>📡</div>
            <div style={{ fontSize: 13, color: "#64748b" }}>
              {devicesScanMode === "full"
                ? "Ping sweep → ARP → Nmap... please wait 30-60 seconds"
                : "Ping sweep → ARP scan... please wait 5-15 seconds"}
            </div>
          </div>
        )}

        {!devicesLoading && devices.length === 0 && (
          <div style={{ textAlign: "center", padding: "40px 0", color: "#475569" }}>
            <div style={{ fontSize: 32, marginBottom: 12 }}>🌐</div>
            <div style={{ fontSize: 13 }}>Click "Quick ARP Scan" to discover devices on your network</div>
          </div>
        )}

        {!devicesLoading && devices.length > 0 && (
          <div>
            <div style={{ fontSize: 12, color: "#475569", marginBottom: 14 }}>
              Discovered <span style={{ color: "#38bdf8", fontWeight: 700 }}>{devices.length}</span> devices on network
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {devices.map((d, i) => (
                <div key={i} style={{
                  padding: "14px 16px",
                  background: d.is_self ? "rgba(56,189,248,0.06)" : d.is_gateway ? "rgba(34,211,160,0.06)" : "rgba(255,255,255,0.02)",
                  border: `1px solid ${d.is_self ? "rgba(56,189,248,0.2)" : d.is_gateway ? "rgba(34,211,160,0.15)" : "rgba(255,255,255,0.06)"}`,
                  borderRadius: 10
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <div style={{ fontSize: 20 }}>
                        {d.device_type === "this_device" || d.is_self
                          ? "💻"
                          : d.device_type === "gateway" || d.is_gateway
                            ? "📶"
                            : d.device_type === "phone"
                              ? "📱"
                              : d.device_type === "computer"
                                ? "🖥️"
                                : "◇"}
                      </div>
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ fontSize: 15, fontFamily: "monospace", color: "#38bdf8", fontWeight: 700 }}>{d.ip}</span>
                          {d.is_self && <span style={{ fontSize: 10, background: "rgba(56,189,248,0.15)", color: "#38bdf8", borderRadius: 4, padding: "2px 6px", fontWeight: 700 }}>THIS DEVICE</span>}
                          {d.is_gateway && <span style={{ fontSize: 10, background: "rgba(34,211,160,0.15)", color: "#22d3a0", borderRadius: 4, padding: "2px 6px", fontWeight: 700 }}>GATEWAY</span>}
                        </div>
                        <div style={{ fontSize: 12, color: "#64748b", marginTop: 3 }}>
                          {d.hostname !== "unknown" && <span style={{ marginRight: 12 }}>🏷️ {d.hostname}</span>}
                          {d.vendor !== "Unknown" && <span>🏭 {d.vendor}</span>}
                        </div>
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: 11, fontFamily: "monospace", color: "#475569" }}>{d.mac || "—"}</div>
                      <div style={{
                        fontSize: 10,
                        color: d.status === "online" || d.status === "up" ? "#22d3a0" : d.status === "seen_recently" ? "#f97316" : "#ef4444",
                        marginTop: 3,
                        fontWeight: 600
                      }}>
                        ● {d.status === "seen_recently" ? "SEEN RECENTLY" : d.status?.toUpperCase()}
                      </div>
                    </div>
                  </div>
                  {d.open_ports && d.open_ports.length > 0 && (
                    <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {d.open_ports.slice(0, 8).map((p, pi) => (
                        <span key={pi} style={{
                          fontSize: 10, fontFamily: "monospace",
                          background: "rgba(167,139,250,0.1)", color: "#a78bfa",
                          border: "1px solid rgba(167,139,250,0.2)",
                          borderRadius: 4, padding: "2px 7px"
                        }}>{p.port}/{p.proto} {p.service}</span>
                      ))}
                      {d.open_ports.length > 8 && (
                        <span style={{ fontSize: 10, color: "#475569" }}>+{d.open_ports.length - 8} more</span>
                      )}
                    </div>
                  )}
                  {d.os && d.os !== "unknown" && (
                    <div style={{ marginTop: 6, fontSize: 11, color: "#475569" }}>🖥️ OS: {d.os}</div>
                  )}
                  <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                    {(currentUser?.role === "admin" || currentUser?.role === "analyst") && !d.is_self && !d.is_gateway && (
                      <button className="danger-btn" style={{ padding: "5px 12px", fontSize: 11 }}
                        onClick={() => {
                          setBlockInput(d.ip);
                          setBlockReason(`Suspicious device: ${d.hostname || d.ip}`);
                          setActiveTab("blocklist");
                        }}>
                        🚫 Block IP
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
