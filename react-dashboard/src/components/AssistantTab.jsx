import React, { useState, useEffect, useRef } from "react";
import { SectionTitle, StatCard, Pill } from "./Common";

export default function AssistantTab({ token, API, themeMode }) {
  const [messages, setMessages] = useState([
    {
      sender: "ai",
      text: "👋 **Hello! I am NetGuard AI Security Co-pilot.**\n\nI analyze real-time network traffic, explain threat detections, and recommend active firewall policies.\n\nHow can I assist your security team today?",
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [briefing, setBriefing] = useState(null);
  const chatEndRef = useRef(null);

  const isSoft = themeMode === "soft";
  const authHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  const loadBriefing = async () => {
    try {
      const res = await fetch(`${API}/assistant/insights`, { headers: authHeaders });
      if (res.ok) {
        const data = await res.json();
        setBriefing(data);
      }
    } catch {}
  };

  useEffect(() => {
    loadBriefing();
  }, []);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendQuery = async (queryText) => {
    const q = (queryText || input).trim();
    if (!q || loading) return;

    const userMsg = {
      sender: "user",
      text: q,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    if (!queryText) setInput("");
    setLoading(true);

    try {
      const res = await fetch(`${API}/assistant/chat`, {
        method: "POST",
        headers: authHeaders,
        body: JSON.stringify({ query: q })
      });

      if (res.ok) {
        const data = await res.json();
        const aiMsg = {
          sender: "ai",
          text: data.reply || "Analysis complete.",
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        setMessages(prev => [...prev, aiMsg]);
      } else {
        setMessages(prev => [...prev, {
          sender: "ai",
          text: "⚠️ System busy or request error. Please try again.",
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }]);
      }
    } catch {
      setMessages(prev => [...prev, {
        sender: "ai",
        text: "🚨 Unable to connect to GenAI Assistant endpoint.",
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    }
    setLoading(false);
  };

  const samplePrompts = [
    "Summarize network threats",
    "How to mitigate DoS attacks?",
    "Recommend firewall rules",
    "Explain Infiltration detection"
  ];

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        
        {/* Chat Panel */}
        <div className="panel" style={{ display: "flex", flexDirection: "column", height: 600 }}>
          <SectionTitle label="GenAI Copilot" title="Security Analyst AI Assistant" />
          
          {/* Message History */}
          <div style={{
            flex: 1,
            overflowY: "auto",
            paddingRight: 8,
            display: "flex",
            flexDirection: "column",
            gap: 14,
            marginBottom: 16
          }}>
            {messages.map((m, i) => (
              <div key={i} style={{
                alignSelf: m.sender === "user" ? "flex-end" : "flex-start",
                maxWidth: "85%",
                background: m.sender === "user" 
                  ? "linear-gradient(135deg, #0ea5e9, #2563eb)" 
                  : isSoft ? "#f1f5f9" : "rgba(255,255,255,0.04)",
                border: m.sender === "user" ? "none" : isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.08)",
                borderRadius: 14,
                padding: "12px 16px",
                color: m.sender === "user" ? "#ffffff" : isSoft ? "#0f172a" : "#e2e8f0",
                fontSize: 13,
                lineHeight: "1.5"
              }}>
                <div style={{ fontSize: 10, opacity: 0.7, marginBottom: 4, display: "flex", justifyContent: "space-between", gap: 12 }}>
                  <span>{m.sender === "user" ? "Security Analyst" : "🤖 NetGuard Copilot"}</span>
                  <span>{m.time}</span>
                </div>
                <div style={{ whiteSpace: "pre-wrap" }}>{m.text}</div>
              </div>
            ))}
            {loading && (
              <div style={{ alignSelf: "flex-start", background: "rgba(255,255,255,0.04)", borderRadius: 14, padding: "10px 16px", fontSize: 12, color: "#38bdf8" }}>
                🤖 Analyzing security telemetry & generating insights...
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Quick Prompt Pills */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
            {samplePrompts.map((prompt, idx) => (
              <button key={idx} onClick={() => sendQuery(prompt)} style={{
                background: "rgba(14,165,233,0.1)",
                border: "1px solid rgba(14,165,233,0.25)",
                borderRadius: 20,
                padding: "6px 12px",
                color: "#38bdf8",
                fontSize: 11,
                cursor: "pointer",
                fontWeight: 600
              }}>
                ⚡ {prompt}
              </button>
            ))}
          </div>

          {/* Input Box */}
          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && sendQuery()}
              placeholder="Ask NetGuard AI Copilot (e.g., 'Summarize incidents', 'How to block DDoS')..."
              style={{
                flex: 1,
                background: isSoft ? "#ffffff" : "rgba(255,255,255,0.05)",
                border: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.1)",
                borderRadius: 10,
                padding: "12px 14px",
                color: isSoft ? "#0f172a" : "#f1f5f9",
                fontSize: 13,
                outline: "none"
              }}
            />
            <button onClick={() => sendQuery()} style={{
              background: "linear-gradient(135deg, #0ea5e9, #2563eb)",
              border: "none",
              borderRadius: 10,
              padding: "0 20px",
              color: "#fff",
              fontWeight: 700,
              fontSize: 13,
              cursor: "pointer"
            }}>
              Send
            </button>
          </div>
        </div>

        {/* Live Threat Intelligence Briefing Panel */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="panel">
            <SectionTitle label="AI Briefing" title="Live Threat Assessment" />
            {briefing ? (
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                  <div style={{
                    width: 10, height: 10, borderRadius: "50%",
                    background: briefing.status_level === "GREEN" ? "#22d3a0" : briefing.status_level === "ORANGE" ? "#f97316" : "#ef4444"
                  }} />
                  <span style={{ fontSize: 13, fontWeight: 700, color: briefing.status_level === "GREEN" ? "#22d3a0" : "#f97316" }}>
                    {briefing.status_level} STATUS
                  </span>
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: isSoft ? "#0f172a" : "#f1f5f9", marginBottom: 8 }}>
                  {briefing.headline}
                </div>
                <div style={{ fontSize: 12, color: isSoft ? "#475569" : "#94a3b8", lineHeight: "1.5", marginBottom: 16 }}>
                  {briefing.assessment}
                </div>

                <div style={{ fontSize: 11, fontWeight: 700, color: "#38bdf8", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 8 }}>
                  Recommended Action Items
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {briefing.action_items?.map((item, idx) => (
                    <div key={idx} style={{ fontSize: 11, color: isSoft ? "#334155" : "#cbd5e1", display: "flex", gap: 6 }}>
                      <span>✓</span>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ fontSize: 12, color: "#64748b" }}>Loading AI Briefing...</div>
            )}
          </div>

          <div className="panel">
            <SectionTitle label="Architecture" title="Modular XAI Engine" />
            <div style={{ fontSize: 12, color: isSoft ? "#475569" : "#94a3b8", lineHeight: "1.5" }}>
              NetGuard features a decoupled <strong>Explainable AI (XAI)</strong> attribution module.
              Click <strong>"🔍 Why Detected?"</strong> on any incident to view feature importance breakdowns and root-cause evidence.
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
