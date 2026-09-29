import React, { useState, useEffect, useRef } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Bot,
  User,
  Send,
  Sparkles,
  Copy,
  Check,
  Trash2,
  RefreshCw,
  Zap,
  ShieldCheck,
  Terminal,
  Activity,
  CheckCircle2,
  Cpu,
  Info
} from "lucide-react";
import { SectionTitle } from "./Common";

function CodeBlock({ code, isSoft }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{
      margin: "10px 0",
      borderRadius: 10,
      overflow: "hidden",
      border: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.12)",
      background: isSoft ? "#f8fafc" : "#070f1e",
      boxShadow: "0 4px 12px rgba(0,0,0,0.15)"
    }}>
      <div style={{
        display: "flex",
        justify: "space-between",
        alignItems: "center",
        padding: "6px 12px",
        background: isSoft ? "#e2e8f0" : "#0d1b2e",
        fontSize: 11,
        color: isSoft ? "#475569" : "#94a3b8",
        fontFamily: "'Space Mono', monospace",
        borderBottom: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.06)"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <Terminal size={13} color="#38bdf8" />
          <span style={{ fontWeight: 600 }}>Command / Output</span>
        </div>
        <button
          onClick={handleCopy}
          style={{
            background: "transparent",
            border: "none",
            color: copied ? "#22d3a0" : isSoft ? "#475569" : "#94a3b8",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: 4,
            fontSize: 11,
            fontWeight: 600
          }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          <span>{copied ? "Copied" : "Copy code"}</span>
        </button>
      </div>
      <pre style={{
        margin: 0,
        padding: "12px 14px",
        overflowX: "auto",
        fontSize: 12,
        fontFamily: "'Space Mono', monospace",
        color: isSoft ? "#0f172a" : "#f1f5f9",
        lineHeight: 1.5
      }}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

export default function AssistantTab({ token, API, themeMode }) {
  const [messages, setMessages] = useState([
    {
      sender: "ai",
      text: "👋 **Hello! I am NetGuard AI Security Co-pilot.**\n\nI analyze real-time network traffic, explain threat detections, and recommend active firewall policies.\n\n### How can I assist your security team today?\n- **Summarize network threats**: Get an immediate overview of active incident vectors.\n- **Mitigate DoS/DDoS**: Recommended rate-limiting and active drop rules.\n- **Firewall recommendations**: Generate copy-ready rules for immediate blocking.",
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [briefing, setBriefing] = useState(null);
  const [copiedIndex, setCopiedIndex] = useState(null);
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
  }, [messages, loading]);

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
          text: "⚠️ **System Busy**: Request failed or timed out. Please try again.",
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }]);
      }
    } catch {
      setMessages(prev => [...prev, {
        sender: "ai",
        text: "🚨 **Connection Error**: Unable to reach GenAI Assistant backend endpoint.",
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    }
    setLoading(false);
  };

  const clearHistory = () => {
    setMessages([
      {
        sender: "ai",
        text: "👋 **Chat history reset.** How can NetGuard Co-pilot help you with threat analysis?",
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);
  };

  const copyMessage = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const samplePrompts = [
    { label: "Summarize network threats", icon: Activity },
    { label: "How to mitigate DoS attacks?", icon: ShieldCheck },
    { label: "Recommend firewall rules", icon: Terminal },
    { label: "Explain Infiltration detection", icon: Zap }
  ];

  return (
    <div style={{ animation: "fadeIn 0.3s ease" }}>
      <style>{`
        @keyframes bounceDot {
          0%, 80%, 100% { transform: scale(0.6); opacity: 0.3; }
          40% { transform: scale(1.1); opacity: 1; }
        }
        .prompt-chip {
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .prompt-chip:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(14,165,233,0.2);
        }
        .chat-input:focus {
          border-color: rgba(14,165,233,0.5) !important;
          box-shadow: 0 0 0 3px rgba(14,165,233,0.15) !important;
        }
      `}</style>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>

        {/* Main Chat Panel */}
        <div className="panel" style={{
          display: "flex",
          flexDirection: "column",
          height: 640,
          padding: 0,
          overflow: "hidden",
          position: "relative"
        }}>
          {/* Header Bar */}
          <div style={{
            padding: "16px 20px",
            borderBottom: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.08)",
            background: isSoft ? "#f8fafc" : "rgba(10,22,45,0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{
                width: 38,
                height: 38,
                borderRadius: 12,
                background: "linear-gradient(135deg, #0ea5e9, #2563eb)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: "0 0 15px rgba(14,165,233,0.3)"
              }}>
                <Bot size={20} color="#ffffff" />
              </div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 15, fontWeight: 700, color: isSoft ? "#0f172a" : "#f1f5f9" }}>
                    NetGuard AI Copilot
                  </span>
                  <span style={{
                    fontSize: 10,
                    fontWeight: 700,
                    background: "rgba(34,211,160,0.12)",
                    color: isSoft ? "#059669" : "#22d3a0",
                    border: "1px solid rgba(34,211,160,0.25)",
                    padding: "2px 8px",
                    borderRadius: 12,
                    display: "flex",
                    alignItems: "center",
                    gap: 4
                  }}>
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#22d3a0" }} />
                    Active Threat AI
                  </span>
                </div>
                <div style={{ fontSize: 11, color: isSoft ? "#64748b" : "#94a3b8", marginTop: 2 }}>
                  Real-time telemetry analysis & automated XAI defense
                </div>
              </div>
            </div>

            {/* Header Actions */}
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <button
                onClick={loadBriefing}
                title="Refresh AI Insights"
                style={{
                  background: isSoft ? "#ffffff" : "rgba(255,255,255,0.05)",
                  border: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 8,
                  padding: "6px 10px",
                  color: isSoft ? "#475569" : "#94a3b8",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  fontSize: 12,
                  fontWeight: 600,
                  transition: "all 0.15s"
                }}
              >
                <RefreshCw size={13} />
                <span>Sync</span>
              </button>
              <button
                onClick={clearHistory}
                title="Clear Chat History"
                style={{
                  background: isSoft ? "#ffffff" : "rgba(255,255,255,0.05)",
                  border: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 8,
                  padding: "6px 10px",
                  color: isSoft ? "#64748b" : "#94a3b8",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  fontSize: 12,
                  fontWeight: 600,
                  transition: "all 0.15s"
                }}
              >
                <Trash2 size={13} />
                <span>Clear</span>
              </button>
            </div>
          </div>

          {/* Message History Area */}
          <div style={{
            flex: 1,
            overflowY: "auto",
            padding: "20px",
            display: "flex",
            flexDirection: "column",
            gap: 18,
            background: isSoft ? "#f1f5f9" : "rgba(2,8,16,0.3)"
          }}>
            {messages.map((m, i) => {
              const isUser = m.sender === "user";
              return (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    gap: 12,
                    flexDirection: isUser ? "row-reverse" : "row",
                    alignItems: "flex-start",
                    maxWidth: "88%",
                    alignSelf: isUser ? "flex-end" : "flex-start"
                  }}
                >
                  {/* Avatar Icon */}
                  <div style={{
                    width: 32,
                    height: 32,
                    borderRadius: "50%",
                    background: isUser
                      ? "linear-gradient(135deg, #0ea5e9, #2563eb)"
                      : isSoft
                        ? "#e2e8f0"
                        : "rgba(14,165,233,0.15)",
                    border: isUser
                      ? "none"
                      : isSoft
                        ? "1px solid #cbd5e1"
                        : "1px solid rgba(14,165,233,0.3)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                    boxShadow: isUser ? "0 4px 12px rgba(14,165,233,0.2)" : "none"
                  }}>
                    {isUser ? (
                      <User size={16} color="#ffffff" />
                    ) : (
                      <Bot size={16} color={isSoft ? "#0ea5e9" : "#38bdf8"} />
                    )}
                  </div>

                  {/* Message Bubble Card */}
                  <div style={{
                    background: isUser
                      ? "linear-gradient(135deg, #0ea5e9, #2563eb)"
                      : isSoft
                        ? "#ffffff"
                        : "rgba(15,23,42,0.8)",
                    border: isUser
                      ? "none"
                      : isSoft
                        ? "1px solid #e2e8f0"
                        : "1px solid rgba(255,255,255,0.08)",
                    borderRadius: isUser ? "16px 16px 4px 16px" : "16px 16px 16px 4px",
                    padding: "14px 18px",
                    color: isUser ? "#ffffff" : isSoft ? "#0f172a" : "#e2e8f0",
                    boxShadow: isUser
                      ? "0 4px 16px rgba(14,165,233,0.25)"
                      : isSoft
                        ? "0 2px 8px rgba(0,0,0,0.04)"
                        : "0 6px 20px rgba(0,0,0,0.25)",
                    fontSize: 13,
                    position: "relative"
                  }}>
                    {/* Header info inside bubble */}
                    <div style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 16,
                      marginBottom: 8,
                      fontSize: 11,
                      fontWeight: 600,
                      opacity: isUser ? 0.9 : 0.75,
                      color: isUser ? "#e0f2fe" : isSoft ? "#64748b" : "#94a3b8"
                    }}>
                      <span>{isUser ? "Security Analyst" : "🤖 NetGuard Copilot"}</span>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span>{m.time}</span>
                        {!isUser && (
                          <button
                            onClick={() => copyMessage(m.text, i)}
                            title="Copy reply"
                            style={{
                              background: "transparent",
                              border: "none",
                              color: copiedIndex === i ? "#22d3a0" : "inherit",
                              cursor: "pointer",
                              padding: 0,
                              display: "flex",
                              alignItems: "center",
                              gap: 2
                            }}
                          >
                            {copiedIndex === i ? <Check size={12} /> : <Copy size={12} />}
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Content Rendering (Formatted Markdown for AI, Clean text for user) */}
                    {isUser ? (
                      <div style={{ whiteSpace: "pre-wrap", lineHeight: 1.5, fontWeight: 500 }}>
                        {m.text}
                      </div>
                    ) : (
                      <div className="markdown-content" style={{ fontSize: 13, lineHeight: 1.6 }}>
                        <ReactMarkdown
                          remarkPlugins={[remarkGfm]}
                          components={{
                            h1: ({ node, ...props }) => (
                              <h1 style={{ fontSize: 16, fontWeight: 700, margin: "14px 0 8px", color: isSoft ? "#0f172a" : "#38bdf8" }} {...props} />
                            ),
                            h2: ({ node, ...props }) => (
                              <h2 style={{ fontSize: 14, fontWeight: 700, margin: "12px 0 6px", borderLeft: "3px solid #0ea5e9", paddingLeft: 8, color: isSoft ? "#0f172a" : "#f1f5f9" }} {...props} />
                            ),
                            h3: ({ node, ...props }) => (
                              <h3 style={{ fontSize: 13, fontWeight: 700, margin: "10px 0 4px", color: isSoft ? "#1e293b" : "#e2e8f0" }} {...props} />
                            ),
                            p: ({ node, ...props }) => (
                              <p style={{ margin: "0 0 8px 0", lineHeight: 1.6 }} {...props} />
                            ),
                            strong: ({ node, ...props }) => (
                              <strong style={{ fontWeight: 700, color: isSoft ? "#0284c7" : "#38bdf8" }} {...props} />
                            ),
                            ul: ({ node, ...props }) => (
                              <ul style={{ paddingLeft: 18, margin: "6px 0 10px", display: "flex", flexDirection: "column", gap: 4 }} {...props} />
                            ),
                            ol: ({ node, ...props }) => (
                              <ol style={{ paddingLeft: 18, margin: "6px 0 10px", display: "flex", flexDirection: "column", gap: 4 }} {...props} />
                            ),
                            li: ({ node, ...props }) => (
                              <li style={{ lineHeight: 1.5 }} {...props} />
                            ),
                            code({ node, inline, className, children, ...props }) {
                              if (inline) {
                                return (
                                  <code style={{
                                    background: isSoft ? "rgba(14,165,233,0.1)" : "rgba(56,189,248,0.15)",
                                    color: isSoft ? "#0284c7" : "#38bdf8",
                                    padding: "2px 6px",
                                    borderRadius: 4,
                                    fontSize: "0.9em",
                                    fontFamily: "'Space Mono', monospace",
                                    border: isSoft ? "1px solid rgba(14,165,233,0.2)" : "1px solid rgba(56,189,248,0.25)"
                                  }} {...props}>
                                    {children}
                                  </code>
                                );
                              }
                              return (
                                <CodeBlock code={String(children).replace(/\n$/, "")} isSoft={isSoft} />
                              );
                            }
                          }}
                        >
                          {m.text}
                        </ReactMarkdown>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {/* Thinking / Loading Indicator */}
            {loading && (
              <div style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                alignSelf: "flex-start",
                background: isSoft ? "#ffffff" : "rgba(15,23,42,0.8)",
                border: isSoft ? "1px solid #e2e8f0" : "1px solid rgba(56,189,248,0.3)",
                borderRadius: "16px 16px 16px 4px",
                padding: "12px 18px",
                boxShadow: "0 4px 16px rgba(0,0,0,0.1)"
              }}>
                <div style={{
                  width: 28,
                  height: 28,
                  borderRadius: "50%",
                  background: isSoft ? "#e0f2fe" : "rgba(14,165,233,0.2)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center"
                }}>
                  <Bot size={15} color="#0ea5e9" />
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: isSoft ? "#0369a1" : "#38bdf8" }}>
                    Analyzing telemetry & security context
                  </span>
                  <div style={{ display: "flex", gap: 4 }}>
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#0ea5e9", animation: "bounceDot 1.4s infinite 0s" }} />
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#0ea5e9", animation: "bounceDot 1.4s infinite 0.2s" }} />
                    <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#0ea5e9", animation: "bounceDot 1.4s infinite 0.4s" }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Quick Prompts Chips */}
          <div style={{
            padding: "10px 16px 0",
            background: isSoft ? "#f8fafc" : "rgba(10,22,45,0.6)",
            borderTop: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.06)",
            display: "flex",
            alignItems: "center",
            gap: 8,
            overflowX: "auto",
            scrollbarWidth: "none"
          }}>
            <Sparkles size={14} color="#0ea5e9" style={{ flexShrink: 0 }} />
            {samplePrompts.map((promptObj, idx) => {
              const IconComp = promptObj.icon;
              return (
                <button
                  key={idx}
                  onClick={() => sendQuery(promptObj.label)}
                  className="prompt-chip"
                  style={{
                    background: isSoft ? "#ffffff" : "rgba(14,165,233,0.1)",
                    border: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(14,165,233,0.25)",
                    borderRadius: 20,
                    padding: "6px 14px",
                    color: isSoft ? "#0369a1" : "#38bdf8",
                    fontSize: 11,
                    cursor: "pointer",
                    fontWeight: 600,
                    whiteSpace: "nowrap",
                    display: "flex",
                    alignItems: "center",
                    gap: 6
                  }}
                >
                  <IconComp size={12} />
                  <span>{promptObj.label}</span>
                </button>
              );
            })}
          </div>

          {/* Input Bar */}
          <div style={{
            padding: "14px 16px",
            background: isSoft ? "#f8fafc" : "rgba(10,22,45,0.9)",
            display: "flex",
            alignItems: "center",
            gap: 10
          }}>
            <input
              type="text"
              className="chat-input"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && sendQuery()}
              placeholder="Ask NetGuard AI Copilot (e.g., 'Summarize incidents', 'How to block DDoS')..."
              style={{
                flex: 1,
                background: isSoft ? "#ffffff" : "rgba(255,255,255,0.05)",
                border: isSoft ? "1px solid #cbd5e1" : "1px solid rgba(255,255,255,0.1)",
                borderRadius: 12,
                padding: "12px 16px",
                color: isSoft ? "#0f172a" : "#f1f5f9",
                fontSize: 13,
                outline: "none",
                transition: "all 0.2s ease"
              }}
            />
            <button
              onClick={() => sendQuery()}
              disabled={loading || !input.trim()}
              style={{
                background: (loading || !input.trim())
                  ? (isSoft ? "#cbd5e1" : "rgba(255,255,255,0.1)")
                  : "linear-gradient(135deg, #0ea5e9, #2563eb)",
                border: "none",
                borderRadius: 12,
                padding: "12px 22px",
                color: "#ffffff",
                fontWeight: 700,
                fontSize: 13,
                cursor: (loading || !input.trim()) ? "not-allowed" : "pointer",
                display: "flex",
                alignItems: "center",
                gap: 8,
                boxShadow: (loading || !input.trim()) ? "none" : "0 4px 16px rgba(14,165,233,0.3)",
                transition: "all 0.2s ease"
              }}
            >
              <span>Send</span>
              <Send size={14} />
            </button>
          </div>
        </div>

        {/* Live Threat Intelligence Briefing Panel */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="panel" style={{ padding: 20 }}>
            <SectionTitle label="AI Briefing" title="Live Threat Assessment" />
            {briefing ? (
              <div style={{ marginTop: 12 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                  <div style={{
                    width: 10,
                    height: 10,
                    borderRadius: "50%",
                    background: briefing.status_level === "GREEN" ? "#22d3a0" : briefing.status_level === "ORANGE" ? "#f97316" : "#ef4444",
                    boxShadow: briefing.status_level === "GREEN" ? "0 0 10px #22d3a0" : "0 0 10px #f97316"
                  }} />
                  <span style={{
                    fontSize: 12,
                    fontWeight: 800,
                    letterSpacing: "0.05em",
                    color: briefing.status_level === "GREEN" ? (isSoft ? "#059669" : "#22d3a0") : (isSoft ? "#ea580c" : "#f97316")
                  }}>
                    {briefing.status_level} STATUS
                  </span>
                </div>
                <div style={{ fontSize: 13, fontWeight: 700, color: isSoft ? "#0f172a" : "#f1f5f9", marginBottom: 8, lineHeight: 1.4 }}>
                  {briefing.headline}
                </div>
                <div style={{ fontSize: 12, color: isSoft ? "#475569" : "#94a3b8", lineHeight: "1.5", marginBottom: 16 }}>
                  {briefing.assessment}
                </div>

                <div style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: isSoft ? "#0284c7" : "#38bdf8",
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  marginBottom: 10,
                  display: "flex",
                  alignItems: "center",
                  gap: 6
                }}>
                  <CheckCircle2 size={13} />
                  <span>Recommended Action Items</span>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {briefing.action_items?.map((item, idx) => (
                    <div key={idx} style={{
                      fontSize: 12,
                      color: isSoft ? "#334155" : "#cbd5e1",
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 8,
                      background: isSoft ? "#f8fafc" : "rgba(255,255,255,0.02)",
                      padding: "8px 10px",
                      borderRadius: 8,
                      border: isSoft ? "1px solid #e2e8f0" : "1px solid rgba(255,255,255,0.04)"
                    }}>
                      <span style={{ color: "#22d3a0", fontWeight: 700 }}>✓</span>
                      <span style={{ lineHeight: 1.4 }}>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ fontSize: 12, color: "#64748b", padding: "16px 0", display: "flex", alignItems: "center", gap: 8 }}>
                <Activity size={14} className="animate-spin" />
                <span>Loading AI Briefing...</span>
              </div>
            )}
          </div>

          <div className="panel" style={{ padding: 20 }}>
            <SectionTitle label="Architecture" title="Modular XAI Engine" />
            <div style={{
              fontSize: 12,
              color: isSoft ? "#475569" : "#94a3b8",
              lineHeight: "1.6",
              marginTop: 10,
              display: "flex",
              flexDirection: "column",
              gap: 10
            }}>
              <div>
                NetGuard features a decoupled <strong>Explainable AI (XAI)</strong> attribution module.
              </div>
              <div style={{
                background: isSoft ? "#f0f9ff" : "rgba(14,165,233,0.08)",
                border: isSoft ? "1px solid #bae6fd" : "1px solid rgba(14,165,233,0.2)",
                padding: "10px 12px",
                borderRadius: 8,
                color: isSoft ? "#0369a1" : "#38bdf8",
                fontSize: 11,
                display: "flex",
                alignItems: "center",
                gap: 8
              }}>
                <Info size={16} style={{ flexShrink: 0 }} />
                <span>Click <strong>"🔍 Why Detected?"</strong> on any incident row to view SHAP attribution breakdowns.</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
