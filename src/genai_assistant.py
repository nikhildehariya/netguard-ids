# =============================================================
# genai_assistant.py — NetGuard IDS v2.1
# Universal Real AI Security Assistant & Threat Copilot
# Supports: Google Gemini API, Ollama (Local Llama3), Hugging Face, & Local SOC Engine
# =============================================================

import os
import sqlite3
import requests
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "logs" / "detections.db"

def _get_recent_summary_context(hours: int = 24) -> Dict:
    """Fetch recent detection context from SQLite database."""
    if not DB_PATH.exists():
        return {"total": 0, "attacks": 0, "by_class": {}}

    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) FROM detections WHERE mode='live'").fetchone()[0]
        attacks = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE mode='live' AND severity != 'none'"
        ).fetchone()[0]
        rows = conn.execute("""
            SELECT prediction, COUNT(*) as cnt FROM detections
            WHERE mode='live' GROUP BY prediction
        """).fetchall()
        conn.close()
        return {
            "total": total,
            "attacks": attacks,
            "by_class": {r["prediction"]: r["cnt"] for r in rows}
        }
    except Exception as e:
        return {"total": 0, "attacks": 0, "by_class": {}, "error": str(e)}


def _query_hf_api(user_query: str, system_prompt: str) -> Optional[str]:
    """Query Hugging Face Inference API if HF_TOKEN is configured in .env."""
    hf_token = os.getenv("HF_TOKEN", "").strip()
    if not hf_token:
        return None

    models_to_try = [
        os.getenv("HF_MODEL", "").strip(),
        "Qwen/Qwen2.5-Coder-32B-Instruct",
        "Qwen/Qwen2.5-72B-Instruct",
        "meta-llama/Llama-3.2-3B-Instruct",
        "mistralai/Mistral-7B-Instruct-v0.3"
    ]
    models_to_try = [m for m in models_to_try if m]

    try:
        from huggingface_hub import InferenceClient
        client = InferenceClient(api_key=hf_token)
        for model in models_to_try:
            try:
                res = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_query}
                    ],
                    max_tokens=600,
                    temperature=0.7
                )
                if res and res.choices and res.choices[0].message and res.choices[0].message.content:
                    return res.choices[0].message.content.strip()
            except Exception:
                continue
    except Exception:
        pass
    return None


def _query_gemini_api(user_query: str, system_prompt: str) -> Optional[str]:
    """Query Google Gemini API if GEMINI_API_KEY is configured in .env."""
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not gemini_key:
        return None

    models_to_try = [
        "gemini-flash-lite-latest",
        "gemini-flash-latest",
        "gemini-pro-latest"
    ]

    try:
        import ssl
        from requests.adapters import HTTPAdapter
        from urllib3.util.ssl_ import create_urllib3_context

        class TLSAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                ctx = create_urllib3_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                kwargs['ssl_context'] = ctx
                return super().init_poolmanager(*args, **kwargs)

        s = requests.Session()
        s.mount('https://', TLSAdapter())
        s.trust_env = False
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"System Context:\n{system_prompt}\n\nUser Question: {user_query}"}
                    ]
                }
            ]
        }

        for model in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
            try:
                res = s.post(url, headers=headers, json=payload, timeout=8)
                if res.status_code == 200:
                    data = res.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts and "text" in parts[0]:
                            return parts[0]["text"].strip()
            except Exception:
                continue
    except Exception:
        pass
    return None




def _query_ollama_local(user_query: str, system_prompt: str) -> Optional[str]:
    """Query Local Ollama Llama3 instance if running on localhost:11434."""
    try:
        url = "http://localhost:11434/api/generate"
        payload = {
            "model": "llama3.2",
            "prompt": f"System Context:\n{system_prompt}\n\nUser Question: {user_query}",
            "stream": False
        }
        res = requests.post(url, json=payload, timeout=4)
        if res.status_code == 200:
            return res.json().get("response", "").strip()
    except Exception:
        pass
    return None


def generate_threat_briefing() -> Dict:
    """Generate an AI threat intelligence executive summary brief."""
    ctx = _get_recent_summary_context(hours=24)
    total = ctx.get("total", 0)
    attacks = ctx.get("attacks", 0)
    by_class = ctx.get("by_class", {})

    if total == 0:
        status_level = "GREEN"
        headline = "Network Security Operational — No Events Logged"
        assessment = "No recent network traffic events or anomalies detected in the system database."
    elif attacks == 0:
        status_level = "GREEN"
        headline = f"Network Clean — {total:,} Normal Traffic Flows Analyzed"
        assessment = "All analyzed traffic patterns conform to normal baseline behavior. Zero threat signatures flagged."
    else:
        status_level = "ORANGE" if (attacks / max(total, 1)) < 0.1 else "RED"
        headline = f"Security Advisory: {attacks} Threat Events Flagged out of {total:,} Total Flows"
        top_attack = max(by_class, key=lambda k: by_class[k] if k != "NORMAL" else -1)
        assessment = (
            f"Active security events detected. Primary threat vectors include {top_attack.replace('_', ' ')} "
            f"comprising {by_class.get(top_attack, 0)} events. Recommended immediate review of incident log."
        )

    action_items = [
        "Review high-severity incident logs on the Incidents Tab.",
        "Ensure auto-blocking thresholds are active for critical severity events.",
        "Generate a PDF Security Audit Report for historical records.",
    ]

    return {
        "timestamp": datetime.now().isoformat(),
        "status_level": status_level,
        "headline": headline,
        "assessment": assessment,
        "total_analyzed": total,
        "threat_count": attacks,
        "by_class": by_class,
        "action_items": action_items,
    }


def process_copilot_query(user_query: str, incident_context: Optional[Dict] = None) -> Dict:
    """
    Universal Real AI Assistant query handler.
    Tries: 1. Hugging Face LLM API -> 2. Gemini API -> 3. Local Ollama LLM -> 4. Comprehensive Security Intelligence Engine.
    Handles ANY arbitrary question smoothly!
    """
    q = user_query.strip()
    q_lower = q.lower()
    ctx = _get_recent_summary_context()

    system_prompt = (
        "You are NetGuard AI Copilot, an expert Cyber Threat Intelligence Analyst for NetGuard IDS. "
        f"Live Network Telemetry: Total Flows: {ctx.get('total', 0):,}, "
        f"Security Threat Detections: {ctx.get('attacks', 0)}, "
        f"Class Breakdown: {ctx.get('by_class', {})}. "
        "Answer the user's question with clear, professional, thorough, step-by-step guidance."
    )

    # 1. Try Hugging Face LLM API if HF_TOKEN is configured
    hf_reply = _query_hf_api(q, system_prompt)
    if hf_reply:
        return {
            "query": user_query,
            "reply": hf_reply,
            "timestamp": datetime.now().isoformat(),
            "engine": "huggingface_llm"
        }

    # 2. Try Gemini API if GEMINI_API_KEY is configured
    gemini_reply = _query_gemini_api(q, system_prompt)
    if gemini_reply:
        return {
            "query": user_query,
            "reply": gemini_reply,
            "timestamp": datetime.now().isoformat(),
            "engine": "gemini_llm"
        }

    # 3. Try Ollama Local LLM (Llama 3) if running locally
    ollama_reply = _query_ollama_local(q, system_prompt)
    if ollama_reply:
        return {
            "query": user_query,
            "reply": ollama_reply,
            "timestamp": datetime.now().isoformat(),
            "engine": "ollama_llm"
        }

    # 3. Comprehensive Security Intelligence Analyst Engine (Handles ANY arbitrary prompt)

    # Intent: Block IP / Firewall / Dropping Traffic
    if any(k in q_lower for k in ["block", "blok", "black", "deny", "ban", "drop", "firewall"]):
        reply = (
            f"🛡️ **Step-by-Step Guide to Block Harmful IPs in NetGuard IDS:**\n\n"
            f"**Method 1: Manual Block via Dashboard**\n"
            f"1. Navigate to the **Blocklist Tab** on the left menu.\n"
            f"2. Enter target IPv4 address (e.g. `203.0.113.50`) in the **IP Address** field.\n"
            f"3. Enter a reason (e.g. *\"Unauthorized Port Scan / Malicious Activity\"*).\n"
            f"4. *(Optional)* Set TTL duration in seconds (e.g. `3600` for 1 hour auto-unblock).\n"
            f"5. Click **+ Add Block**. NetGuard executes a `netsh advfirewall` drop rule on Windows Defender Firewall.\n\n"
            f"**Method 2: One-Click Block from Incident Feed**\n"
            f"1. Go to the **Incidents Tab**.\n"
            f"2. Next to any detected threat, click the red **🚫 Block IP** button.\n\n"
            f"**Method 3: Enable Automated IP Quarantine**\n"
            f"1. Set `AUTO_BLOCK_ENABLED=true` in your `.env` file to drop malicious IPs automatically when confidence exceeds threshold."
        )

    # Intent: DoS / DDoS Mitigation
    elif any(k in q_lower for k in ["dos", "ddos", "flood", "syn"]):
        reply = (
            f"🚨 **Step-by-Step Guidance for DoS / DDoS Mitigation:**\n\n"
            f"1. **Identify Attacking Source IPs:** Check the **Incidents Tab** or **Overview Tab** to locate top flooding IPs.\n"
            f"2. **Isolate Source:** Click **🚫 Block IP** on the Incident Feed or add the IP to **Blocklist Tab**.\n"
            f"3. **Enable Router SYN Cookies:** Configure TCP SYN cookies and packet rate-limiting on your edge router.\n"
            f"4. **Export PDF Evidentiary Audit Log:** Click **↓ Export Report** at the top right to download report PDF for your ISP/SOC team."
        )

    # Intent: Brute Force Attacks
    elif any(k in q_lower for k in ["brute", "ssh", "ftp", "password", "login"]):
        reply = (
            f"🔑 **Step-by-Step Steps for Brute Force Defense:**\n\n"
            f"1. **Block Attacking IP:** Use the **Blocklist Tab** to drop connections targeting ports 22 (SSH), 21 (FTP), or 3389 (RDP).\n"
            f"2. **Account Lockout:** Enforce service account lockout after 5 consecutive failed authentication attempts.\n"
            f"3. **Disable Root SSH:** Disable direct SSH root password logins and enforce SSH public key authentication."
        )

    # Intent: Infiltration / Exfiltration
    elif any(k in q_lower for k in ["infiltrat", "exfiltrat", "malware", "c2", "beacon"]):
        reply = (
            f"☣️ **Step-by-Step Response to Infiltration Events:**\n\n"
            f"1. **Isolate Compromised Endpoint:** Disconnect affected internal host machine from network immediately.\n"
            f"2. **Inspect XAI Rationale:** Click **🔍 Why Detected?** on the incident row to inspect top feature anomalies.\n"
            f"3. **Audit Outbound Sockets:** Kill unauthorized remote sockets and conduct full antivirus endpoint scan."
        )

    # Intent: Network Capture Configuration
    elif any(k in q_lower for k in ["capture", "interface", "wifi", "span", "sniff"]):
        reply = (
            f"📶 **Step-by-Step Guide for Network Capture Setup:**\n\n"
            f"1. Go to **Live Capture Tab**.\n"
            f"2. Choose your mode:\n"
            f"   • **Wi-Fi Monitor:** Auto-detects local wireless adapter for active Wi-Fi traffic.\n"
            f"   • **SPAN / Ethernet:** Captures mirrored port traffic from managed switches.\n"
            f"   • **Manual:** Select any specific network card from the dropdown.\n"
            f"3. Click **▶ Start Capture**. (Ensure PowerShell was launched as Administrator for raw packet access)."
        )

    # Intent: Summary / Status
    elif any(k in q_lower for k in ["summar", "status", "brief", "report", "overview"]):
        brief = generate_threat_briefing()
        reply = (
            f"🛡️ **NetGuard System Security Briefing**\n\n"
            f"**Status:** {brief['headline']}\n"
            f"**Assessment:** {brief['assessment']}\n\n"
            f"**Traffic Breakdown:**\n"
            + "\n".join([f"- **{k.replace('_', ' ')}**: {v:,} flows" for k, v in brief["by_class"].items()])
        )

    # Arbitrary / General Question Handling (Gives helpful detailed answer)
    else:
        reply = (
            f"🤖 **NetGuard AI Security Analyst Copilot**\n\n"
            f"**Analyzing query:** *\"{q}\"*\n\n"
            f"**Telemetry Context:** Monitoring **{ctx.get('total', 0):,}** network flows with **{ctx.get('attacks', 0)}** threat events.\n\n"
            f"**Key Operational Guides Available:**\n"
            f"• Ask **\"give me steps to block harmful ip\"** ➔ Complete IP firewall drop guide.\n"
            f"• Ask **\"how to mitigate DoS attacks\"** ➔ Full DDoS incident response protocol.\n"
            f"• Ask **\"how to setup capture\"** ➔ Wi-Fi & SPAN port mirror setup guide.\n"
            f"• Ask **\"summarize threats\"** ➔ Real-time 24-hour threat telemetry briefing.\n\n"
            f"*(Tip: You can add `GEMINI_API_KEY` to `.env` or run `ollama run llama3.2` for 100% free cloud/local LLM answers on any topic!)*"
        )

    return {
        "query": user_query,
        "reply": reply,
        "timestamp": datetime.now().isoformat(),
        "engine": "security_copilot_engine",
        "context_events_total": ctx.get("total", 0),
        "context_attacks": ctx.get("attacks", 0)
    }
