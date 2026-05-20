# =============================================================
# alert.py — NetGuard IDS v2.1
# Professional alerting: SQLite logging + HTML email + Telegram
# =============================================================

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlite3
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
import requests

from config import (
    ALERT_FROM, ALERT_TO, ALERT_PASS,
    ALERT_CONFIDENCE_THRESHOLD, BASE_DIR,
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
    AUTO_BLOCK_ENABLED, AUTO_BLOCK_THRESHOLD,
    AUTO_BLOCK_CONFIDENCE, AUTO_BLOCK_SEVERITIES,
)
from blocklist import block_ip
from alert_settings import get_alert_email_target

# ── DB Path ────────────────────────────────────────────────────
DB_PATH = BASE_DIR / "logs" / "detections.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_db_lock = threading.Lock()

# ── Schema ─────────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    prediction  TEXT    NOT NULL,
    confidence  REAL    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'none',
    source_ip   TEXT    NOT NULL DEFAULT 'unknown',
    flow_id     TEXT    NOT NULL DEFAULT '',
    mode        TEXT    NOT NULL DEFAULT 'live'
);
CREATE INDEX IF NOT EXISTS idx_det_ts         ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_det_prediction ON detections(prediction);
CREATE INDEX IF NOT EXISTS idx_det_source_ip  ON detections(source_ip);
CREATE INDEX IF NOT EXISTS idx_det_severity   ON detections(severity);
"""

def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


# ── Logging ────────────────────────────────────────────────────
def _log_to_db(result: dict, source_ip: str = "unknown",
               flow_id: str = "", test_mode: bool = False):
    with _db_lock:
        conn = _get_db()
        try:
            conn.execute("""
                INSERT INTO detections
                    (timestamp, prediction, confidence, severity, source_ip, flow_id, mode)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                result["timestamp"],
                result["prediction"],
                float(result["confidence"]),
                result["severity"],
                source_ip,
                flow_id,
                "test" if test_mode else "live",
            ))
            conn.commit()
        finally:
            conn.close()


# ── Professional HTML Email ────────────────────────────────────
def _build_html_email(result: dict, source_ip: str) -> str:
    pred      = result["prediction"].replace("_", " ")
    conf_pct  = f"{result['confidence'] * 100:.1f}%"
    sev       = result["severity"].upper()
    ts        = result["timestamp"]

    sev_color = {
        "CRITICAL": "#ef4444",
        "HIGH":     "#f97316",
        "NONE":     "#22d3a0",
    }.get(sev, "#94a3b8")

    pred_color = {
        "BRUTE FORCE":  "#f97316",
        "DOS DDOS":     "#ef4444",
        "WEB ATTACK":   "#a78bfa",
        "INFILTRATION": "#ec4899",
        "NORMAL":       "#22d3a0",
    }.get(pred, "#94a3b8")

    scores_rows = "".join(
        f"""<tr>
              <td style="padding:6px 12px;color:#94a3b8;font-size:13px;">{k.replace('_',' ')}</td>
              <td style="padding:6px 12px;color:#f1f5f9;font-size:13px;font-weight:600;">{v*100:.1f}%</td>
            </tr>"""
        for k, v in result.get("all_scores", {}).items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#020810;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#020810;padding:32px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#0a1628;border-radius:12px;border:1px solid #1e3a5f;overflow:hidden;">

        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#0ea5e9,#6366f1);padding:28px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <div style="color:#fff;font-size:11px;font-weight:700;letter-spacing:3px;opacity:.75;margin-bottom:6px;">NETGUARD IDS v2.1</div>
                  <div style="color:#fff;font-size:22px;font-weight:700;">🚨 Security Alert Detected</div>
                </td>
                <td align="right">
                  <div style="background:rgba(255,255,255,.15);border-radius:8px;padding:10px 16px;display:inline-block;">
                    <div style="color:#fff;font-size:11px;opacity:.8;">SEVERITY</div>
                    <div style="color:{sev_color};font-size:18px;font-weight:800;">{sev}</div>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Alert Summary -->
        <tr>
          <td style="padding:24px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#020810;border-radius:10px;border:1px solid #1e3a5f;">
              <tr>
                <td style="padding:16px 20px;border-bottom:1px solid #1e3a5f;">
                  <div style="color:#64748b;font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:4px;">ATTACK TYPE</div>
                  <div style="color:{pred_color};font-size:20px;font-weight:800;">{pred}</div>
                </td>
                <td style="padding:16px 20px;border-bottom:1px solid #1e3a5f;border-left:1px solid #1e3a5f;">
                  <div style="color:#64748b;font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:4px;">CONFIDENCE</div>
                  <div style="color:#f1f5f9;font-size:20px;font-weight:800;">{conf_pct}</div>
                </td>
              </tr>
              <tr>
                <td style="padding:16px 20px;">
                  <div style="color:#64748b;font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:4px;">SOURCE IP</div>
                  <div style="color:#0ea5e9;font-size:16px;font-weight:700;font-family:monospace;">{source_ip}</div>
                </td>
                <td style="padding:16px 20px;border-left:1px solid #1e3a5f;">
                  <div style="color:#64748b;font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:4px;">TIMESTAMP</div>
                  <div style="color:#94a3b8;font-size:13px;">{ts}</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Score Breakdown -->
        {'<tr><td style="padding:0 32px 24px;"><div style="color:#0ea5e9;font-size:11px;font-weight:700;letter-spacing:2px;margin-bottom:10px;">SCORE BREAKDOWN</div><table width="100%" cellpadding="0" cellspacing="0" style="background:#020810;border-radius:10px;border:1px solid #1e3a5f;">' + scores_rows + '</table></td></tr>' if scores_rows else ''}

        <!-- Action Button -->
        <tr>
          <td style="padding:0 32px 28px;" align="center">
            <a href="http://localhost:5173" style="display:inline-block;background:linear-gradient(135deg,#0ea5e9,#6366f1);color:#fff;font-size:14px;font-weight:700;padding:14px 32px;border-radius:8px;text-decoration:none;letter-spacing:1px;">
              → OPEN NETGUARD DASHBOARD
            </a>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#020810;border-top:1px solid #1e3a5f;padding:16px 32px;" align="center">
            <div style="color:#334155;font-size:11px;">NetGuard IDS v2.1 &nbsp;•&nbsp; Confidential Security Alert &nbsp;•&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _send_email(result: dict, source_ip: str):
    alert_to = get_alert_email_target() or ALERT_TO
    if not all([ALERT_FROM, alert_to, ALERT_PASS]):
        print("[alert] Email credentials not set — skipping.")
        return

    pred = result["prediction"].replace("_", " ")
    sev  = result["severity"].upper()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[NetGuard IDS] {sev} — {pred} Attack from {source_ip}"
    msg["From"]    = f"NetGuard IDS <{ALERT_FROM}>"
    msg["To"]      = alert_to

    # Plain text fallback
    plain = (
        f"NetGuard IDS — Security Alert\n"
        f"{'='*40}\n"
        f"Attack Type : {pred}\n"
        f"Confidence  : {result['confidence']*100:.1f}%\n"
        f"Severity    : {sev}\n"
        f"Source IP   : {source_ip}\n"
        f"Timestamp   : {result['timestamp']}\n"
        f"{'='*40}\n"
        f"Open dashboard: http://localhost:5173\n"
    )
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(_build_html_email(result, source_ip), "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(ALERT_FROM, ALERT_PASS)
            server.send_message(msg)
        print(f"[alert] [OK] Email sent to {alert_to}")
    except Exception as e:
        print(f"[alert] [ERR] Email failed: {e}")


# ── Telegram ───────────────────────────────────────────────────
def _send_telegram(result: dict, source_ip: str):
    if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID]):
        return

    sev_icon = {"critical": "🔴", "high": "🟠", "none": "🟢"}.get(result["severity"], "⚪")
    message = (
        f"{sev_icon} *NetGuard IDS Alert*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 *Attack:* `{result['prediction']}`\n"
        f"📊 *Confidence:* `{result['confidence']*100:.1f}%`\n"
        f"⚡ *Severity:* `{result['severity'].upper()}`\n"
        f"🌐 *Source IP:* `{source_ip}`\n"
        f"🕐 *Time:* `{result['timestamp']}`\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"[Open Dashboard](http://localhost:5173)"
    )

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={
                "chat_id":    TELEGRAM_CHAT_ID,
                "text":       message,
                "parse_mode": "Markdown",
            },
            timeout=5,
        )
        response.raise_for_status()
        payload = response.json()
        if not payload.get("ok"):
            raise RuntimeError(payload.get("description", "Telegram API rejected request"))
        print("[alert] [OK] Telegram alert sent.")
    except Exception as e:
        print(f"[alert] [ERR] Telegram failed: {e}")


# ── Auto-block ─────────────────────────────────────────────────
def _recent_attack_count(source_ip: str) -> int:
    with _db_lock:
        conn = _get_db()
        try:
            row = conn.execute("""
                SELECT COUNT(*) FROM detections
                WHERE source_ip=? AND severity != 'none'
                AND confidence >= ?
            """, (source_ip, AUTO_BLOCK_CONFIDENCE)).fetchone()
            return row[0] if row else 0
        finally:
            conn.close()


def _maybe_auto_block(result: dict, source_ip: str):
    if not AUTO_BLOCK_ENABLED:
        return
    if result["severity"] not in AUTO_BLOCK_SEVERITIES:
        return
    if result["confidence"] < AUTO_BLOCK_CONFIDENCE:
        return
    if _recent_attack_count(source_ip) < AUTO_BLOCK_THRESHOLD:
        return
    response = block_ip(source_ip, f"{result['prediction']} auto-block")
    print(f"[alert] [BLOCK] Auto-block: {response['message']}")


# ── Main handler ───────────────────────────────────────────────
def handle_alert(result: dict, source_ip: str = "unknown",
                 flow_id: str = "", test_mode: bool = False):
    # Always log to SQLite
    _log_to_db(result, source_ip, flow_id=flow_id, test_mode=test_mode)

    # Email/Telegram/AutoBlock only for real attacks
    if (not test_mode
            and result["severity"] != "none"
            and result["confidence"] >= ALERT_CONFIDENCE_THRESHOLD):
        print(f"[alert] [ALERT] {result['prediction']} from {source_ip} "
              f"({result['confidence']*100:.1f}% confidence)")
        _send_email(result, source_ip)
        _send_telegram(result, source_ip)
        _maybe_auto_block(result, source_ip)
