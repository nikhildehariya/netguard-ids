# =============================================================
# webhook_exporters.py — NetGuard IDS v2.2
# Universal SOC & SIEM Alert Exporter
# Integrations: Slack, Discord, Microsoft Teams, Syslog (RFC 5424/Splunk)
# =============================================================

import os
import json
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger("netguard.webhooks")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip()
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "").strip()
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "").strip()
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "").strip()


def export_to_slack(result: Dict[str, Any], source_ip: str, webhook_url: Optional[str] = None) -> bool:
    """Send threat alert card to Slack channel incoming webhook."""
    url = webhook_url or SLACK_WEBHOOK_URL
    if not url:
        return False

    severity = result.get("severity", "medium").upper()
    color = "#FF0000" if severity in ("HIGH", "CRITICAL") else "#FFA500" if severity == "MEDIUM" else "#36A64F"

    payload = {
        "text": f"🚨 *[NetGuard IDS Alert]* {result.get('prediction', 'Threat')} detected!",
        "attachments": [
            {
                "color": color,
                "title": f"Network Intrusion Event: {result.get('prediction')}",
                "fields": [
                    {"title": "Source IP", "value": source_ip, "short": True},
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Confidence", "value": f"{float(result.get('confidence', 0))*100:.1f}%", "short": True},
                    {"title": "Timestamp", "value": result.get("timestamp", datetime.now(timezone.utc).isoformat()), "short": True},
                    {"title": "Tenant", "value": result.get("tenant_id", "default"), "short": True},
                ],
                "footer": "NetGuard IDS Engine v2.2"
            }
        ]
    }
    try:
        resp = requests.post(url, json=payload, timeout=4)
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"[webhook_exporters] Slack export failed: {e}")
        return False


def export_to_discord(result: Dict[str, Any], source_ip: str, webhook_url: Optional[str] = None) -> bool:
    """Send rich embed threat card to Discord server webhook."""
    url = webhook_url or DISCORD_WEBHOOK_URL
    if not url:
        return False

    severity = result.get("severity", "medium").upper()
    color_int = 0xFF0000 if severity in ("HIGH", "CRITICAL") else 0xFFA500 if severity == "MEDIUM" else 0x00FF00

    payload = {
        "username": "NetGuard SOC Alert",
        "embeds": [
            {
                "title": f"🚨 Network Threat Detected: {result.get('prediction')}",
                "color": color_int,
                "fields": [
                    {"name": "Attacker IP", "value": f"`{source_ip}`", "inline": True},
                    {"name": "Severity", "value": f"`{severity}`", "inline": True},
                    {"name": "Detection Confidence", "value": f"`{float(result.get('confidence', 0))*100:.1f}%`", "inline": True},
                    {"name": "Tenant Organization", "value": f"`{result.get('tenant_id', 'default')}`", "inline": True},
                    {"name": "Event Timestamp", "value": result.get("timestamp", datetime.now(timezone.utc).isoformat()), "inline": False},
                ],
                "footer": {"text": "NetGuard IDS Autonomous Security"}
            }
        ]
    }
    try:
        resp = requests.post(url, json=payload, timeout=4)
        return resp.status_code in (200, 204)
    except Exception as e:
        logger.error(f"[webhook_exporters] Discord export failed: {e}")
        return False


def export_to_teams(result: Dict[str, Any], source_ip: str, webhook_url: Optional[str] = None) -> bool:
    """Send MessageCard format notification to Microsoft Teams Connector."""
    url = webhook_url or TEAMS_WEBHOOK_URL
    if not url:
        return False

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "D63333" if result.get("severity") in ("high", "critical") else "E89A3C",
        "summary": f"NetGuard IDS Alert: {result.get('prediction')}",
        "sections": [
            {
                "activityTitle": f"🚨 NetGuard Intrusion Detected: {result.get('prediction')}",
                "activitySubtitle": f"Autonomous Network Sentinel — Tenant: {result.get('tenant_id', 'default')}",
                "facts": [
                    {"name": "Source IP:", "value": source_ip},
                    {"name": "Severity Level:", "value": result.get("severity", "medium").upper()},
                    {"name": "Confidence Score:", "value": f"{float(result.get('confidence', 0))*100:.1f}%"},
                    {"name": "Event Timestamp:", "value": result.get("timestamp", datetime.now(timezone.utc).isoformat())}
                ],
                "markdown": True
            }
        ]
    }
    try:
        resp = requests.post(url, json=payload, timeout=4)
        return resp.status_code == 200
    except Exception as e:
        logger.error(f"[webhook_exporters] Teams export failed: {e}")
        return False


def export_to_syslog(result: Dict[str, Any], source_ip: str, host: Optional[str] = None, port: Optional[int] = None) -> bool:
    """Export standard CEF / RFC 5424 Syslog datagram to SIEM collector (Splunk / QRadar / Graylog)."""
    target_host = host or SYSLOG_HOST
    target_port = port or SYSLOG_PORT
    if not target_host:
        return False

    facility = 1  # user-level messages
    severity_code = 2 if result.get("severity") in ("critical", "high") else 4  # Critical / Warning
    priority = (facility * 8) + severity_code

    ts = result.get("timestamp", datetime.now(timezone.utc).isoformat())
    cef_message = (
        f"<{priority}>1 {ts} netguard-ids engine - - - "
        f"CEF:0|NetGuard|IoT-IDS|2.2|{result.get('prediction')}|{result.get('prediction')}|"
        f"{8 if result.get('severity') in ('critical', 'high') else 5}|"
        f"src={source_ip} confidence={float(result.get('confidence', 0)):.3f} "
        f"severity={result.get('severity')} tenant={result.get('tenant_id', 'default')}"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(cef_message.encode("utf-8"), (target_host, target_port))
        sock.close()
        return True
    except Exception as e:
        logger.error(f"[webhook_exporters] Syslog export failed: {e}")
        return False


def export_all_siem_channels(result: Dict[str, Any], source_ip: str):
    """Broadcast event across all enabled third-party webhooks and SIEM daemons."""
    export_to_slack(result, source_ip)
    export_to_discord(result, source_ip)
    export_to_teams(result, source_ip)
    export_to_syslog(result, source_ip)
