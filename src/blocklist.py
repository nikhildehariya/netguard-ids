"""
blocklist.py — NetGuard IDS v2.1
Industry-grade IP blocking engine

Layers:
  1. Windows Firewall (netsh advfirewall) — host-based, always active
  2. SPAN/TAP mode — future: push block to network switch via SSH/SNMP
  3. Persistent SQLite store — survives restarts, full audit trail

Features:
  - Block / Unblock with reason, actor, timestamp
  - TTL-based auto-expiry (optional)
  - Full audit log (every block/unblock/expire event)
  - Admin-only unblock enforcement (enforced at API layer)
  - Loopback / protected range guard
  - Bulk block / unblock
  - Thread-safe
  - Windows + Linux support
"""

import ipaddress
import platform
import sqlite3
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────
_BASE = Path(__file__).resolve().parent.parent / "logs"
DB_PATH = _BASE / "blocklist.db"
_BASE.mkdir(parents=True, exist_ok=True)

# ── Thread safety ──────────────────────────────────────────────
_lock = threading.Lock()

# ── Protected ranges (never block these) ───────────────────────
_PROTECTED = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

# ── DB schema ──────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    blocked_by  TEXT NOT NULL DEFAULT 'system',
    blocked_at  TEXT NOT NULL,
    expires_at  TEXT,
    layer       TEXT NOT NULL DEFAULT 'firewall',
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS block_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event       TEXT NOT NULL,
    ip          TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT 'system',
    reason      TEXT,
    timestamp   TEXT NOT NULL,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(active);
CREATE INDEX IF NOT EXISTS idx_audit_ip       ON block_audit(ip);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON block_audit(timestamp);
"""


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _audit(conn: sqlite3.Connection, event: str, ip: str,
           actor: str = "system", reason: str = "", detail: str = ""):
    conn.execute(
        "INSERT INTO block_audit(event, ip, actor, reason, timestamp, detail) "
        "VALUES (?,?,?,?,?,?)",
        (event, ip, actor, reason,
         datetime.now(timezone.utc).isoformat(timespec="seconds"), detail)
    )


# ── IP validation ──────────────────────────────────────────────

def _parse_ip(ip: str):
    try:
        return ipaddress.ip_address(ip.strip())
    except ValueError:
        return None


def _is_protected(addr) -> bool:
    return any(addr in net for net in _PROTECTED)


# ── Firewall layer ─────────────────────────────────────────────

def _fw_block(ip: str) -> tuple[bool, str]:
    system = platform.system().lower()
    if "windows" in system:
        errors = []
        for direction in ("in", "out"):
            name = f"NetGuard-Block-{ip}-{direction}"
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={name}", f"dir={direction}", "action=block",
                 f"remoteip={ip}", "enable=yes", "profile=any"],
                capture_output=True, text=True, check=False
            )
            if r.returncode != 0:
                errors.append(r.stderr.strip() or r.stdout.strip())
        if errors:
            _fw_unblock(ip)
            return False, " | ".join(errors)
        return True, "Windows Firewall rules added (in+out)"
    elif "linux" in system:
        cmds = [
            ["iptables", "-I", "INPUT",   "1", "-s", ip, "-j", "DROP"],
            ["iptables", "-I", "OUTPUT",  "1", "-d", ip, "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"],
        ]
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if r.returncode != 0:
                return False, r.stderr.strip() or "iptables error"
        return True, "iptables rules added (INPUT+OUTPUT+FORWARD)"
    return False, f"Unsupported OS: {system}"


def _fw_unblock(ip: str) -> tuple[bool, str]:
    system = platform.system().lower()
    if "windows" in system:
        for direction in ("in", "out"):
            name = f"NetGuard-Block-{ip}-{direction}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={name}"],
                capture_output=True, text=True, check=False
            )
        return True, "Windows Firewall rules removed"
    elif "linux" in system:
        for cmd in [
            ["iptables", "-D", "INPUT",   "-s", ip, "-j", "DROP"],
            ["iptables", "-D", "OUTPUT",  "-d", ip, "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
        ]:
            subprocess.run(cmd, capture_output=True, text=True, check=False)
        return True, "iptables rules removed"
    return False, f"Unsupported OS: {system}"


# ── Public API ─────────────────────────────────────────────────

def block_ip(
    ip: str,
    reason: str = "Auto-blocked by IDS",
    blocked_by: str = "system",
    ttl_seconds: Optional[int] = None,
    layer: str = "firewall",
) -> dict:
    addr = _parse_ip(ip)
    if addr is None:
        return {"blocked": False, "message": f"Invalid IP address: {ip}", "ip": ip}
    if _is_protected(addr):
        return {"blocked": False, "message": f"Protected address — refusing to block {ip}", "ip": ip}

    ip = str(addr)

    with _lock:
        conn = _db()
        try:
            row = conn.execute(
                "SELECT active FROM blocked_ips WHERE ip=?", (ip,)
            ).fetchone()
            if row and row["active"]:
                return {"blocked": False, "message": f"{ip} is already blocked", "ip": ip}

            detail = ""
            if layer in ("firewall", "both"):
                ok, detail = _fw_block(ip)
                if not ok:
                    return {"blocked": False, "message": f"Firewall error: {detail}", "ip": ip}

            if layer in ("span", "both"):
                detail += " | SPAN ACL: configure SPAN_HOST in .env to enable"

            expires_at = None
            if ttl_seconds:
                expires_at = (
                    datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
                ).isoformat(timespec="seconds")

            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            conn.execute("""
                INSERT INTO blocked_ips(ip, reason, blocked_by, blocked_at, expires_at, layer, active)
                VALUES (?,?,?,?,?,?,1)
                ON CONFLICT(ip) DO UPDATE SET
                    reason=excluded.reason, blocked_by=excluded.blocked_by,
                    blocked_at=excluded.blocked_at, expires_at=excluded.expires_at,
                    layer=excluded.layer, active=1
            """, (ip, reason, blocked_by, now, expires_at, layer))
            _audit(conn, "BLOCK", ip, actor=blocked_by, reason=reason, detail=detail)
            conn.commit()

            msg = f"Blocked {ip}"
            if expires_at:
                msg += f" (expires {expires_at})"
            return {"blocked": True, "message": msg, "ip": ip, "expires_at": expires_at}
        finally:
            conn.close()


def unblock_ip(ip: str, unblocked_by: str = "admin") -> dict:
    addr = _parse_ip(ip)
    if addr is None:
        return {"unblocked": False, "message": f"Invalid IP: {ip}", "ip": ip}

    ip = str(addr)

    with _lock:
        conn = _db()
        try:
            row = conn.execute(
                "SELECT active, layer FROM blocked_ips WHERE ip=? AND active=1", (ip,)
            ).fetchone()
            if not row:
                return {"unblocked": False, "message": f"{ip} is not currently blocked", "ip": ip}

            layer  = row["layer"]
            detail = ""
            if layer in ("firewall", "both"):
                _, detail = _fw_unblock(ip)
            if layer in ("span", "both"):
                detail += " | SPAN ACL removal: pending"

            conn.execute("UPDATE blocked_ips SET active=0 WHERE ip=?", (ip,))
            _audit(conn, "UNBLOCK", ip, actor=unblocked_by, detail=detail)
            conn.commit()
            return {"unblocked": True, "message": f"Unblocked {ip}", "ip": ip}
        finally:
            conn.close()


def list_blocked_ips() -> list[dict]:
    """Return all currently active blocked IPs."""
    _expire_ttl()
    with _lock:
        conn = _db()
        try:
            rows = conn.execute("""
                SELECT ip, reason, blocked_by, blocked_at, expires_at, layer
                FROM blocked_ips WHERE active=1
                ORDER BY blocked_at DESC
            """).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_block_audit(ip: Optional[str] = None, limit: int = 200) -> list[dict]:
    """Return full audit log, optionally filtered by IP."""
    with _lock:
        conn = _db()
        try:
            if ip:
                rows = conn.execute(
                    "SELECT * FROM block_audit WHERE ip=? ORDER BY timestamp DESC LIMIT ?",
                    (ip, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM block_audit ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def is_blocked(ip: str) -> bool:
    addr = _parse_ip(ip)
    if addr is None:
        return False
    ip = str(addr)
    _expire_ttl()
    with _lock:
        conn = _db()
        try:
            row = conn.execute(
                "SELECT 1 FROM blocked_ips WHERE ip=? AND active=1", (ip,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()


def bulk_block(ips: list[str], reason: str, blocked_by: str = "system") -> dict:
    """Block multiple IPs. Returns summary."""
    results: dict = {"blocked": [], "skipped": [], "failed": []}
    for ip in ips:
        r = block_ip(ip, reason=reason, blocked_by=blocked_by)
        if r["blocked"]:
            results["blocked"].append(ip)
        elif "already" in r["message"] or "Protected" in r["message"]:
            results["skipped"].append(ip)
        else:
            results["failed"].append({"ip": ip, "reason": r["message"]})
    return results


def bulk_unblock(ips: list[str], unblocked_by: str = "admin") -> dict:
    """Unblock multiple IPs. Returns summary."""
    results: dict = {"unblocked": [], "failed": []}
    for ip in ips:
        r = unblock_ip(ip, unblocked_by=unblocked_by)
        if r["unblocked"]:
            results["unblocked"].append(ip)
        else:
            results["failed"].append({"ip": ip, "reason": r["message"]})
    return results


def _expire_ttl():
    """Auto-expire TTL-based blocks."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock:
        conn = _db()
        try:
            expired = conn.execute("""
                SELECT ip, layer FROM blocked_ips
                WHERE active=1 AND expires_at IS NOT NULL AND expires_at <= ?
            """, (now,)).fetchall()
            for row in expired:
                if row["layer"] in ("firewall", "both"):
                    _fw_unblock(row["ip"])
                conn.execute("UPDATE blocked_ips SET active=0 WHERE ip=?", (row["ip"],))
                _audit(conn, "EXPIRED", row["ip"], actor="system", detail="TTL expired")
            if expired:
                conn.commit()
        finally:
            conn.close()