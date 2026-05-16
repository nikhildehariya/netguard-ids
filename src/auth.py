"""
NetGuard IDS — Authentication System
Industry-grade JWT auth with roles, bcrypt, rate limiting
"""
import sqlite3
import secrets
import hashlib
import hmac
import time
import json
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── Config ────────────────────────────────────────────────────
AUTH_DB_PATH = Path(__file__).resolve().parent.parent / "logs" / "auth.db"

# FIX: Import SECRET_KEY from config so it persists across restarts
# (set SECRET_KEY=<hex> in your .env to make tokens survive restarts)
try:
    from config import SECRET_KEY
except ImportError:
    SECRET_KEY = secrets.token_hex(32)

ACCESS_TOKEN_EXPIRE_MINUTES  = 60
REFRESH_TOKEN_EXPIRE_DAYS    = 7
MAX_LOGIN_ATTEMPTS           = 5
LOCKOUT_MINUTES              = 15

ROLES = ["admin", "analyst", "viewer"]

ROLE_PERMISSIONS = {
    "admin":   ["view", "capture", "block_ip", "unblock_ip", "report", "manage_users"],
    "analyst": ["view", "capture", "block_ip", "report"],
    "viewer":  ["view"],
}

# ── DB Setup ──────────────────────────────────────────────────
def init_db():
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            email         TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'viewer',
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT    NOT NULL,
            last_login    TEXT
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token_hash TEXT    UNIQUE NOT NULL,
            expires_at TEXT    NOT NULL,
            created_at TEXT    NOT NULL,
            revoked    INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            ip_address TEXT,
            success    INTEGER NOT NULL DEFAULT 0,
            attempted_at TEXT NOT NULL
        );
    """)
    conn.commit()

    # Create default admin if no users exist
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        _create_user_internal(conn, "admin", "admin@netguard.local", "netguard123", "admin")
        print("[auth] Default admin created: admin / netguard123")

    conn.close()


# ── Password Hashing ──────────────────────────────────────────
def _hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return key.hex(), salt


def _verify_password(password: str, stored_hash: str) -> bool:
    # stored_hash format: "hash:salt"
    parts = stored_hash.split(":")
    if len(parts) != 2:
        return False
    stored, salt = parts
    computed, _ = _hash_password(password, salt)
    return hmac.compare_digest(computed, stored)


def _make_password_hash(password: str) -> str:
    h, s = _hash_password(password)
    return f"{h}:{s}"


# ── JWT (manual, no extra lib needed) ────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(payload: dict, secret: str, expires_minutes: int) -> str:
    payload = dict(payload)  # FIX: don't mutate caller's dict
    payload["exp"] = int(time.time()) + expires_minutes * 60
    payload["iat"] = int(time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body   = _b64(json.dumps(payload).encode())
    # FIX: use hmac.new() correctly with digestmod keyword
    sig = _b64(hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def _verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        expected = _b64(hmac.new(SECRET_KEY.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        pad = 4 - len(body) % 4
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * pad))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ── User Management ───────────────────────────────────────────
def _create_user_internal(conn, username, email, password, role):
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
        (username, email, _make_password_hash(password), role, datetime.now().isoformat())
    )
    conn.commit()


def create_user(username: str, email: str, password: str, role: str = "viewer") -> dict:
    if role not in ROLES:
        return {"success": False, "message": f"Invalid role. Choose from: {ROLES}"}
    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters"}
    if len(username) < 3:
        return {"success": False, "message": "Username must be at least 3 characters"}

    conn = sqlite3.connect(AUTH_DB_PATH)
    try:
        _create_user_internal(conn, username, email, password, role)
        return {"success": True, "message": f"User '{username}' created with role '{role}'"}
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return {"success": False, "message": "Username already exists"}
        return {"success": False, "message": "Email already exists"}
    finally:
        conn.close()


def list_users() -> list:
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, is_active, created_at, last_login FROM users")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "username": r[1], "email": r[2], "role": r[3],
             "is_active": bool(r[4]), "created_at": r[5], "last_login": r[6]} for r in rows]


def update_user_role(username: str, new_role: str) -> dict:
    if new_role not in ROLES:
        return {"success": False, "message": "Invalid role"}
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET role=? WHERE username=?", (new_role, username))
    conn.commit()
    conn.close()
    return {"success": True, "message": f"Role updated to {new_role}"}


def delete_user(username: str) -> dict:
    if username == "admin":
        return {"success": False, "message": "Cannot delete default admin"}
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return {"success": True, "message": f"User '{username}' deleted"}


def toggle_user_active(username: str) -> dict:
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET is_active = 1 - is_active WHERE username=?", (username,))
    conn.commit()
    c.execute("SELECT is_active FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return {"success": False, "message": "User not found"}
    return {"success": True, "active": bool(row[0])}


# ── Rate Limiting ─────────────────────────────────────────────
def _is_locked_out(username: str, ip: str) -> bool:
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    c.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE (username=? OR ip_address=?) AND success=0 AND attempted_at>?",
        (username, ip, cutoff)
    )
    count = c.fetchone()[0]
    conn.close()
    return count >= MAX_LOGIN_ATTEMPTS


def _log_attempt(username: str, ip: str, success: bool):
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES (?,?,?,?)",
        (username, ip, int(success), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


# ── Login / Token ─────────────────────────────────────────────
def login(username: str, password: str, ip: str = "unknown") -> dict:
    if _is_locked_out(username, ip):
        return {
            "success": False,
            "message": f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.",
            "locked": True
        }

    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, password_hash, role, is_active FROM users WHERE username=?", (username,))
    row = c.fetchone()

    if not row or not _verify_password(password, row[1]):
        _log_attempt(username, ip, False)
        conn.close()
        return {"success": False, "message": "Invalid username or password"}

    if not row[3]:
        conn.close()
        return {"success": False, "message": "Account is disabled. Contact admin."}

    user_id, _, role, _ = row

    # Update last login
    c.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now().isoformat(), user_id))
    conn.commit()

    # Generate tokens
    access_token = _sign(
        {"sub": username, "role": role, "uid": user_id, "type": "access"},
        SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
    )
    refresh_raw  = secrets.token_hex(32)
    refresh_hash = hashlib.sha256(refresh_raw.encode()).hexdigest()
    refresh_exp  = (datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()

    c.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES (?,?,?,?)",
        (user_id, refresh_hash, refresh_exp, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    _log_attempt(username, ip, True)

    return {
        "success":       True,
        "access_token":  access_token,
        "refresh_token": refresh_raw,
        "token_type":    "bearer",
        "expires_in":    ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "username":    username,
            "role":        role,
            "permissions": ROLE_PERMISSIONS[role],
        }
    }


def refresh_access_token(refresh_token: str) -> dict:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT rt.user_id, u.username, u.role FROM refresh_tokens rt JOIN users u ON rt.user_id=u.id "
        "WHERE rt.token_hash=? AND rt.revoked=0 AND rt.expires_at>?",
        (token_hash, datetime.now().isoformat())
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": "Invalid or expired refresh token"}

    user_id, username, role = row
    access_token = _sign(
        {"sub": username, "role": role, "uid": user_id, "type": "access"},
        SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
    )
    conn.close()
    return {"success": True, "access_token": access_token, "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}


def logout(refresh_token: str) -> dict:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    conn = sqlite3.connect(AUTH_DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (token_hash,))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Logged out"}


def verify_request(token: str) -> Optional[dict]:
    """Returns user payload if token valid, else None."""
    return _verify_token(token)


def has_permission(token: str, permission: str) -> bool:
    payload = verify_request(token)
    if not payload:
        return False
    role = payload.get("role", "viewer")
    return permission in ROLE_PERMISSIONS.get(role, [])


# Init on import
init_db()