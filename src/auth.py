"""
NetGuard IDS — Authentication System
Industry-grade JWT auth with roles, bcrypt/pbkdf2, rate limiting (PostgreSQL backed)
"""
import secrets
import hashlib
import hmac
import time
import json
import base64
from datetime import datetime, timedelta
from typing import Optional
import psycopg2
import psycopg2.extras

from database import get_db_connection, release_db_connection, init_pg_db

# ── Config ────────────────────────────────────────────────────
try:
    from config import SECRET_KEY, DASHBOARD_USERNAME, DASHBOARD_PASSWORD
except ImportError:
    SECRET_KEY = secrets.token_hex(32)
    DASHBOARD_USERNAME = "admin"
    DASHBOARD_PASSWORD = "netguard123"

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
    init_pg_db()
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            # Create default admin if no users exist
            c.execute("SELECT COUNT(*) FROM users")
            if c.fetchone()[0] == 0:
                _create_user_internal(c, DASHBOARD_USERNAME, f"{DASHBOARD_USERNAME}@netguard.local", DASHBOARD_PASSWORD, "admin", "System Administrator", "+919999999999", "Security Operations")
                conn.commit()
                print(f"[auth] Default admin created in PostgreSQL: {DASHBOARD_USERNAME} / {DASHBOARD_PASSWORD}")
    finally:
        release_db_connection(conn)

# ── Password Hashing ──────────────────────────────────────────
def _hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return key.hex(), salt

def _verify_password(password: str, stored_hash: str) -> bool:
    parts = stored_hash.split(":")
    if len(parts) != 2:
        return False
    stored, salt = parts
    computed, _ = _hash_password(password, salt)
    return hmac.compare_digest(computed, stored)

def _make_password_hash(password: str) -> str:
    h, s = _hash_password(password)
    return f"{h}:{s}"

# ── JWT ───────────────────────────────────────────────────────
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _sign(payload: dict, secret: str, expires_minutes: int) -> str:
    payload = dict(payload)
    payload["exp"] = int(time.time()) + expires_minutes * 60
    payload["iat"] = int(time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body   = _b64(json.dumps(payload).encode())
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
def _create_user_internal(cur, username, email, password, role, full_name="", phone="", designation=""):
    cur.execute(
        "INSERT INTO users (username, email, password_hash, role, created_at, full_name, phone, designation) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        (username, email, _make_password_hash(password), role, datetime.now().isoformat(), full_name, phone, designation)
    )

def create_user(username: str, email: str, password: str, role: str = "viewer", full_name: str = "", phone: str = "", designation: str = "") -> dict:
    if role not in ROLES:
        return {"success": False, "message": f"Invalid role. Choose from: {ROLES}"}
    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters"}
    if len(username) < 3:
        return {"success": False, "message": "Username must be at least 3 characters"}

    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            _create_user_internal(c, username, email, password, role, full_name, phone, designation)
        conn.commit()
        return {"success": True, "message": f"User '{username}' created successfully"}
    except psycopg2.IntegrityError as e:
        conn.rollback()
        if "username" in str(e):
            return {"success": False, "message": "Username already exists"}
        return {"success": False, "message": "Email already exists"}
    finally:
        release_db_connection(conn)

def list_users() -> list:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
            c.execute("SELECT id, username, email, role, is_active, created_at, last_login, full_name, phone, designation FROM users ORDER BY id ASC")
            rows = c.fetchall()
            return [dict(r) for r in rows]
    finally:
        release_db_connection(conn)

def update_user_role(username: str, new_role: str) -> dict:
    if new_role not in ROLES:
        return {"success": False, "message": "Invalid role"}
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("UPDATE users SET role=%s WHERE username=%s", (new_role, username))
        conn.commit()
        return {"success": True, "message": f"Role updated to {new_role}"}
    finally:
        release_db_connection(conn)

def delete_user(username: str) -> dict:
    if username == "admin":
        return {"success": False, "message": "Cannot delete default admin"}
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("DELETE FROM users WHERE username=%s", (username,))
        conn.commit()
        return {"success": True, "message": f"User '{username}' deleted"}
    finally:
        release_db_connection(conn)

def toggle_user_active(username: str) -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("UPDATE users SET is_active = 1 - is_active WHERE username=%s RETURNING is_active", (username,))
            row = c.fetchone()
        conn.commit()
        if not row:
            return {"success": False, "message": "User not found"}
        return {"success": True, "active": bool(row[0])}
    finally:
        release_db_connection(conn)

# ── Rate Limiting ─────────────────────────────────────────────
def _is_locked_out_conn(conn, username: str, ip: str) -> bool:
    cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    with conn.cursor() as c:
        c.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE (username=%s OR ip_address=%s) AND success=0 AND attempted_at>%s",
            (username, ip, cutoff)
        )
        count = c.fetchone()[0]
        return count >= MAX_LOGIN_ATTEMPTS

def _log_attempt_conn(conn, username: str, ip: str, success: bool):
    with conn.cursor() as c:
        c.execute(
            "INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES (%s,%s,%s,%s)",
            (username, ip, int(success), datetime.now().isoformat())
        )
    conn.commit()

# ── Login / Token ─────────────────────────────────────────────
def login(username: str, password: str, ip: str = "unknown") -> dict:
    conn = get_db_connection()
    try:
        cutoff = (datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        with conn.cursor() as c:
            # 1. Lockout check
            c.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE (username=%s OR ip_address=%s) AND success=0 AND attempted_at>%s",
                (username, ip, cutoff)
            )
            failed_cnt = c.fetchone()[0]
            if failed_cnt >= MAX_LOGIN_ATTEMPTS:
                return {
                    "success": False,
                    "message": f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.",
                    "locked": True
                }

            # 2. User lookup
            c.execute("SELECT id, password_hash, role, is_active FROM users WHERE username=%s", (username,))
            row = c.fetchone()

            if not row or not _verify_password(password, row[1]):
                c.execute(
                    "INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES (%s,%s,0,%s)",
                    (username, ip, datetime.now().isoformat())
                )
                conn.commit()
                return {"success": False, "message": "Invalid username or password"}

            if not row[3]:
                return {"success": False, "message": "Account is disabled. Contact admin."}

            user_id, _, role, _ = row
            now_iso = datetime.now().isoformat()

            # 3. Batch update last_login, refresh token & log attempt in single transaction
            c.execute("UPDATE users SET last_login=%s WHERE id=%s", (now_iso, user_id))

            access_token = _sign(
                {"sub": username, "role": role, "uid": user_id, "type": "access"},
                SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
            )
            refresh_raw  = secrets.token_hex(32)
            refresh_hash = hashlib.sha256(refresh_raw.encode()).hexdigest()
            refresh_exp  = (datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)).isoformat()

            c.execute(
                "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at) VALUES (%s,%s,%s,%s)",
                (user_id, refresh_hash, refresh_exp, now_iso)
            )
            c.execute(
                "INSERT INTO login_attempts (username, ip_address, success, attempted_at) VALUES (%s,%s,1,%s)",
                (username, ip, now_iso)
            )
            conn.commit()

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
    finally:
        release_db_connection(conn)


def refresh_access_token(refresh_token: str) -> dict:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute(
                "SELECT rt.user_id, u.username, u.role FROM refresh_tokens rt JOIN users u ON rt.user_id=u.id "
                "WHERE rt.token_hash=%s AND rt.revoked=0 AND rt.expires_at>%s",
                (token_hash, datetime.now().isoformat())
            )
            row = c.fetchone()
            if not row:
                return {"success": False, "message": "Invalid or expired refresh token"}

            user_id, username, role = row
            access_token = _sign(
                {"sub": username, "role": role, "uid": user_id, "type": "access"},
                SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
            )
            return {"success": True, "access_token": access_token, "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60}
    finally:
        conn.close()

def logout(refresh_token: str) -> dict:
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=%s", (token_hash,))
        conn.commit()
        return {"success": True, "message": "Logged out"}
    finally:
        conn.close()

def verify_request(token: str) -> Optional[dict]:
    return _verify_token(token)

def has_permission(token: str, permission: str) -> bool:
    payload = verify_request(token)
    if not payload:
        return False
    role = payload.get("role", "viewer")
    return permission in ROLE_PERMISSIONS.get(role, [])

# Init on import
try:
    init_db()
except Exception as e:
    print(f"[auth] Init error: {e}")