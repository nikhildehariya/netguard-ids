import sqlite3
from pathlib import Path

AUTH_DB_PATH = Path(__file__).resolve().parent.parent / "logs" / "auth.db"


def _get_conn() -> sqlite3.Connection:
    AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()


def _get_default_admin_email(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT email FROM users WHERE role='admin' AND is_active=1 ORDER BY id LIMIT 1"
    ).fetchone()
    return (row["email"] if row and row["email"] else "").strip()


def get_alert_email_target() -> str:
    conn = _get_conn()
    try:
        _ensure_schema(conn)
        row = conn.execute(
            "SELECT value FROM app_settings WHERE key='alert_to_email'"
        ).fetchone()
        configured = (row["value"] if row and row["value"] else "").strip()
        if configured:
            return configured
        return _get_default_admin_email(conn)
    finally:
        conn.close()


def get_alert_settings() -> dict:
    conn = _get_conn()
    try:
        _ensure_schema(conn)
        row = conn.execute(
            "SELECT value, updated_at FROM app_settings WHERE key='alert_to_email'"
        ).fetchone()
        configured = (row["value"] if row and row["value"] else "").strip()
        updated_at = row["updated_at"] if row else None
        default_email = _get_default_admin_email(conn)
        effective = configured or default_email
        return {
            "alert_to_email": effective,
            "configured_alert_to_email": configured,
            "default_admin_email": default_email,
            "updated_at": updated_at,
        }
    finally:
        conn.close()


def update_alert_to_email(email: str) -> dict:
    value = (email or "").strip()
    conn = _get_conn()
    try:
        _ensure_schema(conn)
        conn.execute(
            """
            INSERT INTO app_settings(key, value, updated_at)
            VALUES('alert_to_email', ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET
                value=excluded.value,
                updated_at=datetime('now')
            """,
            (value,),
        )
        conn.commit()
    finally:
        conn.close()
    return get_alert_settings()
