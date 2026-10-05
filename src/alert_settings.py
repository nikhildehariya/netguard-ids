import psycopg2
import psycopg2.extras

from database import get_db_connection, release_db_connection

def _get_default_admin_email(conn) -> str:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT email FROM users WHERE role='admin' AND is_active=1 ORDER BY id LIMIT 1"
        )
        row = cur.fetchone()
        return (row["email"] if row and row["email"] else "").strip()

def get_alert_email_target() -> str:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT value FROM app_settings WHERE key='alert_to_email'")
            row = cur.fetchone()
            configured = (row["value"] if row and row["value"] else "").strip()
            if configured:
                return configured
            return _get_default_admin_email(conn)
    finally:
        release_db_connection(conn)

def get_alert_settings() -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT value, updated_at FROM app_settings WHERE key='alert_to_email'")
            row = cur.fetchone()
            configured = (row["value"] if row and row["value"] else "").strip()
            updated_at = row["updated_at"] if row else None
            default_email = _get_default_admin_email(conn)
            effective = configured or default_email
            return {
                "alert_to_email": effective,
                "configured_alert_to_email": configured,
                "default_admin_email": default_email,
                "updated_at": str(updated_at) if updated_at else None,
            }
    finally:
        release_db_connection(conn)

def update_alert_to_email(email: str) -> dict:
    value = (email or "").strip()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO app_settings(key, value, updated_at)
                VALUES('alert_to_email', %s, CURRENT_TIMESTAMP::text)
                ON CONFLICT(key) DO UPDATE SET
                    value=EXCLUDED.value,
                    updated_at=CURRENT_TIMESTAMP::text
                """,
                (value,),
            )
        conn.commit()
    finally:
        release_db_connection(conn)
    return get_alert_settings()
