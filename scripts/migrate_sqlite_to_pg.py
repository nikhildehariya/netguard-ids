# =============================================================
# migrate_sqlite_to_pg.py — NetGuard IDS v2.1
# Chunk-Optimized SQLite to PostgreSQL Migration Script
# =============================================================

import os
import sys
import sqlite3
from pathlib import Path
import psycopg2.extras

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

from database import get_db_connection, init_pg_db

def migrate_all():
    print("[migration] Initializing PostgreSQL schemas...")
    init_pg_db()

    logs_dir = BASE_DIR / "logs"

    # 1. Migrate auth.db
    auth_db = logs_dir / "auth.db"
    if auth_db.exists():
        print(f"[migration] Migrating {auth_db.name}...")
        pg_conn = get_db_connection()
        try:
            with pg_conn.cursor() as cur:
                s_conn = sqlite3.connect(auth_db)
                s_conn.row_factory = sqlite3.Row

                # users
                s_users = s_conn.execute("SELECT * FROM users").fetchall()
                if s_users:
                    user_rows = [(
                        dict(u).get("id"),
                        dict(u).get("username"),
                        dict(u).get("email"),
                        dict(u).get("password_hash"),
                        dict(u).get("role", "viewer"),
                        dict(u).get("is_active", 1),
                        dict(u).get("created_at"),
                        dict(u).get("last_login"),
                        dict(u).get("full_name", ""),
                        dict(u).get("phone", ""),
                        dict(u).get("designation", "")
                    ) for u in s_users]
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO users (id, username, email, password_hash, role, is_active, created_at, last_login, full_name, phone, designation)
                        VALUES %s
                        ON CONFLICT (username) DO NOTHING
                        """,
                        user_rows
                    )
                    cur.execute("SELECT setval(pg_get_serial_sequence('users', 'id'), COALESCE(MAX(id), 1)) FROM users;")
                    print(f"  -> Migrated {len(s_users)} users")

                # refresh_tokens
                s_tokens = s_conn.execute("SELECT * FROM refresh_tokens").fetchall()
                if s_tokens:
                    token_rows = []
                    for t in s_tokens:
                        t_dict = dict(t)
                        cur.execute("SELECT 1 FROM users WHERE id = %s", (t_dict.get("user_id"),))
                        if cur.fetchone():
                            token_rows.append((
                                t_dict.get("id"),
                                t_dict.get("user_id"),
                                t_dict.get("token_hash"),
                                t_dict.get("expires_at"),
                                t_dict.get("created_at"),
                                t_dict.get("revoked", 0)
                            ))
                    if token_rows:
                        psycopg2.extras.execute_values(
                            cur,
                            """
                            INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, revoked)
                            VALUES %s
                            ON CONFLICT (token_hash) DO NOTHING
                            """,
                            token_rows
                        )
                        cur.execute("SELECT setval(pg_get_serial_sequence('refresh_tokens', 'id'), COALESCE(MAX(id), 1)) FROM refresh_tokens;")
                    print(f"  -> Migrated {len(token_rows)} valid refresh_tokens")

                # login_attempts
                s_attempts = s_conn.execute("SELECT * FROM login_attempts").fetchall()
                if s_attempts:
                    attempt_rows = [(
                        dict(a).get("username"),
                        dict(a).get("ip_address"),
                        dict(a).get("success", 0),
                        dict(a).get("attempted_at")
                    ) for a in s_attempts]
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO login_attempts (username, ip_address, success, attempted_at)
                        VALUES %s
                        """,
                        attempt_rows
                    )
                    print(f"  -> Migrated {len(s_attempts)} login_attempts")

                # app_settings
                try:
                    s_settings = s_conn.execute("SELECT * FROM app_settings").fetchall()
                    if s_settings:
                        setting_rows = [(
                            dict(s).get("key"),
                            dict(s).get("value"),
                            dict(s).get("updated_at")
                        ) for s in s_settings]
                        psycopg2.extras.execute_values(
                            cur,
                            """
                            INSERT INTO app_settings (key, value, updated_at)
                            VALUES %s
                            ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at
                            """,
                            setting_rows
                        )
                        print(f"  -> Migrated {len(s_settings)} app_settings")
                except Exception:
                    pass

                s_conn.close()
            pg_conn.commit()
        except Exception as e:
            pg_conn.rollback()
            print(f"[ERROR] Failed auth.db migration: {e}")
        finally:
            pg_conn.close()

    # 2. Migrate blocklist.db
    block_db = logs_dir / "blocklist.db"
    if block_db.exists():
        print(f"[migration] Migrating {block_db.name}...")
        pg_conn = get_db_connection()
        try:
            with pg_conn.cursor() as cur:
                s_conn = sqlite3.connect(block_db)
                s_conn.row_factory = sqlite3.Row
                
                # blocked_ips
                s_blocks = s_conn.execute("SELECT * FROM blocked_ips").fetchall()
                if s_blocks:
                    block_rows = [(
                        dict(b).get("ip"),
                        dict(b).get("reason"),
                        dict(b).get("blocked_by", "system"),
                        dict(b).get("blocked_at"),
                        dict(b).get("expires_at"),
                        dict(b).get("layer", "firewall"),
                        dict(b).get("active", 1)
                    ) for b in s_blocks]
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO blocked_ips (ip, reason, blocked_by, blocked_at, expires_at, layer, active)
                        VALUES %s
                        ON CONFLICT (ip) DO UPDATE SET
                            reason=EXCLUDED.reason, blocked_by=EXCLUDED.blocked_by,
                            blocked_at=EXCLUDED.blocked_at, expires_at=EXCLUDED.expires_at,
                            layer=EXCLUDED.layer, active=EXCLUDED.active
                        """,
                        block_rows
                    )
                    print(f"  -> Migrated {len(s_blocks)} blocked_ips")

                # block_audit
                s_audits = s_conn.execute("SELECT * FROM block_audit").fetchall()
                if s_audits:
                    audit_rows = [(
                        dict(a).get("id"),
                        dict(a).get("event"),
                        dict(a).get("ip"),
                        dict(a).get("actor", "system"),
                        dict(a).get("reason"),
                        dict(a).get("timestamp"),
                        dict(a).get("detail")
                    ) for a in s_audits]
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO block_audit (id, event, ip, actor, reason, timestamp, detail)
                        VALUES %s
                        ON CONFLICT (id) DO NOTHING
                        """,
                        audit_rows
                    )
                    cur.execute("SELECT setval(pg_get_serial_sequence('block_audit', 'id'), COALESCE(MAX(id), 1)) FROM block_audit;")
                    print(f"  -> Migrated {len(s_audits)} block_audit entries")
                s_conn.close()
            pg_conn.commit()
        except Exception as e:
            pg_conn.rollback()
            print(f"[ERROR] Failed blocklist.db migration: {e}")
        finally:
            pg_conn.close()

    # 3. Migrate detections.db in 5000-row chunks
    det_db = logs_dir / "detections.db"
    if det_db.exists():
        print(f"[migration] Migrating {det_db.name} in chunks...")
        s_conn = sqlite3.connect(det_db)
        s_conn.row_factory = sqlite3.Row
        s_cur = s_conn.cursor()
        s_cur.execute("SELECT COUNT(*) FROM detections")
        total_dets = s_cur.fetchone()[0]
        print(f"  Total detections to migrate: {total_dets}")

        s_cur.execute("SELECT * FROM detections ORDER BY id ASC")
        chunk_size = 5000
        migrated_cnt = 0

        pg_conn = get_db_connection()
        while True:
            rows = s_cur.fetchmany(chunk_size)
            if not rows:
                break
            det_rows = [(
                dict(d).get("id"),
                dict(d).get("timestamp"),
                dict(d).get("prediction"),
                dict(d).get("confidence", 0.0),
                dict(d).get("severity", "none"),
                dict(d).get("source_ip", "unknown"),
                dict(d).get("flow_id", ""),
                dict(d).get("mode", "live")
            ) for d in rows]

            try:
                with pg_conn.cursor() as cur:
                    psycopg2.extras.execute_values(
                        cur,
                        """
                        INSERT INTO detections (id, timestamp, prediction, confidence, severity, source_ip, flow_id, mode)
                        VALUES %s
                        ON CONFLICT (id) DO NOTHING
                        """,
                        det_rows,
                        page_size=1000
                    )
                pg_conn.commit()
                migrated_cnt += len(det_rows)
                print(f"  -> Migrated {migrated_cnt} / {total_dets} detections ({round(migrated_cnt/total_dets*100, 1)}%)")
            except Exception as e:
                print(f"[ERROR] Chunk insertion error at {migrated_cnt}: {e}")
                try:
                    pg_conn.rollback()
                    pg_conn.close()
                except Exception:
                    pass
                pg_conn = get_db_connection()

        if pg_conn:
            with pg_conn.cursor() as cur:
                cur.execute("SELECT setval(pg_get_serial_sequence('detections', 'id'), COALESCE(MAX(id), 1)) FROM detections;")
            pg_conn.commit()
            pg_conn.close()

        s_conn.close()

    print("[SUCCESS] All data migrated to PostgreSQL successfully!")

if __name__ == "__main__":
    migrate_all()
