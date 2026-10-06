# =============================================================
# database.py — NetGuard IDS v2.2
# High-Performance Hybrid Database Adapter (PostgreSQL + Ultra-fast Local SQLite Fallback)
# =============================================================

import os
import re
import sqlite3
from pathlib import Path
from typing import Optional, Any, Dict, List

try:
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool
    PSYCOPG2_OK = True
except ImportError:
    PSYCOPG2_OK = False

from config import (
    DATABASE_URL, POSTGRES_HOST, POSTGRES_PORT,
    POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_SSLMODE,
    DASHBOARD_USERNAME, DASHBOARD_PASSWORD
)

BASE_DIR = Path(__file__).resolve().parent.parent
LOCAL_DB_PATH = BASE_DIR / "logs" / "detections.db"
LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

USE_POSTGRES = os.getenv("USE_POSTGRES", "false").lower() == "true"

_db_pool = None

# ── SQLite Compatibility Wrappers ──────────────────────────────
class SQLiteCursorWrapper:
    def __init__(self, cur, is_dict=False):
        self._cur = cur
        self.is_dict = is_dict
        self._last_id = None

    def execute(self, query, params=None):
        query_sq = query.replace("%s", "?")
        returning_col = None
        if "RETURNING" in query_sq.upper():
            parts = re.split(r'\s+RETURNING\s+', query_sq, flags=re.IGNORECASE)
            query_sq = parts[0].strip()
            returning_col = parts[1].strip()

        if params:
            self._cur.execute(query_sq, params)
        else:
            self._cur.execute(query_sq)

        if returning_col:
            self._last_id = self._cur.lastrowid

        return self

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None and self._last_id is not None:
            res = (self._last_id,)
            self._last_id = None
            return res
        if self.is_dict and row is not None:
            return dict(row)
        return row

    def fetchall(self):
        rows = self._cur.fetchall()
        if self.is_dict and rows:
            return [dict(r) for r in rows]
        return rows

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class SQLiteConnWrapper:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self, cursor_factory=None):
        is_dict = (cursor_factory is not None)
        cur = self._conn.cursor()
        return SQLiteCursorWrapper(cur, is_dict=is_dict)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def _get_pg_url() -> str:
    if DATABASE_URL:
        return DATABASE_URL
    return f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}?sslmode={POSTGRES_SSLMODE}"


def _get_pool():
    global _db_pool
    if not PSYCOPG2_OK:
        return None
    if _db_pool is None or _db_pool.closed:
        try:
            _db_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                dsn=_get_pg_url(),
                connect_timeout=2
            )
        except Exception:
            _db_pool = None
    return _db_pool


def get_db_connection():
    """Returns PostgreSQL connection if available, otherwise falls back to ultra-fast local SQLite."""
    if USE_POSTGRES and PSYCOPG2_OK:
        try:
            pool = _get_pool()
            if pool:
                conn = pool.getconn()
                if conn.closed == 0:
                    return conn
        except Exception:
            pass

    # High-speed local SQLite database
    conn = sqlite3.connect(str(LOCAL_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return SQLiteConnWrapper(conn)


def release_db_connection(conn):
    """Releases PostgreSQL connection back to pool or closes SQLite connection."""
    if conn is None:
        return
    if isinstance(conn, SQLiteConnWrapper):
        try:
            conn.close()
        except Exception:
            pass
        return

    if PSYCOPG2_OK and _db_pool and not _db_pool.closed:
        try:
            _db_pool.putconn(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
    else:
        try:
            conn.close()
        except Exception:
            pass


def get_db_mode() -> str:
    return "postgres" if (USE_POSTGRES and PSYCOPG2_OK) else "sqlite"


def init_pg_db():
    """Initializes schemas and default records."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            if get_db_mode() == "postgres":
                # PostgreSQL DDL
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id            SERIAL PRIMARY KEY,
                        username      VARCHAR(255) UNIQUE NOT NULL,
                        email         VARCHAR(255) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        role          VARCHAR(50) NOT NULL DEFAULT 'viewer',
                        is_active     INTEGER NOT NULL DEFAULT 1,
                        created_at    VARCHAR(100) NOT NULL,
                        last_login    VARCHAR(100),
                        full_name     VARCHAR(255) DEFAULT '',
                        phone         VARCHAR(50) DEFAULT '',
                        designation   VARCHAR(255) DEFAULT ''
                    );
                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                        id         SERIAL PRIMARY KEY,
                        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        token_hash VARCHAR(255) UNIQUE NOT NULL,
                        expires_at VARCHAR(100) NOT NULL,
                        created_at VARCHAR(100) NOT NULL,
                        revoked    INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id           SERIAL PRIMARY KEY,
                        username     VARCHAR(255) NOT NULL,
                        ip_address   VARCHAR(100),
                        success      INTEGER NOT NULL DEFAULT 0,
                        attempted_at VARCHAR(100) NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS app_settings (
                        key        VARCHAR(255) PRIMARY KEY,
                        value      TEXT NOT NULL,
                        updated_at VARCHAR(100) NOT NULL DEFAULT CURRENT_TIMESTAMP::text
                    );
                    CREATE TABLE IF NOT EXISTS detections (
                        id          SERIAL PRIMARY KEY,
                        timestamp   VARCHAR(100) NOT NULL,
                        prediction  VARCHAR(100) NOT NULL,
                        confidence  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                        severity    VARCHAR(50) NOT NULL DEFAULT 'none',
                        source_ip   VARCHAR(100) NOT NULL DEFAULT 'unknown',
                        flow_id     VARCHAR(255) NOT NULL DEFAULT '',
                        mode        VARCHAR(50) NOT NULL DEFAULT 'live'
                    );
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        ip          VARCHAR(100) PRIMARY KEY,
                        reason      TEXT NOT NULL,
                        blocked_by  VARCHAR(100) NOT NULL DEFAULT 'system',
                        blocked_at  VARCHAR(100) NOT NULL,
                        expires_at  VARCHAR(100),
                        layer       VARCHAR(50) NOT NULL DEFAULT 'firewall',
                        active      INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE IF NOT EXISTS block_audit (
                        id        SERIAL PRIMARY KEY,
                        event     VARCHAR(100) NOT NULL,
                        ip        VARCHAR(100) NOT NULL,
                        actor     VARCHAR(100) NOT NULL DEFAULT 'system',
                        reason    TEXT,
                        timestamp VARCHAR(100) NOT NULL,
                        detail    TEXT
                    );
                """)
            else:
                # SQLite DDL
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        username      TEXT UNIQUE NOT NULL,
                        email         TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role          TEXT NOT NULL DEFAULT 'viewer',
                        is_active     INTEGER NOT NULL DEFAULT 1,
                        created_at    TEXT NOT NULL,
                        last_login    TEXT,
                        full_name     TEXT DEFAULT '',
                        phone         TEXT DEFAULT '',
                        designation   TEXT DEFAULT ''
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS refresh_tokens (
                        id         INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id    INTEGER NOT NULL,
                        token_hash TEXT UNIQUE NOT NULL,
                        expires_at TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        revoked    INTEGER NOT NULL DEFAULT 0
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        username     TEXT NOT NULL,
                        ip_address   TEXT,
                        success      INTEGER NOT NULL DEFAULT 0,
                        attempted_at TEXT NOT NULL
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS app_settings (
                        key        TEXT PRIMARY KEY,
                        value      TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS detections (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        prediction  TEXT NOT NULL,
                        confidence  REAL NOT NULL DEFAULT 0.0,
                        severity    TEXT NOT NULL DEFAULT 'none',
                        source_ip   TEXT NOT NULL DEFAULT 'unknown',
                        flow_id     TEXT NOT NULL DEFAULT '',
                        mode        TEXT NOT NULL DEFAULT 'benchmark'
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        ip          TEXT PRIMARY KEY,
                        reason      TEXT NOT NULL,
                        blocked_by  TEXT NOT NULL DEFAULT 'system',
                        blocked_at  TEXT NOT NULL,
                        expires_at  TEXT,
                        layer       TEXT NOT NULL DEFAULT 'firewall',
                        active      INTEGER NOT NULL DEFAULT 1
                    );
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS block_audit (
                        id        INTEGER PRIMARY KEY AUTOINCREMENT,
                        event     TEXT NOT NULL,
                        ip        TEXT NOT NULL,
                        actor     TEXT NOT NULL DEFAULT 'system',
                        reason    TEXT,
                        timestamp TEXT NOT NULL,
                        detail    TEXT
                    );
                """)
        conn.commit()
    finally:
        release_db_connection(conn)
