# =============================================================
# database.py — NetGuard IDS v2.2
# Unified Database Adapter for PostgreSQL (psycopg2)
# =============================================================

import os
import psycopg2
import psycopg2.extras
from pathlib import Path
from typing import Optional, Any, Dict, List

from config import (
    DATABASE_URL, POSTGRES_HOST, POSTGRES_PORT,
    POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_SSLMODE,
    DASHBOARD_USERNAME, DASHBOARD_PASSWORD
)

def _get_pg_url() -> str:
    if DATABASE_URL:
        return DATABASE_URL
    return f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}?sslmode={POSTGRES_SSLMODE}"

def get_db_connection():
    """Returns a psycopg2 connection to PostgreSQL."""
    return psycopg2.connect(_get_pg_url())

def get_db_mode() -> str:
    return "postgres"

def init_pg_db():
    """Initializes PostgreSQL schemas and default records."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # 1. users
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
            """)

            # 2. refresh_tokens
            cur.execute("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id         SERIAL PRIMARY KEY,
                    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(255) UNIQUE NOT NULL,
                    expires_at VARCHAR(100) NOT NULL,
                    created_at VARCHAR(100) NOT NULL,
                    revoked    INTEGER NOT NULL DEFAULT 0
                );
            """)

            # 3. login_attempts
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id           SERIAL PRIMARY KEY,
                    username     VARCHAR(255) NOT NULL,
                    ip_address   VARCHAR(100),
                    success      INTEGER NOT NULL DEFAULT 0,
                    attempted_at VARCHAR(100) NOT NULL
                );
            """)

            # 4. app_settings
            cur.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key        VARCHAR(255) PRIMARY KEY,
                    value      TEXT NOT NULL,
                    updated_at VARCHAR(100) NOT NULL DEFAULT CURRENT_TIMESTAMP::text
                );
            """)

            # 5. detections
            cur.execute("""
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
                CREATE INDEX IF NOT EXISTS idx_det_ts         ON detections(timestamp);
                CREATE INDEX IF NOT EXISTS idx_det_prediction ON detections(prediction);
                CREATE INDEX IF NOT EXISTS idx_det_source_ip  ON detections(source_ip);
                CREATE INDEX IF NOT EXISTS idx_det_severity   ON detections(severity);
            """)

            # 6. blocked_ips
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip          VARCHAR(100) PRIMARY KEY,
                    reason      TEXT NOT NULL,
                    blocked_by  VARCHAR(100) NOT NULL DEFAULT 'system',
                    blocked_at  VARCHAR(100) NOT NULL,
                    expires_at  VARCHAR(100),
                    layer       VARCHAR(50) NOT NULL DEFAULT 'firewall',
                    active      INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(active);
            """)

            # 7. block_audit
            cur.execute("""
                CREATE TABLE IF NOT EXISTS block_audit (
                    id        SERIAL PRIMARY KEY,
                    event     VARCHAR(100) NOT NULL,
                    ip        VARCHAR(100) NOT NULL,
                    actor     VARCHAR(100) NOT NULL DEFAULT 'system',
                    reason    TEXT,
                    timestamp VARCHAR(100) NOT NULL,
                    detail    TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_ip ON block_audit(ip);
                CREATE INDEX IF NOT EXISTS idx_audit_ts ON block_audit(timestamp);
            """)

        conn.commit()
    finally:
        conn.close()

# Auto-initialize tables on module import
try:
    init_pg_db()
except Exception as e:
    print(f"[database.py] Warning: Could not initialize PostgreSQL tables: {e}")
