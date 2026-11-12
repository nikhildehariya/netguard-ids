# =============================================================
# detections_db.py — NetGuard IDS v2.1
# SQLite storage for detections + CSV migration
# =============================================================

import sqlite3
import csv
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH  = BASE_DIR / "logs" / "detections.db"
CSV_PATH = BASE_DIR / "logs" / "detections.csv"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    prediction  TEXT NOT NULL,
    confidence  REAL NOT NULL DEFAULT 0.0,
    severity    TEXT NOT NULL DEFAULT 'none',
    source_ip   TEXT NOT NULL DEFAULT 'unknown',
    flow_id     TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT 'live'
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


def _safe_float(val, default=0.0) -> float:
    """Safely convert any value to float — handles empty, None, strings."""
    try:
        f = float(val)
        # Reject NaN/Inf
        if f != f or f == float('inf') or f == float('-inf'):
            return default
        return f
    except (TypeError, ValueError):
        return default


def _safe_str(val, default="unknown") -> str:
    if val is None or str(val).strip() == "":
        return default
    return str(val).strip()


def migrate_csv_to_sqlite() -> dict:
    """One-time migration: detections.csv → detections.db"""
    if not CSV_PATH.exists():
        return {"success": False, "message": f"CSV not found: {CSV_PATH}"}

    conn = _get_db()
    migrated = 0
    skipped  = 0
    errors   = []

    try:
        with open(CSV_PATH, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO detections
                            (timestamp, prediction, confidence, severity, source_ip, flow_id, mode)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        _safe_str(row.get("timestamp"), datetime.now(timezone.utc).isoformat()),
                        _safe_str(row.get("prediction"), "NORMAL"),
                        _safe_float(row.get("confidence"), 0.0),
                        _safe_str(row.get("severity"), "none"),
                        _safe_str(row.get("source_ip"), "unknown"),
                        _safe_str(row.get("flow_id"), ""),
                        _safe_str(row.get("mode"), "benchmark"),
                    ))
                    migrated += 1
                except Exception as e:
                    skipped += 1
                    if len(errors) < 5:  # Only log first 5 errors
                        errors.append(f"Row {i}: {str(e)}")

        conn.commit()
        return {
            "success":  True,
            "migrated": migrated,
            "skipped":  skipped,
            "errors":   errors,
            "message":  f"✅ Migrated {migrated} rows to detections.db"
        }
    except Exception as e:
        return {"success": False, "message": str(e)}
    finally:
        conn.close()


def insert_detection(result: dict, source_ip: str = "unknown",
                     flow_id: str = "", test_mode: bool = False, tenant_id: str = "default") -> bool:
    """Insert a single detection into SQLite."""
    conn = _get_db()
    try:
        conn.execute("""
            INSERT INTO detections
                (timestamp, prediction, confidence, severity, source_ip, flow_id, mode, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("timestamp", datetime.now(timezone.utc).isoformat()),
            result.get("prediction", "NORMAL"),
            _safe_float(result.get("confidence"), 0.0),
            result.get("severity", "none"),
            source_ip,
            flow_id,
            "test" if test_mode else "live",
            tenant_id or "default",
        ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[detections_db] Insert error: {e}")
        return False
    finally:
        conn.close()


def load_detections(limit: int = 200, mode: str = "live", tenant_id: str = "default") -> list[dict]:
    """Load recent detections from SQLite with tenant isolation."""
    conn = _get_db()
    try:
        query_clauses = []
        params = []
        if mode != "all":
            query_clauses.append("mode = ?")
            params.append(mode)
        if tenant_id and tenant_id != "*":
            query_clauses.append("tenant_id = ?")
            params.append(tenant_id)

        where_sql = f"WHERE {' AND '.join(query_clauses)}" if query_clauses else ""
        query = f"SELECT * FROM detections {where_sql} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_stats(tenant_id: str = "default") -> dict:
    """Quick stats from SQLite filtered by tenant."""
    conn = _get_db()
    try:
        if tenant_id and tenant_id != "*":
            total = conn.execute("SELECT COUNT(*) FROM detections WHERE mode='live' AND tenant_id=?", (tenant_id,)).fetchone()[0]
            attacks = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE mode='live' AND severity != 'none' AND tenant_id=?", (tenant_id,)
            ).fetchone()[0]
            by_class = conn.execute("""
                SELECT prediction, COUNT(*) as cnt FROM detections
                WHERE mode='live' AND tenant_id=? GROUP BY prediction
            """, (tenant_id,)).fetchall()
        else:
            total = conn.execute("SELECT COUNT(*) FROM detections WHERE mode='live'").fetchone()[0]
            attacks = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE mode='live' AND severity != 'none'"
            ).fetchone()[0]
            by_class = conn.execute("""
                SELECT prediction, COUNT(*) as cnt FROM detections
                WHERE mode='live' GROUP BY prediction
            """).fetchall()

        return {
            "total":       total,
            "attacks":     attacks,
            "attack_rate": round(attacks / total * 100, 2) if total else 0.0,
            "by_class":    {r["prediction"]: r["cnt"] for r in by_class},
        }
    finally:
        conn.close()