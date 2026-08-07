"""
VulnScope Database Layer
--------------------------
SQLite storage for scans, their discovered open ports, matched CVEs,
continuous monitor jobs, and alerts raised by the monitor.
Kept as plain sqlite3 (no ORM) to keep the project easy to explain in
an interview — every query is visible and simple.
"""

import sqlite3
import json
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "vulnscope.db"


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                resolved_ip TEXT,
                status TEXT NOT NULL DEFAULT 'running',  -- running | done | failed
                overall_risk TEXT,
                started_at REAL NOT NULL,
                finished_at REAL,
                error TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                port INTEGER NOT NULL,
                service TEXT,
                banner TEXT,
                version TEXT,
                risk_score REAL DEFAULT 0,
                cves_json TEXT  -- serialized list of CVE dicts, simplest storage for a 1-week project
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitor_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL DEFAULT 300,
                active INTEGER NOT NULL DEFAULT 1,
                last_run_at REAL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL REFERENCES monitor_jobs(id),
                target TEXT NOT NULL,
                alert_type TEXT NOT NULL,   -- 'new_port' | 'new_cve'
                severity TEXT,
                message TEXT NOT NULL,
                created_at REAL NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            )
        """)


def create_scan(target: str, started_at: float) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, status, started_at) VALUES (?, 'running', ?)",
            (target, started_at),
        )
        return cur.lastrowid


def complete_scan(scan_id: int, resolved_ip: str, overall_risk: str, finished_at: float, findings: list):
    with get_conn() as conn:
        conn.execute(
            """UPDATE scans SET status='done', resolved_ip=?, overall_risk=?, finished_at=?
               WHERE id=?""",
            (resolved_ip, overall_risk, finished_at, scan_id),
        )
        for f in findings:
            conn.execute(
                """INSERT INTO findings (scan_id, port, service, banner, version, risk_score, cves_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, f["port"], f["service"], f["banner"], f["version"],
                 f["risk_score"], json.dumps(f["cves"])),
            )


def fail_scan(scan_id: int, error: str, finished_at: float):
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET status='failed', error=?, finished_at=? WHERE id=?",
            (error, finished_at, scan_id),
        )


def get_scan(scan_id: int) -> dict | None:
    with get_conn() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return None
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY port", (scan_id,)
        ).fetchall()
        result = dict(scan)
        result["findings"] = []
        for f in findings:
            fd = dict(f)
            fd["cves"] = json.loads(fd.pop("cves_json") or "[]")
            result["findings"].append(fd)
        return result


def list_scans(limit: int = 20) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, target, resolved_ip, status, overall_risk, started_at, finished_at "
            "FROM scans ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_last_completed_scan_for_target(target: str, exclude_scan_id: int = None) -> dict | None:
    """Used for diffing — finds the most recent 'done' scan for a target."""
    with get_conn() as conn:
        query = "SELECT * FROM scans WHERE target=? AND status='done'"
        params = [target]
        if exclude_scan_id:
            query += " AND id != ?"
            params.append(exclude_scan_id)
        query += " ORDER BY id DESC LIMIT 1"
        scan = conn.execute(query, params).fetchone()
        if not scan:
            return None
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY port", (scan["id"],)
        ).fetchall()
        result = dict(scan)
        result["findings"] = []
        for f in findings:
            fd = dict(f)
            fd["cves"] = json.loads(fd.pop("cves_json") or "[]")
            result["findings"].append(fd)
        return result


# ---------------- Monitor jobs (continuous re-scan + alerting) ----------------

def create_monitor_job(target: str, interval_seconds: int) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO monitor_jobs (target, interval_seconds, active, created_at) VALUES (?, ?, 1, ?)",
            (target, interval_seconds, time.time()),
        )
        return cur.lastrowid


def stop_monitor_job(job_id: int):
    with get_conn() as conn:
        conn.execute("UPDATE monitor_jobs SET active=0 WHERE id=?", (job_id,))


def list_monitor_jobs() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM monitor_jobs ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def get_active_monitor_jobs() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM monitor_jobs WHERE active=1").fetchall()
        return [dict(r) for r in rows]


def update_job_last_run(job_id: int, timestamp: float):
    with get_conn() as conn:
        conn.execute("UPDATE monitor_jobs SET last_run_at=? WHERE id=?", (timestamp, job_id))


def create_alert(job_id: int, target: str, alert_type: str, severity: str, message: str):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts (job_id, target, alert_type, severity, message, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (job_id, target, alert_type, severity, message, time.time()),
        )


def list_alerts(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    
def get_scan_history_for_target(target: str, limit: int = 30) -> list[dict]:
    """Chronological scan history for one target — used for the risk trend chart."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, overall_risk, started_at, finished_at, status
               FROM scans WHERE target=? AND status='done'
               ORDER BY id ASC LIMIT ?""",
            (target, limit),
        ).fetchall()
        return [dict(r) for r in rows]