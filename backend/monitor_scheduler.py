"""
VulnScope Monitor Scheduler
------------------------------
Runs continuous monitoring: for every active monitor job, periodically
re-scans the target and compares the new result against the last
completed scan for that same target. Raises alerts for:
  - a port that is newly open (wasn't open last time)
  - a CVE that appears on a port that wasn't there last time

Runs as a single background daemon thread started at FastAPI startup.
Deliberately simple (a sleep loop, not Celery/APScheduler) so the whole
mechanism is easy to explain line-by-line in an interview.
"""

import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

import db
from pipeline import run_full_scan

CHECK_INTERVAL_SECONDS = 15  # how often the loop wakes up to check for due jobs


def diff_findings(old_findings: list[dict], new_findings: list[dict]) -> list[dict]:
    """
    Compares two scans' findings for the same target.
    Returns a list of alert dicts: {alert_type, severity, message}
    """
    alerts = []
    old_by_port = {f["port"]: f for f in old_findings}
    new_by_port = {f["port"]: f for f in new_findings}

    # New ports that weren't open before
    for port, finding in new_by_port.items():
        if port not in old_by_port:
            alerts.append({
                "alert_type": "new_port",
                "severity": "HIGH",
                "message": f"New open port detected: {port} ({finding.get('service') or 'unknown'})",
            })

    # New CVEs on ports that already existed
    for port, finding in new_by_port.items():
        if port in old_by_port:
            old_cve_ids = {c["cve_id"] for c in old_by_port[port].get("cves", [])}
            new_cves = [c for c in finding.get("cves", []) if c["cve_id"] not in old_cve_ids]
            for c in new_cves:
                alerts.append({
                    "alert_type": "new_cve",
                    "severity": c.get("severity") or "MEDIUM",
                    "message": f"New CVE on port {port}: {c['cve_id']} ({c.get('severity')} {c.get('cvss_score')})",
                })

    return alerts


def _run_job_once(job: dict):
    """Executes a single monitoring cycle for one job: scan, diff, alert, store."""
    target = job["target"]
    job_id = job["id"]

    previous = db.get_last_completed_scan_for_target(target)

    scan_id = db.create_scan(target, started_at=time.time())
    try:
        report = run_full_scan(target)
        findings = [
            {
                "port": a.port,
                "service": a.service,
                "banner": a.banner,
                "version": a.version,
                "risk_score": a.risk_score,
                "cves": [
                    {"cve_id": c.cve_id, "description": c.description,
                     "cvss_score": c.cvss_score, "severity": c.severity}
                    for c in a.cves
                ],
            }
            for a in report.assessments
        ]
        db.complete_scan(
            scan_id=scan_id,
            resolved_ip=report.resolved_ip,
            overall_risk=report.overall_risk,
            finished_at=report.finished_at,
            findings=findings,
        )

        if previous is not None:
            new_alerts = diff_findings(previous["findings"], findings)
            for a in new_alerts:
                db.create_alert(job_id, target, a["alert_type"], a["severity"], a["message"])

    except Exception as e:
        db.fail_scan(scan_id, str(e), time.time())

    db.update_job_last_run(job_id, time.time())


def _scheduler_loop():
    """Background loop: wakes up periodically, runs any job that's due."""
    while True:
        try:
            jobs = db.get_active_monitor_jobs()
            now = time.time()
            for job in jobs:
                last_run = job["last_run_at"] or 0
                if now - last_run >= job["interval_seconds"]:
                    _run_job_once(job)
        except Exception as e:
            print(f"[monitor_scheduler] loop error: {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


def start_scheduler():
    """Call once at app startup — spins up the background thread."""
    thread = threading.Thread(target=_scheduler_loop, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    # Quick manual test: create a job for scanme.nmap.org with a short interval
    db.init_db()
    job_id = db.create_monitor_job("scanme.nmap.org", interval_seconds=20)
    print(f"Created monitor job {job_id}. Starting scheduler loop (Ctrl+C to stop)...")
    start_scheduler()
    while True:
        time.sleep(5)
        print("alerts so far:", db.list_alerts())