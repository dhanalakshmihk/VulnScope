"""
VulnScope Backend API
------------------------
FastAPI app exposing:
  POST /scan          - kick off a new scan (runs in background)
  GET  /results/{id}  - poll scan status / get results
  GET  /history        - list recent scans
  GET  /report/{id}    - render an HTML report for a completed scan
  GET  /network/devices    - discover devices on local network
  GET  /system/connections - live connections on this machine
  GET  /trends/{target}    - historical risk trend for a target
  POST /monitor/start      - start continuous monitoring of a target
  POST /monitor/stop/{id}  - stop a monitor job
  GET  /monitor/jobs       - list monitor jobs
  GET  /alerts             - list raised alerts

Run with: uvicorn main:app --reload --port 8000
"""

import sys
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

# Make the scanner package importable
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

import db
from pipeline import run_full_scan
import connections_monitor
import network_discovery
import monitor_scheduler

app = FastAPI(title="VulnScope API", version="0.1.0")

# During development the React dev server runs on a different port,
# so CORS needs to be open for local testing.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    db.init_db()
    monitor_scheduler.start_scheduler()


class ScanRequest(BaseModel):
    target: str = Field(..., description="Hostname or IP to scan. Only scan hosts you're authorized to test.")


class ScanResponse(BaseModel):
    scan_id: int
    status: str


def _execute_scan(scan_id: int, target: str):
    """Runs in the background so the API can respond immediately with a scan_id."""
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
                    {
                        "cve_id": c.cve_id,
                        "description": c.description,
                        "cvss_score": c.cvss_score,
                        "severity": c.severity,
                    }
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
    except Exception as e:
        db.fail_scan(scan_id, str(e), time.time())


@app.post("/scan", response_model=ScanResponse)
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = db.create_scan(req.target, started_at=time.time())
    background_tasks.add_task(_execute_scan, scan_id, req.target)
    return ScanResponse(scan_id=scan_id, status="running")


@app.get("/results/{scan_id}")
def get_results(scan_id: int):
    result = db.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/history")
def get_history(limit: int = 20):
    return db.list_scans(limit)


@app.get("/report/{scan_id}", response_class=HTMLResponse)
def get_html_report(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "done":
        raise HTTPException(status_code=409, detail=f"Scan status is '{scan['status']}', not ready yet")

    risk_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#65a30d", "NONE": "#16a34a"}
    color = risk_colors.get(scan["overall_risk"], "#6b7280")

    rows = ""
    for f in scan["findings"]:
        cve_html = "".join(
            f"<li><b>{c['cve_id']}</b> ({c.get('severity') or '?'} {c.get('cvss_score') or '?'}) — {c['description'][:150]}</li>"
            for c in f["cves"]
        ) or "<li>No known CVEs matched</li>"
        rows += f"""
        <tr>
            <td>{f['port']}</td>
            <td>{f['service'] or '-'}</td>
            <td>{f['version'] or '-'}</td>
            <td>{f['risk_score']}</td>
            <td><ul>{cve_html}</ul></td>
        </tr>"""

    html = f"""
    <html>
    <head><title>VulnScope Report — {scan['target']}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1f2937; }}
        h1 {{ margin-bottom: 4px; }}
        .meta {{ color: #6b7280; margin-bottom: 20px; }}
        .risk-badge {{ display: inline-block; padding: 4px 12px; border-radius: 6px; color: white; background: {color}; font-weight: 600; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
        th {{ background: #f9fafb; }}
        ul {{ margin: 0; padding-left: 18px; }}
    </style>
    </head>
    <body>
        <h1>VulnScope Scan Report</h1>
        <div class="meta">
            Target: <b>{scan['target']}</b> ({scan['resolved_ip'] or 'unresolved'})<br>
            Scanned: {time.strftime('%Y-%m-%d %H:%M', time.localtime(scan['started_at']))}<br>
            Overall risk: <span class="risk-badge">{scan['overall_risk']}</span>
        </div>
        <table>
            <tr><th>Port</th><th>Service</th><th>Version</th><th>Risk Score</th><th>Matched CVEs</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/")
def root():
    return {"status": "VulnScope API running", "docs": "/docs"}


# ---------------- Network monitoring dashboard endpoints ----------------

@app.get("/network/devices")
def get_network_devices():
    """Discovers devices on the local network via ping sweep + ARP table."""
    devices = network_discovery.discover_devices()
    return [
        {"ip": d.ip, "mac": d.mac, "is_self": d.is_self} for d in devices
    ]


@app.get("/system/connections")
def get_system_connections():
    """Live active network connections on this machine."""
    connections = connections_monitor.get_live_connections()
    summary = connections_monitor.summarize_connections(connections)
    return {
        "summary": summary,
        "connections": [
            {
                "pid": c.pid,
                "process_name": c.process_name,
                "local_addr": c.local_addr,
                "local_port": c.local_port,
                "remote_addr": c.remote_addr,
                "remote_port": c.remote_port,
                "status": c.status,
                "is_remote": c.is_remote,
            }
            for c in connections[:50]  # cap payload size
        ],
    }


@app.get("/trends/{target}")
def get_risk_trend(target: str):
    """Historical risk-score trend for repeated scans of the same target."""
    history = db.get_scan_history_for_target(target)
    return history


# ---------------- Continuous monitoring endpoints ----------------

class MonitorRequest(BaseModel):
    target: str
    interval_seconds: int = Field(default=300, ge=30, description="Minimum 30s between re-scans")


@app.post("/monitor/start")
def start_monitor(req: MonitorRequest):
    job_id = db.create_monitor_job(req.target, req.interval_seconds)
    return {"job_id": job_id, "target": req.target, "interval_seconds": req.interval_seconds}


@app.post("/monitor/stop/{job_id}")
def stop_monitor(job_id: int):
    db.stop_monitor_job(job_id)
    return {"job_id": job_id, "status": "stopped"}


@app.get("/monitor/jobs")
def get_monitor_jobs():
    return db.list_monitor_jobs()


@app.get("/alerts")
def get_alerts(limit: int = 50):
    return db.list_alerts(limit)