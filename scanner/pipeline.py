"""
VulnScope Pipeline
--------------------
Combines core_scanner (port scan + banner grab) with cve_lookup (NVD match)
into a single end-to-end scan-and-assess function.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

from core_scanner import scan_target, PortResult
from cve_lookup import lookup_cves, extract_version, CVEFinding


@dataclass
class PortAssessment:
    port: int
    service: str
    banner: Optional[str]
    version: Optional[str]
    cves: list = field(default_factory=list)
    risk_score: float = 0.0  # highest CVSS among matched CVEs, 0 if none found


@dataclass
class FullScanReport:
    target: str
    resolved_ip: str
    started_at: float
    finished_at: float
    assessments: list = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return round(self.finished_at - self.started_at, 2)

    @property
    def overall_risk(self) -> str:
        if not self.assessments:
            return "NONE"
        top = max((a.risk_score for a in self.assessments), default=0)
        if top >= 9.0:
            return "CRITICAL"
        if top >= 7.0:
            return "HIGH"
        if top >= 4.0:
            return "MEDIUM"
        if top > 0:
            return "LOW"
        return "NONE"


def assess_port(port_result: PortResult, cve_limit: int = 3) -> PortAssessment:
    """Run CVE lookup for a single open port's detected service."""
    version = extract_version(port_result.banner)
    cves: list[CVEFinding] = []
    try:
        cves = lookup_cves(port_result.service_guess, version, limit=cve_limit)
    except RuntimeError:
        # NVD unreachable or rate-limited — degrade gracefully, don't fail the whole scan
        cves = []

    top_score = max((c.cvss_score or 0 for c in cves), default=0.0)
    return PortAssessment(
        port=port_result.port,
        service=port_result.service_guess,
        banner=port_result.banner,
        version=version,
        cves=cves,
        risk_score=top_score,
    )


def run_full_scan(target: str, ports: list = None) -> FullScanReport:
    """
    End-to-end: port scan the target, then look up CVEs for every open
    service found. This is the single function the API layer calls.
    """
    started_at = time.time()
    scan = scan_target(target, ports=ports)

    assessments = [assess_port(p) for p in scan.open_ports]

    return FullScanReport(
        target=scan.target,
        resolved_ip=scan.resolved_ip,
        started_at=started_at,
        finished_at=time.time(),
        assessments=assessments,
    )


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"Running full scan + CVE assessment on {target}...\n")
    report = run_full_scan(target)
    print(f"Target: {report.target} ({report.resolved_ip})")
    print(f"Duration: {report.duration_seconds}s | Overall risk: {report.overall_risk}\n")
    for a in report.assessments:
        print(f"Port {a.port} [{a.service}] version={a.version or '?'} risk={a.risk_score}")
        for c in a.cves:
            print(f"   - {c.cve_id} ({c.severity} {c.cvss_score}): {c.description[:70]}...")
