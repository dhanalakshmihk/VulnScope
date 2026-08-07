"""
VulnScope CVE Lookup
---------------------
Queries the NVD (National Vulnerability Database) REST API v2.0 to find
known CVEs matching a detected service/version, with local SQLite caching
to avoid hitting NVD's rate limit (5 requests / 30s without an API key).

NOTE: services.nvd.nist.gov must be reachable from wherever this runs.
It will work once deployed (e.g. on Render) since NVD is a public API —
no key required for light use, though one can be added later via the
NVD_API_KEY env var to raise the rate limit.
"""

import json
import re
import sqlite3
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DB = Path(__file__).parent / "cve_cache.db"

# Without an API key NVD asks for 5 req/30s. Stay comfortably under that.
MIN_REQUEST_INTERVAL = 6.5
_last_request_time = 0.0


@dataclass
class CVEFinding:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: Optional[str]
    published: Optional[str]


def _init_cache():
    conn = sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            query_key TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _cache_get(query_key: str, max_age_seconds: int = 86400) -> Optional[dict]:
    conn = sqlite3.connect(CACHE_DB)
    row = conn.execute(
        "SELECT response_json, fetched_at FROM cve_cache WHERE query_key = ?",
        (query_key,),
    ).fetchone()
    conn.close()
    if row and (time.time() - row[1]) < max_age_seconds:
        return json.loads(row[0])
    return None


def _cache_set(query_key: str, data: dict):
    conn = sqlite3.connect(CACHE_DB)
    conn.execute(
        "INSERT OR REPLACE INTO cve_cache (query_key, response_json, fetched_at) VALUES (?, ?, ?)",
        (query_key, json.dumps(data), time.time()),
    )
    conn.commit()
    conn.close()


def _throttle():
    """Respect NVD's rate limit by spacing out requests."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < MIN_REQUEST_INTERVAL:
        time.sleep(MIN_REQUEST_INTERVAL - elapsed)
    _last_request_time = time.time()


def extract_version(banner: Optional[str]) -> Optional[str]:
    """
    Pull a version-looking token (e.g. 2.4.41, 8.0.30) out of a banner string.
    Skips the leading "HTTP/1.1" style protocol version, which isn't a
    software version and would otherwise produce false matches.
    """
    if not banner:
        return None
    # Drop a leading HTTP protocol marker like "HTTP/1.1 200 OK" before searching
    cleaned = re.sub(r"^HTTP/\d+\.\d+\s*", "", banner)
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", cleaned)
    return match.group(1) if match else None


def _parse_cvss(metrics: dict) -> tuple[Optional[float], Optional[str]]:
    """CVSS v3.1 preferred, fall back to v3.0, then v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss = entries[0]["cvssData"]
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, severity
    return None, None


def _parse_nvd_response(data: dict, limit: int = 5) -> list[CVEFinding]:
    findings = []
    for item in data.get("vulnerabilities", [])[:limit]:
        cve = item["cve"]
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        score, severity = _parse_cvss(cve.get("metrics", {}))
        findings.append(CVEFinding(
            cve_id=cve["id"],
            description=desc_text[:300],
            cvss_score=score,
            severity=severity,
            published=cve.get("published"),
        ))
    # Highest severity first
    findings.sort(key=lambda f: f.cvss_score or 0, reverse=True)
    return findings


def lookup_cves(service: str, version: Optional[str] = None, limit: int = 5) -> list[CVEFinding]:
    """
    Look up CVEs for a given service (+ optional version) via NVD keyword search.
    Uses a local SQLite cache to avoid re-querying NVD and to survive rate limits.
    """
    _init_cache()
    keyword = f"{service} {version}".strip() if version else service
    query_key = keyword.lower()

    cached = _cache_get(query_key)
    if cached is not None:
        return _parse_nvd_response(cached, limit)

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max(limit, 5),
    }
    url = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"

    _throttle()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScope/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise RuntimeError(
                "NVD rejected the request (403) — this host's network can't "
                "reach services.nvd.nist.gov, or you're rate-limited."
            ) from e
        raise
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach NVD API: {e}") from e

    _cache_set(query_key, data)
    return _parse_nvd_response(data, limit)


if __name__ == "__main__":
    import sys
    service = sys.argv[1] if len(sys.argv) > 1 else "openssh"
    version = sys.argv[2] if len(sys.argv) > 2 else None
    results = lookup_cves(service, version)
    for f in results:
        print(f"{f.cve_id}  [{f.severity or '?'} {f.cvss_score or '?'}]  {f.description[:80]}...")
