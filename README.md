# VulnScope

A full-stack network vulnerability scanner that discovers open ports, matches detected services against real CVEs from the National Vulnerability Database (NVD), and continuously monitors targets for new security risks — with a live dashboard for network visibility.

> ⚠️ **Only scan hosts and networks you own or are explicitly authorized to test.** This tool is built for learning, personal-network auditing, and authorized security assessments.

---

## Features

**Vulnerability Scanner**
- Multi-threaded TCP port scanner with service banner grabbing
- Real-time CVE matching against the NVD database, with CVSS severity scoring
- Auto-generated HTML vulnerability reports
- Live scan console that streams results as they're found

**Network Monitoring Dashboard**
- Local network device discovery (ARP-based, no admin privileges required)
- Live view of active network connections on your own machine — spot unexpected processes phoning home
- Historical risk-trend charting across repeated scans

**Continuous Monitoring**
- Background scheduler that re-scans a target on a set interval
- Automatically diffs each scan against the last one
- Raises alerts when a new port opens or a new CVE appears — without needing to manually re-scan

---

## Tech Stack

| Layer | Technology |
|---|---|
| Scan engine | Python (threading, sockets, `psutil`) |
| Backend API | FastAPI + SQLite |
| Frontend | React (Vite) + Recharts |
| Vulnerability data | NIST NVD REST API v2.0 |

---

## Architecture
scanner/ Core scan engine (pure Python, no web framework)
├── core_scanner.py Multi-threaded port scanner + banner grabbing
├── cve_lookup.py NVD API integration with SQLite caching
├── network_discovery.py ARP-based local network device discovery
├── connections_monitor.py Live system connection monitoring (via psutil)
└── pipeline.py Wires scanning + CVE matching together

backend/ FastAPI REST API
├── main.py API endpoints
├── db.py SQLite schema + queries
└── monitor_scheduler.py Background continuous-monitoring engine

frontend/ React dashboard (Vite)
└── src/
├── App.jsx Tabbed layout: Scanner / Network Monitor
└── components/ Scan console, results table, charts, alerts panel

## How It Works

1. **Scanning**: A thread pool attempts TCP connections across common ports, grabbing service banners where possible (e.g. HTTP headers, SSH version strings).
2. **CVE Matching**: Detected service names/versions are queried against the NVD API, with results cached locally in SQLite to respect NVD's rate limits.
3. **Continuous Monitoring**: A background thread periodically re-scans watched targets and diffs the results against the previous scan, raising alerts only when something genuinely changes.

---

## Running Locally

**Backend**
```bash
cd backend
pip install fastapi uvicorn psutil
uvicorn main:app --reload --port 8000 --host 0.0.0.0
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173`.

---

## Known Limitations

- **Version fingerprinting is basic.** Banner-based version extraction can misfire (e.g., picking up a protocol version instead of the actual software version). A production tool would use a much larger signature database, similar to Nmap's `-sV`.
- **CVE matches without a confirmed version are broad, not precise.** When no version is detected, matching falls back to service-name-only search, which can surface decades-old CVEs that may not actually apply. This is flagged in the UI via risk scoring, not silently trusted.
- **ARP-based device discovery only covers the local subnet** and depends on the OS's ARP cache; it won't discover devices across VLANs or behind certain router configurations.

---

## Legal & Ethical Use

This project is for educational purposes and authorized security testing only. Only scan systems you own or have explicit written permission to test. Unauthorized scanning of networks/systems you don't control may violate computer misuse laws in your jurisdiction.