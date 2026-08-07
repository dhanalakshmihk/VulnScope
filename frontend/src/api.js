const API_BASE = "http://localhost:8000";

export async function startScan(target) {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Scan request failed (${res.status})`);
  }
  return res.json();
}

export async function getResults(scanId) {
  const res = await fetch(`${API_BASE}/results/${scanId}`);
  if (!res.ok) throw new Error(`Could not fetch results (${res.status})`);
  return res.json();
}

export async function getHistory(limit = 20) {
  const res = await fetch(`${API_BASE}/history?limit=${limit}`);
  if (!res.ok) throw new Error(`Could not fetch history (${res.status})`);
  return res.json();
}

export function reportUrl(scanId) {
  return `${API_BASE}/report/${scanId}`;
}
export async function getNetworkDevices() {
  const res = await fetch(`${API_BASE}/network/devices`);
  if (!res.ok) throw new Error(`Could not fetch devices (${res.status})`);
  return res.json();
}

export async function getSystemConnections() {
  const res = await fetch(`${API_BASE}/system/connections`);
  if (!res.ok) throw new Error(`Could not fetch connections (${res.status})`);
  return res.json();
}

export async function getRiskTrend(target) {
  const res = await fetch(`${API_BASE}/trends/${encodeURIComponent(target)}`);
  if (!res.ok) throw new Error(`Could not fetch trend (${res.status})`);
  return res.json();
}

export async function startMonitor(target, intervalSeconds) {
  const res = await fetch(`${API_BASE}/monitor/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, interval_seconds: intervalSeconds }),
  });
  if (!res.ok) throw new Error(`Could not start monitor (${res.status})`);
  return res.json();
}

export async function stopMonitor(jobId) {
  const res = await fetch(`${API_BASE}/monitor/stop/${jobId}`, { method: "POST" });
  if (!res.ok) throw new Error(`Could not stop monitor (${res.status})`);
  return res.json();
}

export async function getMonitorJobs() {
  const res = await fetch(`${API_BASE}/monitor/jobs`);
  if (!res.ok) throw new Error(`Could not fetch jobs (${res.status})`);
  return res.json();
}

export async function getAlerts(limit = 50) {
  const res = await fetch(`${API_BASE}/alerts?limit=${limit}`);
  if (!res.ok) throw new Error(`Could not fetch alerts (${res.status})`);
  return res.json();
}