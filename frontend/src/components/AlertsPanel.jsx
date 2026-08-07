import { useState, useEffect, useCallback } from "react";
import { startMonitor, stopMonitor, getMonitorJobs, getAlerts } from "../api";

const SEV_COLOR = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

const POLL_MS = 8000;

export default function AlertsPanel() {
  const [target, setTarget] = useState("scanme.nmap.org");
  const [intervalMinutes, setIntervalMinutes] = useState(1);
  const [jobs, setJobs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);
  const [starting, setStarting] = useState(false);

  const refresh = useCallback(() => {
    getMonitorJobs().then(setJobs).catch(() => {});
    getAlerts().then(setAlerts).catch(() => {});
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  async function handleStart(e) {
    e.preventDefault();
    if (!target.trim()) return;
    setStarting(true);
    setError(null);
    try {
      // Backend enforces a 30s minimum interval — convert minutes to seconds.
      await startMonitor(target.trim(), Math.max(30, intervalMinutes * 60));
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setStarting(false);
    }
  }

  async function handleStop(jobId) {
    try {
      await stopMonitor(jobId);
      refresh();
    } catch (e) {
      setError(e.message);
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title mono">continuous monitoring</div>
      </div>

      <form onSubmit={handleStart} className="monitor-form">
        <input
          className="inline-input"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="target to watch"
          spellCheck={false}
        />
        <input
          className="interval-input"
          type="number"
          min={1}
          value={intervalMinutes}
          onChange={(e) => setIntervalMinutes(Number(e.target.value))}
        />
        <span className="interval-unit">min</span>
        <button className="refresh-btn" type="submit" disabled={starting}>
          {starting ? "starting…" : "start watching"}
        </button>
      </form>

      {error && <div className="error-text">{error}</div>}

      {jobs.length > 0 && (
        <div className="jobs-list">
          {jobs.map((j) => (
            <div key={j.id} className={`job-row ${j.active ? "active" : "inactive"}`}>
              <span className={`job-dot ${j.active ? "on" : "off"}`} />
              <span className="mono job-target">{j.target}</span>
              <span className="job-interval">every {Math.round(j.interval_seconds / 60) || 1}m</span>
              {j.active ? (
                <button className="stop-btn" onClick={() => handleStop(j.id)}>
                  stop
                </button>
              ) : (
                <span className="job-stopped">stopped</span>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="alerts-divider mono">alerts</div>

      {alerts.length === 0 ? (
        <div className="empty-state small">no alerts yet — good sign</div>
      ) : (
        <ul className="alerts-list">
          {alerts.map((a) => (
            <li key={a.id} className="alert-item">
              <span
                className="alert-severity"
                style={{ "--sev-color": SEV_COLOR[a.severity] || "var(--sev-none)" }}
              >
                {a.severity || "?"}
              </span>
              <div className="alert-body">
                <div className="alert-message">{a.message}</div>
                <div className="alert-meta mono">
                  {a.target} · {new Date(a.created_at * 1000).toLocaleString()}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}