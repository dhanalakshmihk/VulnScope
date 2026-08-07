import { useState, useEffect, useRef } from "react";
import { getSystemConnections } from "../api";

const REFRESH_MS = 5000;

export default function LiveConnections() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const intervalRef = useRef(null);

  async function refresh() {
    try {
      const result = await getSystemConnections();
      setData(result);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => {
    refresh();
    intervalRef.current = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(intervalRef.current);
  }, []);

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title mono">live connections</div>
        <span className="live-dot" />
      </div>

      {error && <div className="error-text">{error}</div>}

      {data && (
        <>
          <div className="summary-cards">
            <div className="summary-card">
              <div className="summary-value">{data.summary.established}</div>
              <div className="summary-label">established</div>
            </div>
            <div className="summary-card">
              <div className="summary-value">{data.summary.listening}</div>
              <div className="summary-label">listening</div>
            </div>
            <div className="summary-card">
              <div className="summary-value">{data.summary.unique_remote_hosts}</div>
              <div className="summary-label">remote hosts</div>
            </div>
          </div>

          <table className="simple-table">
            <thead>
              <tr>
                <th>Process</th>
                <th>Local</th>
                <th>Remote</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {data.connections.slice(0, 20).map((c, i) => (
                <tr key={i}>
                  <td>{c.process_name || "—"}</td>
                  <td className="mono">{c.local_addr}:{c.local_port}</td>
                  <td className="mono">
                    {c.remote_addr ? `${c.remote_addr}:${c.remote_port}` : "—"}
                  </td>
                  <td>
                    <span className={`status-pill ${c.status.toLowerCase()}`}>
                      {c.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}