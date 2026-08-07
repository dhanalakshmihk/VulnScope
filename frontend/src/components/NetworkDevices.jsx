import { useState, useEffect } from "react";
import { getNetworkDevices } from "../api";

export default function NetworkDevices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const data = await getNetworkDevices();
      setDevices(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title mono">network devices</div>
        <button className="refresh-btn" onClick={refresh} disabled={loading}>
          {loading ? "scanning…" : "refresh"}
        </button>
      </div>

      {error && <div className="error-text">{error}</div>}

      {!error && devices.length === 0 && !loading && (
        <div className="empty-state small">no devices found</div>
      )}

      {devices.length > 0 && (
        <table className="simple-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>MAC Address</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.ip}>
                <td className="mono">{d.ip}</td>
                <td className="mono">{d.mac || "—"}</td>
                <td>{d.is_self && <span className="tag-self">this device</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}