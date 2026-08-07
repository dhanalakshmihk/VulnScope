import { useState } from "react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { getRiskTrend } from "../api";

const RISK_LEVELS = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const RISK_LABELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export default function RiskTrendChart() {
  const [target, setTarget] = useState("scanme.nmap.org");
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  async function loadTrend(e) {
    e.preventDefault();
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const history = await getRiskTrend(target.trim());
      const points = history.map((h) => ({
        scanId: h.id,
        time: new Date(h.finished_at * 1000).toLocaleTimeString(),
        riskValue: RISK_LEVELS[h.overall_risk] ?? 0,
        riskLabel: h.overall_risk,
      }));
      setData(points);
    } catch (e) {
      setError(e.message);
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title mono">risk trend</div>
      </div>

      <form onSubmit={loadTrend} className="inline-form">
        <input
          className="inline-input"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="target to view trend for"
          spellCheck={false}
        />
        <button className="refresh-btn" type="submit" disabled={loading}>
          {loading ? "loading…" : "load trend"}
        </button>
      </form>

      {error && <div className="error-text">{error}</div>}

      {data && data.length === 0 && (
        <div className="empty-state small">
          No scan history yet for this target — run a scan or start monitoring it first.
        </div>
      )}

      {data && data.length > 0 && (
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={data} margin={{ left: -10, right: 20, top: 10, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#21262D" />
            <XAxis dataKey="time" stroke="#545D68" fontSize={11} />
            <YAxis
              domain={[0, 4]}
              ticks={[0, 1, 2, 3, 4]}
              tickFormatter={(v) => RISK_LABELS[v]}
              stroke="#8B949E"
              fontSize={11}
              width={70}
            />
            <Tooltip
              contentStyle={{
                background: "#1C2129",
                border: "1px solid #2D333B",
                borderRadius: 6,
                fontFamily: "IBM Plex Mono, monospace",
                fontSize: 12,
              }}
              formatter={(_, __, props) => [props.payload.riskLabel, "risk"]}
            />
            <Line
              type="stepAfter"
              dataKey="riskValue"
              stroke="#58A6FF"
              strokeWidth={2}
              dot={{ r: 3, fill: "#58A6FF" }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}