import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_HEX = {
  CRITICAL: "#F85149",
  HIGH: "#DB6D28",
  MEDIUM: "#D4A72C",
  LOW: "#56D364",
};

export default function SeverityChart({ result }) {
  if (!result || result.findings.length === 0) return null;

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  result.findings.forEach((f) =>
    f.cves.forEach((c) => {
      if (counts[c.severity] !== undefined) counts[c.severity] += 1;
    })
  );

  const totalCves = Object.values(counts).reduce((a, b) => a + b, 0);
  if (totalCves === 0) return null;

  const data = SEV_ORDER.map((sev) => ({ severity: sev, count: counts[sev] }));

  return (
    <div className="chart-panel">
      <div className="chart-title mono">cve severity distribution</div>
      <ResponsiveContainer width="100%" height={160}>
        <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20, top: 4, bottom: 4 }}>
          <XAxis type="number" allowDecimals={false} stroke="#545D68" fontSize={12} />
          <YAxis
            type="category"
            dataKey="severity"
            stroke="#8B949E"
            fontSize={12}
            width={70}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              background: "#1C2129",
              border: "1px solid #2D333B",
              borderRadius: 6,
              fontFamily: "IBM Plex Mono, monospace",
              fontSize: 12,
            }}
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={18}>
            {data.map((d) => (
              <Cell key={d.severity} fill={SEV_HEX[d.severity]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
