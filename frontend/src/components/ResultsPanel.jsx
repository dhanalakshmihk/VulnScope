const SEV_COLOR = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

function SeverityBadge({ severity, score }) {
  const color = SEV_COLOR[severity] || "var(--sev-none)";
  return (
    <span className="sev-badge" style={{ "--sev-color": color }}>
      {severity || "N/A"} {score != null ? score.toFixed(1) : ""}
    </span>
  );
}

export default function ResultsPanel({ result }) {
  if (!result) return null;
  const { target, resolved_ip, overall_risk, findings } = result;
  const riskColor = SEV_COLOR[overall_risk] || "var(--sev-none)";

  return (
    <div className="results-panel">
      <div className="results-header">
        <div>
          <div className="results-target mono">{target}</div>
          <div className="results-ip mono">{resolved_ip}</div>
        </div>
        <div className="overall-risk" style={{ "--sev-color": riskColor }}>
          <span className="overall-risk-label">overall risk</span>
          <span className="overall-risk-value">{overall_risk}</span>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="empty-state">No open ports found among the scanned list.</div>
      ) : (
        <table className="results-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
              <th>Version</th>
              <th>Findings</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.port}>
                <td className="mono">{f.port}</td>
                <td>{f.service || "—"}</td>
                <td className="mono">{f.version || "—"}</td>
                <td>
                  {f.cves.length === 0 ? (
                    <span className="no-cve">no known CVEs matched</span>
                  ) : (
                    <ul className="cve-list">
                      {f.cves.map((c) => (
                        <li key={c.cve_id}>
                          <span className="mono cve-id">{c.cve_id}</span>
                          <SeverityBadge severity={c.severity} score={c.cvss_score} />
                          <div className="cve-desc">{c.description}</div>
                        </li>
                      ))}
                    </ul>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
