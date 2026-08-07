const SEV_COLOR = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  NONE: "var(--sev-none)",
};

export default function HistoryList({ history, onSelect, activeId }) {
  return (
    <div className="history-panel">
      <div className="history-title mono">recent scans</div>
      {history.length === 0 && <div className="empty-state small">no scans yet</div>}
      <ul className="history-list">
        {history.map((h) => (
          <li
            key={h.id}
            className={`history-item ${h.id === activeId ? "active" : ""}`}
            onClick={() => onSelect(h.id)}
          >
            <span
              className="history-dot"
              style={{ background: SEV_COLOR[h.overall_risk] || "var(--sev-none)" }}
            />
            <span className="history-target mono">{h.target}</span>
            <span className={`history-status ${h.status}`}>{h.status}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
