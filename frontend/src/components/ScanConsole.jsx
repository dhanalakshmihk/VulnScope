import { useState, useRef, useEffect } from "react";
import { startScan, getResults } from "../api";

const STAGE_LINES = [
  "resolving host…",
  "opening socket pool…",
  "probing 29 common ports…",
  "grabbing service banners…",
  "cross-referencing NVD for known CVEs…",
];

export default function ScanConsole({ onComplete }) {
  const [target, setTarget] = useState("scanme.nmap.org");
  const [lines, setLines] = useState([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const logRef = useRef(null);
  const pollRef = useRef(null);
  const stageRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [lines]);

  function pushLine(text) {
    setLines((prev) => [...prev, { text, t: Date.now() }]);
  }

  async function runScan(e) {
    e.preventDefault();
    if (!target.trim() || running) return;
    setError(null);
    setLines([]);
    setRunning(true);
    pushLine(`$ vulnscope scan ${target.trim()}`);

    let stageIdx = 0;
    stageRef.current = setInterval(() => {
      if (stageIdx < STAGE_LINES.length) {
        pushLine(STAGE_LINES[stageIdx]);
        stageIdx += 1;
      }
    }, 900);

    try {
      const { scan_id } = await startScan(target.trim());

      pollRef.current = setInterval(async () => {
        const result = await getResults(scan_id);
        if (result.status === "running") return;

        clearInterval(pollRef.current);
        clearInterval(stageRef.current);

        if (result.status === "failed") {
          pushLine(`error: ${result.error || "scan failed"}`);
          setError(result.error);
          setRunning(false);
          return;
        }

        pushLine(`resolved → ${result.resolved_ip}`);
        if (result.findings.length === 0) {
          pushLine("no open ports found among scanned list");
        } else {
          result.findings.forEach((f) => {
            pushLine(`open  :${f.port}  ${f.service || "unknown"}${f.version ? " v" + f.version : ""}`);
            if (f.cves.length > 0) {
              f.cves.forEach((c) =>
                pushLine(`  └─ ${c.cve_id}  [${c.severity || "?"} ${c.cvss_score ?? "?"}]`)
              );
            }
          });
        }
        pushLine(`scan complete — overall risk: ${result.overall_risk}`);
        setRunning(false);
        onComplete(result);
      }, 1200);
    } catch (err) {
      clearInterval(stageRef.current);
      pushLine(`error: ${err.message}`);
      setError(err.message);
      setRunning(false);
    }
  }

  useEffect(() => {
    return () => {
      clearInterval(pollRef.current);
      clearInterval(stageRef.current);
    };
  }, []);

  return (
    <div className="console-panel">
      <form onSubmit={runScan} className="console-form">
        <span className="prompt-glyph">❯</span>
        <input
          className="console-input"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="hostname or IP (only scan hosts you're authorized to test)"
          disabled={running}
          spellCheck={false}
        />
        <button className="run-btn" type="submit" disabled={running}>
          {running ? "scanning…" : "run scan"}
        </button>
      </form>

      <div className="console-log" ref={logRef}>
        {lines.length === 0 && (
          <div className="log-placeholder">output will stream here once you run a scan</div>
        )}
        {lines.map((l, i) => (
          <div key={i} className="log-line">
            {l.text}
          </div>
        ))}
        {running && <span className="cursor-blink">▍</span>}
      </div>
    </div>
  );
}
