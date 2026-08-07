import { useState, useEffect, useCallback } from "react";
import "./tokens.css";
import "./App.css";
import ScanConsole from "./components/ScanConsole";
import ResultsPanel from "./components/ResultsPanel";
import SeverityChart from "./components/SeverityChart";
import HistoryList from "./components/HistoryList";
import NetworkDevices from "./components/NetworkDevices";
import LiveConnections from "./components/LiveConnections";
import RiskTrendChart from "./components/RiskTrendChart";
import AlertsPanel from "./components/AlertsPanel";
import { getHistory, getResults, reportUrl } from "./api";

export default function App() {
  const [tab, setTab] = useState("scanner");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  const refreshHistory = useCallback(() => {
    getHistory().then(setHistory).catch(() => {});
  }, []);

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  function handleComplete(res) {
    setResult(res);
    refreshHistory();
  }

  async function handleSelectHistory(id) {
    try {
      const res = await getResults(id);
      if (res.status === "done") setResult(res);
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark">*</span>
          <span className="brand-name">VulnScope</span>
        </div>
        <div className="brand-sub mono">port scanner - CVE matcher - network monitor</div>
      </header>

      <div className="app-notice">
        Only scan hosts and networks you own or are explicitly authorized to test.
      </div>

      <nav className="tab-bar">
        <button
          className={tab === "scanner" ? "tab-btn active" : "tab-btn"}
          onClick={() => setTab("scanner")}
        >
          Scanner
        </button>
        <button
          className={tab === "monitor" ? "tab-btn active" : "tab-btn"}
          onClick={() => setTab("monitor")}
        >
          Network Monitor
        </button>
      </nav>

      {tab === "scanner" && (
        <main className="app-main">
          <div className="main-col">
            <ScanConsole onComplete={handleComplete} />

            {result && (
              <>
                <SeverityChart result={result} />
                <ResultsPanel result={result} />
                {result.status === "done" && (
                  <a className="report-link" href={reportUrl(result.id)} target="_blank" rel="noreferrer">
                    open full report
                  </a>
                )}
              </>
            )}
          </div>

          <aside className="side-col">
            <HistoryList
              history={history}
              onSelect={handleSelectHistory}
              activeId={result ? result.id : null}
            />
          </aside>
        </main>
      )}

      {tab === "monitor" && (
        <main className="app-main monitor-layout">
          <div className="main-col">
            <NetworkDevices />
            <LiveConnections />
            <RiskTrendChart />
          </div>
          <aside className="side-col wide">
            <AlertsPanel />
          </aside>
        </main>
      )}
    </div>
  );
}