import { useEffect, useState } from "react";
import CommandCenter  from "./components/CommandCenter";
import Dashboard      from "./components/Dashboard";
import IncidentList   from "./components/IncidentList";
import ThreatTrends   from "./components/ThreatTrends";
import AIAdvisor      from "./components/AIAdvisor";
import LiveFeed       from "./components/LiveFeed";
import AssetInventory from "./components/AssetInventory";

const NAV = [
  { id: "command",   label: "Command Center", short: "CMD" },
  { id: "dashboard", label: "Analytics",       short: "OPS" },
  { id: "incidents", label: "Incident Queue",  short: "IR"  },
  { id: "advisor",   label: "AI Analyst",      short: "AI"  },
  { id: "feed",      label: "Live Feed",        short: "LOG" },
  { id: "threats",   label: "Threat Intel",     short: "IOC" },
  { id: "assets",    label: "Assets",           short: "AST" },
];

export default function App() {
  const [page, setPage] = useState("command");
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const [alertBanner, setAlertBanner] = useState(null);

  useEffect(() => {
    const timer = setInterval(() => setLastUpdated(new Date()), 30_000);
    return () => clearInterval(timer);
  }, []);

  function showAlert(msg, type = "info") {
    setAlertBanner({ msg, type });
    window.clearTimeout(showAlert.timeoutId);
    showAlert.timeoutId = window.setTimeout(() => setAlertBanner(null), 4000);
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(14,165,233,0.16),_transparent_28%),radial-gradient(circle_at_80%_20%,_rgba(249,115,22,0.12),_transparent_22%),linear-gradient(180deg,_#020617_0%,_#020617_55%,_#08111f_100%)]" />

      <div className="grid min-h-screen lg:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="border-r border-slate-800/80 bg-slate-950/80 backdrop-blur">
          <div className="border-b border-slate-800/80 px-6 py-6">
            <div className="text-[11px] uppercase tracking-[0.35em] text-cyan-400">
              AI-SOC
            </div>
            <div className="mt-2 text-2xl font-semibold tracking-tight text-white">
              Sentinel Deck
            </div>
            <p className="mt-2 max-w-xs text-sm leading-6 text-slate-400">
              Live detection, response, and threat posture in one operator surface.
            </p>
          </div>

          <nav className="space-y-2 px-4 py-5">
            {NAV.map((item) => {
              const active = page === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setPage(item.id)}
                  className={`flex w-full items-center gap-3 rounded-2xl border px-4 py-3 text-left transition ${
                    active
                      ? "border-cyan-500/40 bg-cyan-500/10 text-white shadow-[0_0_0_1px_rgba(34,211,238,0.12)]"
                      : "border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700 hover:bg-slate-900/70 hover:text-slate-200"
                  }`}
                >
                  <span
                    className={`inline-flex h-10 w-10 items-center justify-center rounded-xl text-xs font-semibold ${
                      active
                        ? "bg-cyan-400/15 text-cyan-300"
                        : "bg-slate-800 text-slate-500"
                    }`}
                  >
                    {item.short}
                  </span>
                  <span className="text-sm font-medium">{item.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="mt-auto border-t border-slate-800/80 px-6 py-5 text-sm text-slate-400">
            <div className="flex items-center justify-between">
              <span>Last sync</span>
              <span className="text-slate-200">
                {lastUpdated.toLocaleTimeString()}
              </span>
            </div>
            <div className="mt-3 flex items-center gap-2 text-xs uppercase tracking-[0.25em] text-emerald-400">
              <span className="inline-block h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(74,222,128,0.8)]" />
              Monitoring active
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-col">
          <header className="border-b border-slate-800/80 bg-slate-950/70 px-6 py-5 backdrop-blur">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <div className="text-[11px] uppercase tracking-[0.35em] text-slate-500">
                  Security Operations Center
                </div>
                <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">
                  {NAV.find((item) => item.id === page)?.label}
                </h1>
              </div>

              <div className="flex flex-wrap gap-3 text-xs uppercase tracking-[0.25em] text-slate-400">
                <div className="rounded-full border border-slate-800 bg-slate-900/70 px-4 py-2">
                  Auto refresh 30s
                </div>
                <div className="rounded-full border border-slate-800 bg-slate-900/70 px-4 py-2">
                  Analyst console
                </div>
                <div className="rounded-full border border-slate-800 bg-slate-900/70 px-4 py-2">
                  Playbooks armed
                </div>
              </div>
            </div>
          </header>

          {alertBanner && (
            <div
              className={`mx-6 mt-4 rounded-2xl border px-4 py-3 text-sm ${
                alertBanner.type === "error"
                  ? "border-rose-500/30 bg-rose-500/10 text-rose-200"
                  : alertBanner.type === "success"
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                    : "border-cyan-500/30 bg-cyan-500/10 text-cyan-200"
              }`}
            >
              {alertBanner.msg}
            </div>
          )}

          <main className="min-w-0 flex-1 overflow-auto px-6 py-6">
            {page === "command"   && <CommandCenter  lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "dashboard" && <Dashboard      lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "incidents" && <IncidentList   lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "advisor"   && <AIAdvisor      lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "feed"      && <LiveFeed       lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "threats"   && <ThreatTrends   lastUpdated={lastUpdated} showAlert={showAlert} />}
            {page === "assets"    && <AssetInventory lastUpdated={lastUpdated} showAlert={showAlert} />}
          </main>
        </div>
      </div>
    </div>
  );
}
