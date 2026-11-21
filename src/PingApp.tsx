import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./PingApp.css";
import {
  pingClearAll,
  pingClearSession,
  pingCreateSession,
  pingDeleteSession,
  pingExportDb,
  pingGetStats,
  pingImportCsv,
  pingImportDb,
  pingListResults,
  pingListSessions,
  pingStart,
  pingStop,
  pingStopAll,
  type PingLiveEvent,
  type PingResultRow,
  type PingSession,
  type PingStatSummary,
} from "./lib/pingApi";

const MAX_CONSOLE = 400;

function LatencyChart({ results }: { results: PingResultRow[] }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "rgba(0,0,0,0.25)";
    ctx.fillRect(0, 0, width, height);

    const points = results.slice(-200);
    if (points.length < 2) {
      ctx.fillStyle = "#8eada3";
      ctx.font = "12px IBM Plex Mono, monospace";
      ctx.fillText("Not enough samples yet", 12, 24);
      return;
    }

    const latencies = points.map((p) =>
      p.success && p.latencyMs != null ? p.latencyMs : null,
    );
    const values = latencies.filter((v): v is number => v != null);
    const max = Math.max(10, ...(values.length ? values : [10]));
    const pad = 8;

    points.forEach((p, i) => {
      if (p.success) return;
      const x = pad + (i / (points.length - 1)) * (width - pad * 2);
      ctx.strokeStyle = "rgba(255,107,107,0.55)";
      ctx.beginPath();
      ctx.moveTo(x, pad);
      ctx.lineTo(x, height - pad);
      ctx.stroke();
    });

    ctx.beginPath();
    ctx.strokeStyle = "#3ecf9a";
    ctx.lineWidth = 2;
    let started = false;
    points.forEach((p, i) => {
      if (!p.success || p.latencyMs == null) {
        started = false;
        return;
      }
      const x = pad + (i / (points.length - 1)) * (width - pad * 2);
      const y = height - pad - (p.latencyMs / max) * (height - pad * 2);
      if (!started) {
        ctx.moveTo(x, y);
        started = true;
      } else {
        ctx.lineTo(x, y);
      }
    });
    ctx.stroke();
  }, [results]);

  return <canvas ref={canvasRef} className="latency-chart" />;
}

async function startSessionsStaggered(ids: string[], gapMs = 40) {
  for (const id of ids) {
    try {
      await pingStart(id);
    } catch {
      // already running / race — ignore
    }
    if (gapMs > 0) {
      await new Promise((r) => setTimeout(r, gapMs));
    }
  }
}

export default function PingApp() {
  const [sessions, setSessions] = useState<PingSession[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, PingResultRow[]>>({});
  const [stats, setStats] = useState<Record<string, PingStatSummary>>({});
  const [target, setTarget] = useState("");
  const [title, setTitle] = useState("");
  const [intervalMs, setIntervalMs] = useState(1000);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const consoleEndRef = useRef<HTMLDivElement | null>(null);

  const active = useMemo(
    () => sessions.find((s) => s.id === activeId) ?? null,
    [sessions, activeId],
  );
  const activeResults = activeId ? (results[activeId] ?? []) : [];
  const activeStats = activeId ? stats[activeId] : undefined;
  const runningCount = sessions.filter((s) => s.running).length;

  async function refreshSessions(preferId?: string | null) {
    const list = await pingListSessions();
    setSessions(list);
    const nextId =
      preferId && list.some((s) => s.id === preferId)
        ? preferId
        : activeId && list.some((s) => s.id === activeId)
          ? activeId
          : (list[0]?.id ?? null);
    setActiveId(nextId);
    return list;
  }

  async function loadSessionData(sessionId: string) {
    const [rows, summary] = await Promise.all([
      pingListResults(sessionId, 500),
      pingGetStats(sessionId),
    ]);
    setResults((prev) => ({ ...prev, [sessionId]: rows }));
    setStats((prev) => ({ ...prev, [sessionId]: summary }));
  }

  useEffect(() => {
    void (async () => {
      try {
        const list = await refreshSessions();
        await Promise.all(list.map((s) => loadSessionData(s.id)));
      } catch (e) {
        setError(String(e));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!activeId) return;
    void loadSessionData(activeId).catch((e) => setError(String(e)));
  }, [activeId]);

  useEffect(() => {
    let disposed = false;
    const unsubs: Array<() => void> = [];
    void (async () => {
      const listeners = await Promise.all([
        listen<PingLiveEvent>("ping-result", (event) => {
          const { sessionId, result } = event.payload;
          setResults((prev) => {
            const cur = prev[sessionId] ?? [];
            const next = [...cur, result];
            return {
              ...prev,
              [sessionId]:
                next.length > MAX_CONSOLE
                  ? next.slice(next.length - MAX_CONSOLE)
                  : next,
            };
          });
          void pingGetStats(sessionId).then((summary) => {
            setStats((prev) => ({ ...prev, [sessionId]: summary }));
          });
          setSessions((prev) =>
            prev.map((s) => (s.id === sessionId ? { ...s, running: true } : s)),
          );
        }),
        listen<string>("ping-stopped", (event) => {
          setSessions((prev) =>
            prev.map((s) =>
              s.id === event.payload ? { ...s, running: false } : s,
            ),
          );
        }),
        listen<string>("ping-error", (event) => {
          setError(event.payload);
        }),
      ]);
      if (disposed) {
        listeners.forEach((u) => u());
        return;
      }
      unsubs.push(...listeners);
    })();
    return () => {
      disposed = true;
      unsubs.forEach((u) => u());
    };
  }, []);

  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [activeResults.length, activeId]);

  async function onAddTab() {
    setError(null);
    try {
      const session = await pingCreateSession(title, target, intervalMs);
      setTarget("");
      setTitle("");
      await refreshSessions(session.id);
      setResults((prev) => ({ ...prev, [session.id]: [] }));
      await pingStart(session.id);
      await refreshSessions(session.id);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onImportCsv() {
    setError(null);
    try {
      const selected = await open({
        multiple: false,
        filters: [{ name: "CSV", extensions: ["csv", "txt"] }],
        title: "Import IP list (CSV)",
      });
      if (!selected || Array.isArray(selected)) return;
      setBusy(true);
      const created = await pingImportCsv(selected, intervalMs);
      setResults((prev) => {
        const next = { ...prev };
        for (const s of created) next[s.id] = [];
        return next;
      });
      await refreshSessions(created[0]?.id ?? null);
      await startSessionsStaggered(created.map((s) => s.id));
      await refreshSessions(created[0]?.id ?? null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onExportDb() {
    setError(null);
    try {
      const path = await save({
        defaultPath: "ipscan-ping.db",
        filters: [{ name: "SQLite DB", extensions: ["db"] }],
        title: "Export ping database",
      });
      if (!path) return;
      await pingExportDb(path);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onLoadDb() {
    setError(null);
    if (
      !confirm(
        "Load a ping database? This replaces the current tabs and history in %AppData%\\ipscan\\ping.db.",
      )
    ) {
      return;
    }
    try {
      const selected = await open({
        multiple: false,
        filters: [{ name: "SQLite DB", extensions: ["db"] }],
        title: "Load ping database",
      });
      if (!selected || Array.isArray(selected)) return;
      setBusy(true);
      const list = await pingImportDb(selected);
      setSessions(list);
      setActiveId(list[0]?.id ?? null);
      setResults({});
      setStats({});
      await Promise.all(list.map((s) => loadSessionData(s.id)));
      if (
        list.length > 0 &&
        confirm(`Loaded ${list.length} tab(s). Start pinging all of them now?`)
      ) {
        await startSessionsStaggered(list.map((s) => s.id));
        await refreshSessions(list[0]?.id ?? null);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onStart() {
    if (!activeId) return;
    setError(null);
    try {
      await pingStart(activeId);
      await refreshSessions(activeId);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onStop() {
    if (!activeId) return;
    await pingStop(activeId);
    await refreshSessions(activeId);
  }

  async function onStartAll() {
    setError(null);
    setBusy(true);
    try {
      const stopped = sessions.filter((s) => !s.running).map((s) => s.id);
      await startSessionsStaggered(stopped);
      await refreshSessions(activeId);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onStopAll() {
    await pingStopAll();
    await refreshSessions(activeId);
  }

  async function onClearCurrent() {
    if (!activeId) return;
    if (!confirm("Clear all recorded results for this tab?")) return;
    await pingClearSession(activeId);
    setResults((prev) => ({ ...prev, [activeId]: [] }));
    await loadSessionData(activeId);
  }

  async function onDeleteTab(id?: string) {
    const sessionId = id ?? activeId;
    if (!sessionId) return;
    if (!confirm("Close this ping tab and delete its history?")) return;
    await pingDeleteSession(sessionId);
    setResults((prev) => {
      const next = { ...prev };
      delete next[sessionId];
      return next;
    });
    setStats((prev) => {
      const next = { ...prev };
      delete next[sessionId];
      return next;
    });
    await refreshSessions(null);
  }

  async function onClearAll() {
    if (!confirm("Delete ALL ping tabs and history?")) return;
    await pingClearAll();
    setSessions([]);
    setActiveId(null);
    setResults({});
    setStats({});
  }

  return (
    <div className="ping-embed">
      <div className="ping-toolbar">
        <div className="ping-new">
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="IP or hostname"
            onKeyDown={(e) => {
              if (e.key === "Enter") void onAddTab();
            }}
          />
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Tab title (optional)"
          />
          <label className="interval-field">
            <span>Interval ms</span>
            <input
              type="number"
              min={500}
              max={3600000}
              value={intervalMs}
              onChange={(e) => setIntervalMs(Number(e.target.value) || 1000)}
            />
          </label>
          <button
            className="primary"
            type="button"
            disabled={busy || !target.trim()}
            onClick={() => void onAddTab()}
          >
            New tab + start
          </button>
        </div>

        <div className="ping-file-actions">
          <button
            className="ghost"
            type="button"
            disabled={busy}
            onClick={() => void onImportCsv()}
            title="CSV: one IP/hostname per line, or first column"
          >
            Import CSV
          </button>
          <button
            className="ghost"
            type="button"
            disabled={busy}
            onClick={() => void onExportDb()}
          >
            Export DB
          </button>
          <button
            className="ghost"
            type="button"
            disabled={busy}
            onClick={() => void onLoadDb()}
          >
            Load DB
          </button>
          <button
            className="ghost"
            type="button"
            disabled={busy || sessions.length === 0}
            onClick={() => void onStartAll()}
          >
            Start all
          </button>
          <button
            className="ghost"
            type="button"
            disabled={busy || runningCount === 0}
            onClick={() => void onStopAll()}
          >
            Stop all
          </button>
          <button
            className="danger"
            type="button"
            disabled={busy}
            onClick={() => void onClearAll()}
          >
            Clear all tabs
          </button>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="browser-tabs-wrap">
        <div className="browser-tabs-meta">
          <span>
            {sessions.length} tab{sessions.length === 1 ? "" : "s"}
            {runningCount > 0 ? ` · ${runningCount} running` : ""}
          </span>
          <span className="hint">Tabs wrap to extra rows as the window fills</span>
        </div>
        <div className="browser-tabs" role="tablist">
          {sessions.length === 0 ? (
            <span className="hint">
              No ping tabs yet — add a target, import a CSV, or load a DB.
            </span>
          ) : (
            sessions.map((s) => (
              <div
                key={s.id}
                className={`browser-tab${s.id === activeId ? " active" : ""}${s.running ? " running" : ""}`}
                role="tab"
                tabIndex={0}
                onClick={() => setActiveId(s.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") setActiveId(s.id);
                }}
              >
                <span className="dot" />
                <span className="tab-label" title={s.target}>
                  {s.title}
                </span>
                <button
                  type="button"
                  className="tab-close"
                  title="Close tab"
                  onClick={(e) => {
                    e.stopPropagation();
                    void onDeleteTab(s.id);
                  }}
                >
                  ×
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      {active ? (
        <div className="ping-main">
          <section className="panel ping-controls">
            <div className="meta">
              <span className="mono">{active.target}</span>
              <span>every {active.intervalMs} ms</span>
              <span className={active.running ? "ok" : "muted"}>
                {active.running ? "RUNNING" : "STOPPED"}
              </span>
              <span className="hint">SQLite: %AppData%\ipscan\ping.db</span>
            </div>
            <div className="actions">
              <button
                className="primary"
                type="button"
                disabled={active.running || busy}
                onClick={() => void onStart()}
              >
                Start
              </button>
              <button
                className="danger"
                type="button"
                disabled={!active.running || busy}
                onClick={() => void onStop()}
              >
                Stop
              </button>
              <button
                className="ghost"
                type="button"
                onClick={() => void onClearCurrent()}
              >
                Clear screen / history
              </button>
            </div>
          </section>

          <section className="panel stats-row">
            <div className="stat-card">
              <em>Total</em>
              <strong>{activeStats?.total ?? 0}</strong>
            </div>
            <div className="stat-card">
              <em>OK</em>
              <strong>{activeStats?.success ?? 0}</strong>
            </div>
            <div className="stat-card warn">
              <em>Drops</em>
              <strong>
                {activeStats?.failed ?? 0}{" "}
                <small>({(activeStats?.dropPercent ?? 0).toFixed(1)}%)</small>
              </strong>
            </div>
            <div className="stat-card">
              <em>Avg / Min / Max</em>
              <strong className="mono">
                {activeStats?.avgLatencyMs != null
                  ? `${activeStats.avgLatencyMs.toFixed(1)}`
                  : "—"}
                {" / "}
                {activeStats?.minLatencyMs != null
                  ? `${activeStats.minLatencyMs.toFixed(1)}`
                  : "—"}
                {" / "}
                {activeStats?.maxLatencyMs != null
                  ? `${activeStats.maxLatencyMs.toFixed(1)}`
                  : "—"}{" "}
                ms
              </strong>
            </div>
          </section>

          <section className="panel chart-panel">
            <h2>Latency &amp; drops</h2>
            <LatencyChart results={activeResults} />
            <p className="hint">
              Green line = latency. Red marks = drops. History keeps recording while
              running; Export DB to resume later on another machine.
            </p>
          </section>

          <section className="panel console-panel">
            <h2>Live results</h2>
            <div className="ping-console">
              {activeResults.length === 0 ? (
                <div className="console-empty">No samples yet.</div>
              ) : (
                activeResults.map((r) => (
                  <div
                    key={r.id}
                    className={`ping-line${r.success ? "" : " fail"}`}
                  >
                    <span className="ts">{r.ts}</span>
                    <span className="msg">{r.message}</span>
                  </div>
                ))
              )}
              <div ref={consoleEndRef} />
            </div>
          </section>
        </div>
      ) : (
        <div className="panel empty-state">
          Create a tab, import a CSV of IPs, or load a saved ping database.
        </div>
      )}
    </div>
  );
}
