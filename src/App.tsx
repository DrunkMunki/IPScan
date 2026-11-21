import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import "./App.css";
import {
  cancelNetworkScan,
  exportResults,
  getAllowlist,
  getAuditPath,
  getExtendedCommonPorts,
  getLocalNetwork,
  openAuditLocation,
  getProfiles,
  removeProfile,
  resetAuditPath,
  resultsToCsv,
  resultsToJson,
  saveProfile,
  setAllowlist,
  setAuditPath as persistAuditPath,
  startNetworkScan,
  vulnsToCsv,
} from "./lib/api";
import PingApp from "./PingApp";
import type {
  AppMode,
  CompleteEvent,
  HostResult,
  OpenPort,
  PortFoundEvent,
  PortPreset,
  PortScanFormState,
  ProgressEvent,
  ScanFormState,
  ScanLogEvent,
  ScanProfile,
  VulnScanFormState,
} from "./types";

const MAX_CONSOLE_LINES = 500;

function mergeOpenPorts(existing: OpenPort[], incoming: OpenPort[]): OpenPort[] {
  const map = new Map<string, OpenPort>();
  for (const p of existing) {
    map.set(`${p.protocol ?? "tcp"}-${p.port}`, p);
  }
  for (const p of incoming) {
    const key = `${p.protocol ?? "tcp"}-${p.port}`;
    const prev = map.get(key);
    if (!prev) {
      map.set(key, p);
      continue;
    }
    const notes = Array.from(
      new Set([...(prev.notes ?? []), ...(p.notes ?? [])]),
    );
    map.set(key, { ...prev, ...p, notes });
  }
  return Array.from(map.values()).sort((a, b) => a.port - b.port);
}

function mergeHostResult(prev: HostResult[], incoming: HostResult): HostResult[] {
  const idx = prev.findIndex((r) => r.ip === incoming.ip);
  if (idx < 0) {
    return [...prev, incoming].sort((a, b) =>
      a.ip.localeCompare(b.ip, undefined, { numeric: true }),
    );
  }
  const existing = prev[idx];
  const openPorts = mergeOpenPorts(existing.openPorts, incoming.openPorts);
  const next = [...prev];
  next[idx] = {
    ...existing,
    ...incoming,
    openPorts,
    vulns: incoming.vulns?.length ? incoming.vulns : existing.vulns,
    hostname: incoming.hostname || existing.hostname,
    mac: incoming.mac || existing.mac,
    manufacturer: incoming.manufacturer || existing.manufacturer,
  };
  return next;
}

function applyPortFound(prev: HostResult[], event: PortFoundEvent): HostResult[] {
  const idx = prev.findIndex((r) => r.ip === event.ip);
  const port = event.port;
  if (idx < 0) {
    return [
      ...prev,
      {
        ip: event.ip,
        hostname: event.hostname ?? null,
        mac: event.mac ?? null,
        manufacturer: event.manufacturer ?? null,
        latencyMs: event.latencyMs ?? null,
        alive: true,
        openPorts: [port],
        notes: [],
      },
    ].sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  }
  const existing = prev[idx];
  const openPorts = mergeOpenPorts(existing.openPorts, [port]);
  const next = [...prev];
  next[idx] = {
    ...existing,
    hostname: event.hostname || existing.hostname,
    mac: event.mac || existing.mac,
    manufacturer: event.manufacturer || existing.manufacturer,
    latencyMs: event.latencyMs ?? existing.latencyMs,
    alive: true,
    openPorts,
  };
  return next;
}

const defaultForm: ScanFormState = {
  targets: "",
  ports: "22,80,81,443,445,3389,8000,8080,8081",
  useCommonPorts: true,
  hostConcurrency: 64,
  portConcurrency: 100,
  timeoutMs: 400,
  useIcmp: true,
  scanPorts: true,
  scanUdp: false,
  probeAllTargets: false,
  identifyServices: false,
  vulnScan: false,
  authorized: false,
};

const defaultPortForm: PortScanFormState = {
  targets: "",
  preset: "extended",
  customPorts: "1-1024,8000-8100,8443",
  hostConcurrency: 32,
  portConcurrency: 200,
  timeoutMs: 500,
  scanUdp: false,
  identifyServices: true,
  vulnScan: false,
  authorized: false,
};

const defaultVulnForm: VulnScanFormState = {
  targets: "",
  hostConcurrency: 8,
  portConcurrency: 120,
  timeoutMs: 700,
  authorized: false,
};

async function resolvePortPreset(preset: PortPreset, customPorts: string): Promise<string> {
  switch (preset) {
    case "extended": {
      const ports = await getExtendedCommonPorts();
      return ports.join(",");
    }
    case "1-1024":
      return "1-1024";
    case "1-10000":
      return "1-10000";
    case "1-65535":
      return "1-65535";
    case "custom":
      return customPorts.trim();
  }
}

function App() {
  const [mode, setMode] = useState<AppMode>("network");
  const [form, setForm] = useState<ScanFormState>(defaultForm);
  const [portForm, setPortForm] = useState<PortScanFormState>(defaultPortForm);
  const [vulnForm, setVulnForm] = useState<VulnScanFormState>(defaultVulnForm);
  const [allowlistText, setAllowlistText] = useState(
    "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n127.0.0.0/8",
  );
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [results, setResults] = useState<HostResult[]>([]);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [portFilter, setPortFilter] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [consoleLines, setConsoleLines] = useState<ScanLogEvent[]>([]);
  const [consoleOpen, setConsoleOpen] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("Ready");
  const [auditPath, setAuditPath] = useState<string>("");
  const [profileName, setProfileName] = useState("Custom profile");
  const [localNetLabel, setLocalNetLabel] = useState<string>("");
  const consoleEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const [loadedProfiles, loadedAllowlist, audit, localNet] =
          await Promise.all([
            getProfiles(),
            getAllowlist(),
            getAuditPath(),
            getLocalNetwork().catch(() => null),
          ]);
        setProfiles(loadedProfiles);
        if (loadedAllowlist.length) {
          setAllowlistText(loadedAllowlist.join("\n"));
        }
        setAuditPath(audit);
        if (localNet) {
          setForm((prev) =>
            prev.targets.trim()
              ? prev
              : { ...prev, targets: localNet.cidr },
          );
          setLocalNetLabel(
            `${localNet.interfaceName} · ${localNet.ip} → ${localNet.cidr}`,
          );
        } else {
          setForm((prev) =>
            prev.targets.trim() ? prev : { ...prev, targets: "192.168.1.0/24" },
          );
        }
      } catch (e) {
        setError(String(e));
      }
    })();
  }, []);

  useEffect(() => {
    let disposed = false;
    const unsubs: Array<() => void> = [];

    void (async () => {
      const listeners = await Promise.all([
        listen<HostResult>("host-result", (event) => {
          setResults((prev) => mergeHostResult(prev, event.payload));
        }),
        listen<PortFoundEvent>("port-found", (event) => {
          setResults((prev) => applyPortFound(prev, event.payload));
        }),
        listen<ScanLogEvent>("scan-log", (event) => {
          setConsoleLines((prev) => {
            const next = [...prev, event.payload];
            if (next.length > MAX_CONSOLE_LINES) {
              return next.slice(next.length - MAX_CONSOLE_LINES);
            }
            return next;
          });
        }),
        listen<ProgressEvent>("scan-progress", (event) => {
          setProgress(event.payload);
          setStatus(event.payload.message);
        }),
        listen<CompleteEvent>("scan-complete", (event) => {
          setScanning(false);
          setStatus(
            event.payload.cancelled
              ? "Scan cancelled"
              : `Complete — ${event.payload.hostsAlive}/${event.payload.hostsTotal} hosts, ${event.payload.openPortCount} open ports`,
          );
        }),
        listen<string>("scan-error", (event) => {
          setScanning(false);
          setError(event.payload);
          setStatus("Scan failed");
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
    if (consoleOpen) {
      consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [consoleLines, consoleOpen]);

  // Single-host scans open the detail view automatically; multi-host stays on summary.
  useEffect(() => {
    if (results.length === 1) {
      setSelectedIp(results[0].ip);
      return;
    }
    if (selectedIp && !results.some((r) => r.ip === selectedIp)) {
      setSelectedIp(null);
    }
  }, [results, selectedIp]);

  const allowlist = useMemo(
    () =>
      allowlistText
        .split(/\r?\n|,|;/)
        .map((s) => s.trim())
        .filter(Boolean),
    [allowlistText],
  );

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return results;
    return results.filter((r) => {
      const hay = [
        r.ip,
        r.hostname ?? "",
        r.mac ?? "",
        r.manufacturer ?? "",
        r.notes.join(" "),
        r.openPorts
          .map(
            (p) =>
              `${p.protocol ?? "tcp"} ${p.port} ${p.service ?? ""} ${p.product ?? ""} ${p.banner ?? ""}`,
          )
          .join(" "),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [filter, results]);

  const selectedHost = useMemo(
    () => (selectedIp ? results.find((r) => r.ip === selectedIp) ?? null : null),
    [results, selectedIp],
  );

  const detailPorts = useMemo(() => {
    if (!selectedHost) return [];
    const q = portFilter.trim().toLowerCase();
    const ports = [...selectedHost.openPorts].sort((a, b) => a.port - b.port);
    if (!q) return ports;
    return ports.filter((p) => {
      const hay = [
        String(p.port),
        p.protocol ?? "",
        p.service ?? "",
        p.product ?? "",
        p.version ?? "",
        p.banner ?? "",
        ...(p.notes ?? []),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [selectedHost, portFilter]);

  const progressPct = progress
    ? Math.round((progress.completed / Math.max(progress.total, 1)) * 100)
    : 0;

  function update<K extends keyof ScanFormState>(key: K, value: ScanFormState[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function updatePort<K extends keyof PortScanFormState>(
    key: K,
    value: PortScanFormState[K],
  ) {
    setPortForm((prev) => ({ ...prev, [key]: value }));
  }

  function updateVuln<K extends keyof VulnScanFormState>(
    key: K,
    value: VulnScanFormState[K],
  ) {
    setVulnForm((prev) => ({ ...prev, [key]: value }));
  }

  async function onStart() {
    setError(null);
    setResults([]);
    setSelectedIp(null);
    setPortFilter("");
    setProgress(null);
    setConsoleLines([]);
    setConsoleOpen(true);
    try {
      await setAllowlist(allowlist);
      setScanning(true);
      setStatus("Starting scan…");
      await startNetworkScan(form, allowlist);
    } catch (e) {
      setScanning(false);
      setError(String(e));
      setStatus("Ready");
    }
  }

  async function onStartPortScan() {
    setError(null);
    setResults([]);
    setSelectedIp(null);
    setPortFilter("");
    setProgress(null);
    setConsoleLines([]);
    setConsoleOpen(true);
    try {
      if (!portForm.targets.trim()) {
        throw new Error("Enter one or more IPs / ranges for the port scan.");
      }
      const ports = await resolvePortPreset(portForm.preset, portForm.customPorts);
      if (!ports) {
        throw new Error("Choose a port preset or enter a custom port list.");
      }
      if (portForm.preset === "1-65535") {
        setStatus("Full 1–65535 scan can take a while…");
      }
      await setAllowlist(allowlist);
      setScanning(true);
      setStatus("Starting detailed port scan…");
      await startNetworkScan(
        {
          targets: portForm.targets,
          ports,
          useCommonPorts: false,
          hostConcurrency: portForm.hostConcurrency,
          portConcurrency: portForm.portConcurrency,
          timeoutMs: portForm.timeoutMs,
          useIcmp: false,
          scanPorts: true,
          scanUdp: portForm.scanUdp,
          probeAllTargets: true,
          identifyServices: portForm.identifyServices,
          vulnScan: portForm.vulnScan,
          authorized: portForm.authorized,
        },
        allowlist,
      );
    } catch (e) {
      setScanning(false);
      setError(String(e));
      setStatus("Ready");
    }
  }

  async function onStartVulnScan() {
    setError(null);
    setResults([]);
    setSelectedIp(null);
    setPortFilter("");
    setProgress(null);
    setConsoleLines([]);
    setConsoleOpen(true);
    try {
      const target = vulnForm.targets.trim();
      if (!target) {
        throw new Error("Enter a single IP (or small CIDR) for vulnerability checks.");
      }
      const ports = await getExtendedCommonPorts();
      await setAllowlist(allowlist);
      setScanning(true);
      setStatus("Starting vulnerability assessment…");
      await startNetworkScan(
        {
          targets: target,
          ports: ports.join(","),
          useCommonPorts: false,
          hostConcurrency: vulnForm.hostConcurrency,
          portConcurrency: vulnForm.portConcurrency,
          timeoutMs: vulnForm.timeoutMs,
          useIcmp: false,
          scanPorts: true,
          scanUdp: true,
          probeAllTargets: true,
          identifyServices: true,
          vulnScan: true,
          authorized: vulnForm.authorized,
        },
        allowlist,
      );
    } catch (e) {
      setScanning(false);
      setError(String(e));
      setStatus("Ready");
    }
  }

  function deepScanIp(ip: string) {
    setMode("ports");
    setPortForm((prev) => ({
      ...prev,
      targets: ip,
      authorized: form.authorized || prev.authorized || vulnForm.authorized,
    }));
    setStatus(`Port Scan ready for ${ip}`);
  }

  function vulnScanIp(ip: string) {
    setMode("vuln");
    setVulnForm((prev) => ({
      ...prev,
      targets: ip,
      authorized: form.authorized || portForm.authorized || prev.authorized,
    }));
    setStatus(`Vuln check ready for ${ip}`);
  }

  async function onCancel() {
    await cancelNetworkScan();
    setStatus("Cancelling…");
  }

  async function onSaveAllowlist() {
    try {
      await setAllowlist(allowlist);
      setStatus("Allowlist saved");
    } catch (e) {
      setError(String(e));
    }
  }

  async function onSaveProfile() {
    const profile: ScanProfile = {
      id: crypto.randomUUID(),
      name: profileName || "Custom profile",
      targets: form.targets,
      ports: form.ports,
      useCommonPorts: form.useCommonPorts,
      hostConcurrency: form.hostConcurrency,
      portConcurrency: form.portConcurrency,
      timeoutMs: form.timeoutMs,
      useIcmp: form.useIcmp,
      scanPorts: form.scanPorts,
      scanUdp: form.scanUdp,
      probeAllTargets: form.probeAllTargets,
      identifyServices: form.identifyServices,
      vulnScan: form.vulnScan,
    };
    try {
      setProfiles(await saveProfile(profile));
      setStatus(`Saved profile “${profile.name}”`);
    } catch (e) {
      setError(String(e));
    }
  }

  function applyProfile(profile: ScanProfile) {
    setForm({
      targets: profile.targets,
      ports: profile.ports,
      useCommonPorts: profile.useCommonPorts,
      hostConcurrency: profile.hostConcurrency,
      portConcurrency: profile.portConcurrency,
      timeoutMs: profile.timeoutMs,
      useIcmp: profile.useIcmp,
      scanPorts: profile.scanPorts,
      scanUdp: profile.scanUdp ?? false,
      probeAllTargets: profile.probeAllTargets,
      identifyServices: profile.identifyServices ?? false,
      vulnScan: profile.vulnScan ?? false,
      authorized: form.authorized,
    });
    setProfileName(profile.name);
    setStatus(`Loaded profile “${profile.name}”`);
  }

  async function onDeleteProfile(id: string) {
    try {
      setProfiles(await removeProfile(id));
    } catch (e) {
      setError(String(e));
    }
  }

  async function onExport(format: "csv" | "json" | "vulns") {
    try {
      const path = await save({
        defaultPath:
          format === "json"
            ? "ipscan-results.json"
            : format === "vulns"
              ? "ipscan-vulns.csv"
              : "ipscan-results.csv",
        filters: [
          format === "json"
            ? { name: "JSON", extensions: ["json"] }
            : { name: "CSV", extensions: ["csv"] },
        ],
      });
      if (!path) return;
      const contents =
        format === "json"
          ? resultsToJson(results)
          : format === "vulns"
            ? vulnsToCsv(results)
            : resultsToCsv(results);
      await exportResults(
        path,
        format === "json" ? "json" : "csv",
        contents,
      );
      setStatus(`Exported ${format.toUpperCase()} to ${path}`);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onUseLocalSubnet() {
    try {
      const localNet = await getLocalNetwork();
      update("targets", localNet.cidr);
      setLocalNetLabel(
        `${localNet.interfaceName} · ${localNet.ip} → ${localNet.cidr}`,
      );
      setStatus(`Targets set to local subnet ${localNet.cidr}`);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onBrowseAuditPath() {
    try {
      const path = await save({
        defaultPath: auditPath || "audit.log",
        filters: [{ name: "Log files", extensions: ["log", "txt"] }],
        title: "Choose audit log file",
      });
      if (!path) return;
      setAuditPath(path);
    } catch (e) {
      setError(String(e));
    }
  }

  async function onSaveAuditPath() {
    try {
      const saved = await persistAuditPath(auditPath);
      setAuditPath(saved);
      setStatus("Audit log path saved to registry");
    } catch (e) {
      setError(String(e));
    }
  }

  async function onResetAuditPath() {
    try {
      const path = await resetAuditPath();
      setAuditPath(path);
      setStatus("Audit log path reset to default");
    } catch (e) {
      setError(String(e));
    }
  }

  async function onOpenAuditLocation() {
    try {
      await openAuditLocation();
      setStatus("Opened audit log location");
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">IP</div>
          <div>
            <h1>IPScan</h1>
            <p>Internal IT — internal host &amp; port scanner</p>
          </div>
        </div>
        <div className="topbar-right">
          <div className="mode-tabs" role="tablist" aria-label="Scan mode">
            <button
              type="button"
              className={mode === "network" ? "mode-tab active" : "mode-tab"}
              onClick={() => setMode("network")}
              disabled={scanning}
            >
              Network scan
            </button>
            <button
              type="button"
              className={mode === "ports" ? "mode-tab active" : "mode-tab"}
              onClick={() => setMode("ports")}
              disabled={scanning}
            >
              Port scan
            </button>
            <button
              type="button"
              className={mode === "vuln" ? "mode-tab active" : "mode-tab"}
              onClick={() => setMode("vuln")}
              disabled={scanning}
            >
              Vuln check
            </button>
            <button
              type="button"
              className={mode === "ping" ? "mode-tab active" : "mode-tab"}
              onClick={() => setMode("ping")}
              disabled={scanning}
            >
              Ping
            </button>
          </div>
          <div className="badge">Developed by Simon Hughes</div>
        </div>
      </header>

      {mode === "ping" ? (
        <PingApp />
      ) : (
      <div className="layout">
        <aside className="side">
          {mode === "vuln" ? (
            <section className="panel">
              <h2 className="section-title">Vulnerability check</h2>
              <p className="hint" style={{ marginBottom: "0.8rem" }}>
                Best on a single IP: extended ports → identify → vulnerability checks.
              </p>
              <div className="field">
                <label htmlFor="vulnTargets">IP / small range</label>
                <textarea
                  id="vulnTargets"
                  value={vulnForm.targets}
                  onChange={(e) => updateVuln("targets", e.target.value)}
                  placeholder="192.168.1.10"
                />
              </div>
              <div className="grid-2">
                <div className="field">
                  <label htmlFor="vulnHostConc">Host concurrency</label>
                  <input
                    id="vulnHostConc"
                    type="number"
                    min={1}
                    max={64}
                    value={vulnForm.hostConcurrency}
                    onChange={(e) =>
                      updateVuln("hostConcurrency", Number(e.target.value) || 1)
                    }
                  />
                </div>
                <div className="field">
                  <label htmlFor="vulnPortConc">Port concurrency</label>
                  <input
                    id="vulnPortConc"
                    type="number"
                    min={1}
                    max={512}
                    value={vulnForm.portConcurrency}
                    onChange={(e) =>
                      updateVuln("portConcurrency", Number(e.target.value) || 1)
                    }
                  />
                </div>
              </div>
              <div className="field">
                <label htmlFor="vulnTimeout">Connect timeout (ms)</label>
                <input
                  id="vulnTimeout"
                  type="number"
                  min={100}
                  max={10000}
                  value={vulnForm.timeoutMs}
                  onChange={(e) => updateVuln("timeoutMs", Number(e.target.value) || 100)}
                />
              </div>
              <div className="check-row">
                <input
                  id="vulnAuthorized"
                  type="checkbox"
                  checked={vulnForm.authorized}
                  onChange={(e) => updateVuln("authorized", e.target.checked)}
                />
                <label htmlFor="vulnAuthorized">
                  I confirm this scan is authorized on company networks only.
                </label>
              </div>
              <div className="actions">
                <button
                  className="primary"
                  type="button"
                  disabled={scanning || !vulnForm.authorized}
                  onClick={() => void onStartVulnScan()}
                >
                  {scanning ? "Scanning…" : "Start vuln check"}
                </button>
                <button
                  className="danger"
                  type="button"
                  disabled={!scanning}
                  onClick={() => void onCancel()}
                >
                  Cancel
                </button>
              </div>
              {error && <div className="error">{error}</div>}
            </section>
          ) : mode === "ports" ? (
            <section className="panel">
              <h2 className="section-title">Detailed port scan</h2>
              <p className="hint" style={{ marginBottom: "0.8rem" }}>
                Scan specific IP(s) or a small range with a broader port set.
              </p>
              <div className="field">
                <label htmlFor="portTargets">IP / range / CIDR</label>
                <textarea
                  id="portTargets"
                  value={portForm.targets}
                  onChange={(e) => updatePort("targets", e.target.value)}
                  placeholder="192.168.2.10&#10;192.168.2.5-192.168.2.20"
                />
              </div>
              <div className="field">
                <label htmlFor="portPreset">Port set</label>
                <select
                  id="portPreset"
                  value={portForm.preset}
                  onChange={(e) => updatePort("preset", e.target.value as PortPreset)}
                >
                  <option value="extended">Extended common (~150 ports, includes 81)</option>
                  <option value="1-1024">Well-known 1–1024</option>
                  <option value="1-10000">1–10000 (deeper)</option>
                  <option value="1-65535">All TCP ports 1–65535 (slow)</option>
                  <option value="custom">Custom list / ranges</option>
                </select>
              </div>
              {portForm.preset === "custom" && (
                <div className="field">
                  <label htmlFor="customPorts">Custom ports</label>
                  <input
                    id="customPorts"
                    value={portForm.customPorts}
                    onChange={(e) => updatePort("customPorts", e.target.value)}
                    placeholder="81,443,8000-8100"
                  />
                </div>
              )}
              {portForm.preset === "1-65535" && (
                <p className="hint" style={{ color: "var(--warn)" }}>
                  Full port range is intensive — prefer a single IP or a tiny range.
                </p>
              )}
              <div className="grid-2">
                <div className="field">
                  <label htmlFor="portHostConc">Host concurrency</label>
                  <input
                    id="portHostConc"
                    type="number"
                    min={1}
                    max={128}
                    value={portForm.hostConcurrency}
                    onChange={(e) =>
                      updatePort("hostConcurrency", Number(e.target.value) || 1)
                    }
                  />
                </div>
                <div className="field">
                  <label htmlFor="portPortConc">Port concurrency</label>
                  <input
                    id="portPortConc"
                    type="number"
                    min={1}
                    max={1024}
                    value={portForm.portConcurrency}
                    onChange={(e) =>
                      updatePort("portConcurrency", Number(e.target.value) || 1)
                    }
                  />
                </div>
              </div>
              <div className="field">
                <label htmlFor="portTimeout">Connect timeout (ms)</label>
                <input
                  id="portTimeout"
                  type="number"
                  min={100}
                  max={10000}
                  value={portForm.timeoutMs}
                  onChange={(e) => updatePort("timeoutMs", Number(e.target.value) || 100)}
                />
              </div>
              <div className="check-row">
                <input
                  id="portScanUdp"
                  type="checkbox"
                  checked={portForm.scanUdp}
                  onChange={(e) => updatePort("scanUdp", e.target.checked)}
                />
                <label htmlFor="portScanUdp">Also probe common UDP services</label>
              </div>
              <div className="check-row">
                <input
                  id="portIdentify"
                  type="checkbox"
                  checked={portForm.identifyServices}
                  onChange={(e) => updatePort("identifyServices", e.target.checked)}
                />
                <label htmlFor="portIdentify">
                  Identify services (banners, HTTP/SMB version, TLS cert CN)
                </label>
              </div>
              <div className="check-row">
                <input
                  id="portVuln"
                  type="checkbox"
                  checked={portForm.vulnScan}
                  onChange={(e) => updatePort("vulnScan", e.target.checked)}
                />
                <label htmlFor="portVuln">
                  Chain basic vulnerability checks after ports (best on 1 IP)
                </label>
              </div>
              <div className="check-row">
                <input
                  id="portAuthorized"
                  type="checkbox"
                  checked={portForm.authorized}
                  onChange={(e) => updatePort("authorized", e.target.checked)}
                />
                <label htmlFor="portAuthorized">
                  I confirm this scan is authorized on company networks only.
                </label>
              </div>
              <div className="actions">
                <button
                  className="primary"
                  type="button"
                  disabled={scanning || !portForm.authorized}
                  onClick={() => void onStartPortScan()}
                >
                  {scanning ? "Scanning…" : "Start port scan"}
                </button>
                <button
                  className="danger"
                  type="button"
                  disabled={!scanning}
                  onClick={() => void onCancel()}
                >
                  Cancel
                </button>
              </div>
              {error && <div className="error">{error}</div>}
            </section>
          ) : (
          <section className="panel">
            <h2 className="section-title">Scan targets</h2>
            <div className="field">
              <label htmlFor="targets">CIDR / range / IP list</label>
              <textarea
                id="targets"
                value={form.targets}
                onChange={(e) => update("targets", e.target.value)}
                placeholder="192.168.2.0/24&#10;10.0.0.1-10.0.0.50"
              />
            </div>
            {localNetLabel && <p className="hint">Detected NIC: {localNetLabel}</p>}
            <div className="actions" style={{ marginTop: 0, marginBottom: "0.8rem" }}>
              <button
                className="ghost"
                type="button"
                onClick={() => void onUseLocalSubnet()}
              >
                Use local subnet
              </button>
            </div>

            <div className="check-row">
              <input
                id="commonPorts"
                type="checkbox"
                checked={form.useCommonPorts}
                onChange={(e) => update("useCommonPorts", e.target.checked)}
              />
              <label htmlFor="commonPorts">Use common TCP ports</label>
            </div>

            {!form.useCommonPorts && (
              <div className="field">
                <label htmlFor="ports">Custom ports</label>
                <input
                  id="ports"
                  value={form.ports}
                  onChange={(e) => update("ports", e.target.value)}
                  placeholder="22,80,443,8000-8100"
                />
              </div>
            )}

            <div className="grid-2">
              <div className="field">
                <label htmlFor="hostConc">Host concurrency</label>
                <input
                  id="hostConc"
                  type="number"
                  min={1}
                  max={512}
                  value={form.hostConcurrency}
                  onChange={(e) =>
                    update("hostConcurrency", Number(e.target.value) || 1)
                  }
                />
              </div>
              <div className="field">
                <label htmlFor="portConc">Port concurrency</label>
                <input
                  id="portConc"
                  type="number"
                  min={1}
                  max={1024}
                  value={form.portConcurrency}
                  onChange={(e) =>
                    update("portConcurrency", Number(e.target.value) || 1)
                  }
                />
              </div>
            </div>

            <div className="field">
              <label htmlFor="timeout">Connect timeout (ms)</label>
              <input
                id="timeout"
                type="number"
                min={100}
                max={10000}
                value={form.timeoutMs}
                onChange={(e) => update("timeoutMs", Number(e.target.value) || 100)}
              />
            </div>

            <div className="check-row">
              <input
                id="icmp"
                type="checkbox"
                checked={form.useIcmp}
                onChange={(e) => update("useIcmp", e.target.checked)}
              />
              <label htmlFor="icmp">
                ICMP ping during discovery (runs hidden; uncheck if discovery feels heavy)
              </label>
            </div>
              <div className="check-row">
                <input
                  id="scanPorts"
                  type="checkbox"
                  checked={form.scanPorts}
                  onChange={(e) => update("scanPorts", e.target.checked)}
                />
                <label htmlFor="scanPorts">TCP port-scan live hosts</label>
              </div>
              <div className="check-row">
                <input
                  id="scanUdp"
                  type="checkbox"
                  checked={form.scanUdp}
                  onChange={(e) => update("scanUdp", e.target.checked)}
                />
                <label htmlFor="scanUdp">
                  UDP scan common services (DNS/NTP/SNMP/NetBIOS/SSDP…) — only reports ports that reply
                </label>
              </div>
              <div className="check-row">
                <input
                  id="probeAll"
                  type="checkbox"
                  checked={form.probeAllTargets}
                  onChange={(e) => update("probeAllTargets", e.target.checked)}
                />
                <label htmlFor="probeAll">Skip discovery (scan all targets)</label>
              </div>
              <div className="check-row">
                <input
                  id="identifyServices"
                  type="checkbox"
                  checked={form.identifyServices}
                  onChange={(e) => update("identifyServices", e.target.checked)}
                />
                <label htmlFor="identifyServices">
                  Identify services on open ports (slower; banners / HTTP / SMB / TLS)
                </label>
              </div>
              <div className="check-row">
                <input
                  id="vulnScan"
                  type="checkbox"
                  checked={form.vulnScan}
                  onChange={(e) => update("vulnScan", e.target.checked)}
                />
                <label htmlFor="vulnScan">
                  Chain basic vulnerability checks (prefer small target sets)
                </label>
              </div>

            <div className="check-row">
              <input
                id="authorized"
                type="checkbox"
                checked={form.authorized}
                onChange={(e) => update("authorized", e.target.checked)}
              />
              <label htmlFor="authorized">
                I confirm this scan is authorized on company networks only.
              </label>
            </div>

            <div className="actions">
              <button
                className="primary"
                type="button"
                disabled={scanning || !form.authorized}
                onClick={() => void onStart()}
              >
                {scanning ? "Scanning…" : "Start scan"}
              </button>
              <button
                className="danger"
                type="button"
                disabled={!scanning}
                onClick={() => void onCancel()}
              >
                Cancel
              </button>
            </div>
            {error && <div className="error">{error}</div>}
          </section>
          )}

          <section className="panel">
            <h2 className="section-title">Allowlist (required)</h2>
            <div className="field">
              <label htmlFor="allowlist">Authorized CIDR ranges</label>
              <textarea
                id="allowlist"
                value={allowlistText}
                onChange={(e) => setAllowlistText(e.target.value)}
              />
            </div>
            <p className="hint">
              Scans refuse any target outside these ranges. Defaults cover RFC1918
              private space — tighten to your company subnets.
            </p>
            <div className="actions">
              <button className="ghost" type="button" onClick={() => void onSaveAllowlist()}>
                Save allowlist
              </button>
            </div>
          </section>

          <section className="panel">
            <h2 className="section-title">Profiles</h2>
            <div className="field">
              <label htmlFor="profileName">Profile name</label>
              <input
                id="profileName"
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
              />
            </div>
            <div className="actions">
              <button className="ghost" type="button" onClick={() => void onSaveProfile()}>
                Save current as profile
              </button>
            </div>
            <div className="profile-list" style={{ marginTop: "0.8rem" }}>
              {profiles.map((p) => (
                <div className="profile-item" key={p.id}>
                  <span>{p.name}</span>
                  <span>
                    <button className="ghost" type="button" onClick={() => applyProfile(p)}>
                      Load
                    </button>{" "}
                    <button
                      className="danger"
                      type="button"
                      onClick={() => void onDeleteProfile(p.id)}
                    >
                      Delete
                    </button>
                  </span>
                </div>
              ))}
            </div>
          </section>

          <section className="panel">
            <h2 className="section-title">Audit log</h2>
            <div className="field">
              <label htmlFor="auditPath">Log file path</label>
              <input
                id="auditPath"
                value={auditPath}
                onChange={(e) => setAuditPath(e.target.value)}
                placeholder="C:\Logs\ipscan-audit.log"
              />
            </div>
            <p className="hint">
              Saved in registry:{" "}
              <span className="mono">HKCU\Software\Onyx\IPScan\AuditLogPath</span>
            </p>
            <div className="actions" style={{ flexWrap: "wrap" }}>
              <button className="primary" type="button" onClick={() => void onOpenAuditLocation()}>
                Open location
              </button>
              <button className="ghost" type="button" onClick={() => void onBrowseAuditPath()}>
                Browse…
              </button>
              <button className="ghost" type="button" onClick={() => void onSaveAuditPath()}>
                Save path
              </button>
              <button className="ghost" type="button" onClick={() => void onResetAuditPath()}>
                Reset default
              </button>
            </div>
          </section>
        </aside>

        <main className="main">
          <section className="panel progress-wrap">
            <div className="progress-meta">
              <span>{status}</span>
              <span>
                {progress
                  ? `${progress.phase} ${progress.completed.toLocaleString()}/${progress.total.toLocaleString()} (${progressPct}%)`
                  : scanning
                    ? "…"
                    : "idle"}
              </span>
            </div>
            <div className="progress-bar">
              <span style={{ width: `${scanning ? Math.max(progressPct, 4) : progressPct}%` }} />
            </div>
          </section>

          <section className={`panel console-panel${consoleOpen ? "" : " collapsed"}`}>
            <div className="toolbar" style={{ marginBottom: consoleOpen ? "0.45rem" : 0 }}>
              <div className="toolbar-left">
                <h2 className="section-title" style={{ margin: 0 }}>
                  Console
                </h2>
                <span className="stat">{consoleLines.length} lines</span>
              </div>
              <div className="toolbar-right">
                <button
                  className="ghost"
                  type="button"
                  onClick={() => setConsoleOpen((v) => !v)}
                >
                  {consoleOpen ? "Hide" : "Show"}
                </button>
                <button
                  className="ghost"
                  type="button"
                  disabled={!consoleLines.length}
                  onClick={() => setConsoleLines([])}
                >
                  Clear
                </button>
              </div>
            </div>
            {consoleOpen && (
              <div className="console-view" aria-live="polite">
                {consoleLines.length === 0 ? (
                  <div className="console-empty">
                    Activity appears here while a scan runs (hosts up, OPEN ports, progress).
                  </div>
                ) : (
                  consoleLines.map((line, i) => (
                    <div
                      className={`console-line level-${line.level}`}
                      key={`${line.ts}-${i}-${line.message.slice(0, 24)}`}
                    >
                      <span className="console-ts">{line.ts}</span>
                      <span className="console-level">{line.level}</span>
                      <span className="console-msg">{line.message}</span>
                    </div>
                  ))
                )}
                <div ref={consoleEndRef} />
              </div>
            )}
          </section>

          <section className="panel results-panel">
            {selectedHost ? (
              <>
                <div className="toolbar">
                  <div className="toolbar-left">
                    {results.length > 1 && (
                      <button
                        className="ghost"
                        type="button"
                        onClick={() => setSelectedIp(null)}
                      >
                        ← All hosts
                      </button>
                    )}
                    <div className="detail-title">
                      <span className="mono">{selectedHost.ip}</span>
                      {selectedHost.hostname ? (
                        <span className="detail-host">{selectedHost.hostname}</span>
                      ) : null}
                    </div>
                    <span className="stat">
                      {selectedHost.openPorts.length} open ports
                    </span>
                  </div>
                  <div className="toolbar-right">
                    <input
                      value={portFilter}
                      onChange={(e) => setPortFilter(e.target.value)}
                      placeholder="Filter ports…"
                      style={{ minWidth: 140 }}
                    />
                    <button
                      className="ghost"
                      type="button"
                      disabled={scanning}
                      onClick={() => deepScanIp(selectedHost.ip)}
                    >
                      Deep scan
                    </button>
                    <button
                      className="ghost"
                      type="button"
                      disabled={scanning}
                      onClick={() => vulnScanIp(selectedHost.ip)}
                    >
                      Vuln check
                    </button>
                    <button
                      className="ghost"
                      type="button"
                      disabled={!results.length}
                      onClick={() => void onExport("csv")}
                    >
                      Export CSV
                    </button>
                    {(selectedHost.vulns?.length ?? 0) > 0 && (
                      <button
                        className="ghost"
                        type="button"
                        onClick={() => void onExport("vulns")}
                      >
                        Export vulns
                      </button>
                    )}
                  </div>
                </div>

                <div className="detail-meta">
                  <span>
                    <em>MAC</em> {selectedHost.mac || "—"}
                  </span>
                  <span>
                    <em>Vendor</em> {selectedHost.manufacturer || "—"}
                  </span>
                  <span>
                    <em>Latency</em>{" "}
                    {selectedHost.latencyMs != null
                      ? `${selectedHost.latencyMs} ms`
                      : "—"}
                  </span>
                  {selectedHost.notes.length > 0 && (
                    <span className="note">{selectedHost.notes.join(" · ")}</span>
                  )}
                </div>

                <div className="table-wrap detail-ports">
                  <table>
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Proto</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>Banner / details</th>
                        <th>Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detailPorts.length === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ color: "var(--muted)" }}>
                            {scanning
                              ? "Waiting for open ports…"
                              : selectedHost.openPorts.length === 0
                                ? "No open ports found on this host."
                                : "No ports match this filter."}
                          </td>
                        </tr>
                      ) : (
                        detailPorts.map((p) => (
                          <tr key={`${p.protocol ?? "tcp"}-${p.port}`}>
                            <td className="mono">{p.port}</td>
                            <td>
                              <span
                                className={`pill${p.protocol === "udp" ? " udp" : ""}`}
                              >
                                {(p.protocol ?? "tcp").toUpperCase()}
                              </span>
                            </td>
                            <td>{p.service || "—"}</td>
                            <td>{p.product || "—"}</td>
                            <td className="mono">{p.version || "—"}</td>
                            <td className="banner-cell">{p.banner || "—"}</td>
                            <td className="note">
                              {(p.notes ?? []).join(" · ") || "—"}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                {(selectedHost.vulns?.length ?? 0) > 0 && (
                  <div className="vuln-section">
                    <h3 className="section-title">Vulnerability findings</h3>
                    <div className="table-wrap detail-vulns">
                      <table>
                        <thead>
                          <tr>
                            <th>Severity</th>
                            <th>Port</th>
                            <th>Title</th>
                            <th>Detail</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedHost.vulns!.map((v, i) => (
                            <tr key={`${v.title}-${v.port ?? "x"}-${i}`}>
                              <td>
                                <span className={`sev sev-${v.severity}`}>
                                  {v.severity}
                                </span>
                              </td>
                              <td className="mono">{v.port ?? "—"}</td>
                              <td>{v.title}</td>
                              <td className="banner-cell">{v.detail}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <>
                <div className="toolbar">
                  <div className="toolbar-left">
                    <span className="stat">{results.length} hosts</span>
                    <span className="stat">
                      {results.reduce((n, r) => n + r.openPorts.length, 0)} open
                      ports
                    </span>
                    <input
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                      placeholder="Filter hosts…"
                      style={{ minWidth: 160 }}
                    />
                  </div>
                  <div className="toolbar-right">
                    <button
                      className="ghost"
                      type="button"
                      disabled={!results.length}
                      onClick={() => void onExport("csv")}
                    >
                      Export CSV
                    </button>
                    <button
                      className="ghost"
                      type="button"
                      disabled={!results.length}
                      onClick={() => void onExport("json")}
                    >
                      Export JSON
                    </button>
                  </div>
                </div>

                <div className="table-wrap host-summary">
                  <table>
                    <thead>
                      <tr>
                        <th>IP</th>
                        <th>Hostname</th>
                        <th>MAC</th>
                        <th>Manufacturer</th>
                        <th>Latency</th>
                        <th>Open ports</th>
                        <th>Notes</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.length === 0 ? (
                        <tr>
                          <td colSpan={8} style={{ color: "var(--muted)" }}>
                            {mode === "ports"
                              ? "No results yet. Enter target IP(s), pick a port set, confirm authorization, then start."
                              : "No results yet. Configure an allowlist, confirm authorization, then start a scan."}
                          </td>
                        </tr>
                      ) : (
                        filtered.map((r) => (
                          <tr
                            key={r.ip}
                            className="host-row"
                            onClick={() => setSelectedIp(r.ip)}
                          >
                            <td className="mono">{r.ip}</td>
                            <td>{r.hostname || "—"}</td>
                            <td className="mono">{r.mac || "—"}</td>
                            <td>{r.manufacturer || "—"}</td>
                            <td className="mono">
                              {r.latencyMs != null ? `${r.latencyMs} ms` : "—"}
                            </td>
                            <td>
                              <span className="port-count">
                                {r.openPorts.length}
                              </span>
                            </td>
                            <td className="note">
                              {r.notes.join(" · ") || "—"}
                            </td>
                            <td onClick={(e) => e.stopPropagation()}>
                              <button
                                className="ghost"
                                type="button"
                                onClick={() => setSelectedIp(r.ip)}
                              >
                                Details
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
                {filtered.length > 0 && (
                  <p className="hint" style={{ marginTop: "0.65rem" }}>
                    Click a host row to open its port list and service details.
                  </p>
                )}
              </>
            )}
          </section>
        </main>
      </div>
      )}
    </div>
  );
}

export default App;