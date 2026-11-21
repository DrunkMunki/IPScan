import { invoke } from "@tauri-apps/api/core";
import type { ScanFormState, ScanProfile } from "../types";

export async function startNetworkScan(
  form: ScanFormState,
  allowlist: string[],
): Promise<string> {
  return invoke("start_network_scan", {
    request: {
      targets: form.targets,
      ports: form.ports,
      useCommonPorts: form.useCommonPorts,
      allowlist,
      hostConcurrency: form.hostConcurrency,
      portConcurrency: form.portConcurrency,
      timeoutMs: form.timeoutMs,
      useIcmp: form.useIcmp,
      scanPorts: form.scanPorts,
      scanUdp: form.scanUdp,
      probeAllTargets: form.probeAllTargets,
      identifyServices: form.identifyServices,
      vulnScan: form.vulnScan,
      authorized: form.authorized,
    },
  });
}

export function cancelNetworkScan(): Promise<boolean> {
  return invoke("cancel_network_scan");
}

export function getCommonPorts(): Promise<number[]> {
  return invoke("get_common_ports");
}

export function getExtendedCommonPorts(): Promise<number[]> {
  return invoke("get_extended_common_ports");
}

export function getProfiles(): Promise<ScanProfile[]> {
  return invoke("get_profiles");
}

export function saveProfile(profile: ScanProfile): Promise<ScanProfile[]> {
  return invoke("save_profile", { profile });
}

export function removeProfile(id: string): Promise<ScanProfile[]> {
  return invoke("remove_profile", { id });
}

export function getAllowlist(): Promise<string[]> {
  return invoke("get_allowlist");
}

export function setAllowlist(cidrs: string[]): Promise<void> {
  return invoke("set_allowlist", { cidrs });
}

export function exportResults(
  path: string,
  format: "csv" | "json",
  contents: string,
): Promise<void> {
  return invoke("export_results", { path, format, contents });
}

export function getAuditPath(): Promise<string> {
  return invoke("get_audit_path");
}

export function getDefaultAuditPath(): Promise<string> {
  return invoke("get_default_audit_path");
}

export function setAuditPath(path: string): Promise<string> {
  return invoke("set_audit_path", { path });
}

export function resetAuditPath(): Promise<string> {
  return invoke("reset_audit_path");
}

export function openAuditLocation(): Promise<void> {
  return invoke("open_audit_location");
}

export interface LocalNetworkInfo {
  interfaceName: string;
  ip: string;
  cidr: string;
  prefixLen: number;
}

export function getLocalNetwork(): Promise<LocalNetworkInfo> {
  return invoke("get_local_network");
}

export function resultsToCsv(results: import("../types").HostResult[]): string {
  const header = [
    "ip",
    "hostname",
    "mac",
    "manufacturer",
    "latency_ms",
    "alive",
    "protocol",
    "port",
    "service",
    "product",
    "version",
    "banner",
    "notes",
  ];

  const rows: Array<Array<string | number | boolean>> = [];
  for (const r of results) {
    const host = [
      r.ip,
      r.hostname ?? "",
      r.mac ?? "",
      r.manufacturer ?? "",
      r.latencyMs ?? "",
      String(r.alive),
    ];
    if (!r.openPorts.length) {
      rows.push([...host, "", "", "", "", "", "", r.notes.join("; ")]);
      continue;
    }

    const ports = [...r.openPorts].sort((a, b) => a.port - b.port);
    for (const p of ports) {
      rows.push([
        ...host,
        p.protocol || "tcp",
        p.port,
        p.service ?? "",
        p.product ?? "",
        p.version ?? "",
        p.banner ?? "",
        (p.notes ?? []).join("; "),
      ]);
    }
  }

  return [header, ...rows]
    .map((cols) =>
      cols
        .map((c) => {
          const s = String(c);
          return s.includes(",") || s.includes('"') || s.includes("\n")
            ? `"${s.replace(/"/g, '""')}"`
            : s;
        })
        .join(","),
    )
    .join("\n");
}

export function vulnsToCsv(results: import("../types").HostResult[]): string {
  const header = [
    "ip",
    "hostname",
    "port",
    "protocol",
    "severity",
    "title",
    "detail",
  ];
  const rows: Array<Array<string | number>> = [];
  for (const r of results) {
    for (const v of r.vulns ?? []) {
      rows.push([
        v.ip || r.ip,
        r.hostname ?? "",
        v.port ?? "",
        v.protocol ?? "",
        v.severity,
        v.title,
        v.detail,
      ]);
    }
  }
  return [header, ...rows]
    .map((cols) =>
      cols
        .map((c) => {
          const s = String(c);
          return s.includes(",") || s.includes('"') || s.includes("\n")
            ? `"${s.replace(/"/g, '""')}"`
            : s;
        })
        .join(","),
    )
    .join("\n");
}

export function resultsToJson(results: import("../types").HostResult[]): string {
  return JSON.stringify(results, null, 2);
}