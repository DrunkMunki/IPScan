export interface OpenPort {
  port: number;
  protocol?: string | null;
  service?: string | null;
  product?: string | null;
  version?: string | null;
  banner?: string | null;
  notes?: string[];
}

export interface VulnFinding {
  ip: string;
  port?: number | null;
  protocol?: string | null;
  severity: string;
  title: string;
  detail: string;
}

export interface HostResult {
  ip: string;
  hostname?: string | null;
  mac?: string | null;
  manufacturer?: string | null;
  latencyMs?: number | null;
  alive: boolean;
  openPorts: OpenPort[];
  notes: string[];
  vulns?: VulnFinding[];
}

export interface ProgressEvent {
  scanId: string;
  phase: string;
  completed: number;
  total: number;
  message: string;
}

export interface CompleteEvent {
  scanId: string;
  cancelled: boolean;
  hostsAlive: number;
  hostsTotal: number;
  openPortCount: number;
}

export interface ScanLogEvent {
  scanId: string;
  ts: string;
  level: string;
  message: string;
}

export interface PortFoundEvent {
  scanId: string;
  ip: string;
  hostname?: string | null;
  mac?: string | null;
  manufacturer?: string | null;
  latencyMs?: number | null;
  port: OpenPort;
}

export interface ScanProfile {
  id: string;
  name: string;
  targets: string;
  ports: string;
  useCommonPorts: boolean;
  hostConcurrency: number;
  portConcurrency: number;
  timeoutMs: number;
  useIcmp: boolean;
  scanPorts: boolean;
  scanUdp?: boolean;
  probeAllTargets: boolean;
  identifyServices?: boolean;
  vulnScan?: boolean;
}

export interface ScanFormState {
  targets: string;
  ports: string;
  useCommonPorts: boolean;
  hostConcurrency: number;
  portConcurrency: number;
  timeoutMs: number;
  useIcmp: boolean;
  scanPorts: boolean;
  scanUdp: boolean;
  probeAllTargets: boolean;
  identifyServices: boolean;
  vulnScan: boolean;
  authorized: boolean;
}

export type AppMode = "network" | "ports" | "vuln" | "ping";

export type PortPreset =
  | "extended"
  | "1-1024"
  | "1-10000"
  | "1-65535"
  | "custom";

export interface PortScanFormState {
  targets: string;
  preset: PortPreset;
  customPorts: string;
  hostConcurrency: number;
  portConcurrency: number;
  timeoutMs: number;
  scanUdp: boolean;
  identifyServices: boolean;
  vulnScan: boolean;
  authorized: boolean;
}

export interface VulnScanFormState {
  targets: string;
  hostConcurrency: number;
  portConcurrency: number;
  timeoutMs: number;
  authorized: boolean;
}