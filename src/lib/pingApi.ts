import { invoke } from "@tauri-apps/api/core";

export interface PingSession {
  id: string;
  title: string;
  target: string;
  intervalMs: number;
  tableName: string;
  createdAt: string;
  updatedAt: string;
  running: boolean;
}

export interface PingResultRow {
  id: number;
  sessionId: string;
  ts: string;
  success: boolean;
  latencyMs?: number | null;
  ttl?: number | null;
  message: string;
}

export interface PingStatSummary {
  sessionId: string;
  total: number;
  success: number;
  failed: number;
  dropPercent: number;
  avgLatencyMs?: number | null;
  minLatencyMs?: number | null;
  maxLatencyMs?: number | null;
  lastTs?: string | null;
  lastSuccess?: boolean | null;
}

export interface PingLiveEvent {
  sessionId: string;
  result: PingResultRow;
}

export function pingListSessions(): Promise<PingSession[]> {
  return invoke("ping_list_sessions");
}

export function pingCreateSession(
  title: string,
  target: string,
  intervalMs: number,
): Promise<PingSession> {
  return invoke("ping_create_session", { title, target, intervalMs });
}

export function pingStart(sessionId: string): Promise<void> {
  return invoke("ping_start", { sessionId });
}

export function pingStop(sessionId: string): Promise<boolean> {
  return invoke("ping_stop", { sessionId });
}

export function pingStopAll(): Promise<number> {
  return invoke("ping_stop_all");
}

export function pingListResults(
  sessionId: string,
  limit = 500,
): Promise<PingResultRow[]> {
  return invoke("ping_list_results", { sessionId, limit });
}

export function pingGetStats(sessionId: string): Promise<PingStatSummary> {
  return invoke("ping_get_stats", { sessionId });
}

export function pingClearSession(sessionId: string): Promise<void> {
  return invoke("ping_clear_session", { sessionId });
}

export function pingDeleteSession(sessionId: string): Promise<void> {
  return invoke("ping_delete_session", { sessionId });
}

export function pingClearAll(): Promise<void> {
  return invoke("ping_clear_all");
}

export function pingImportCsv(
  path: string,
  intervalMs: number,
): Promise<PingSession[]> {
  return invoke("ping_import_csv", { path, intervalMs });
}

export function pingExportDb(path: string): Promise<void> {
  return invoke("ping_export_db", { path });
}

export function pingImportDb(path: string): Promise<PingSession[]> {
  return invoke("ping_import_db", { path });
}
