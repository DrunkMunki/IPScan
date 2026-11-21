use crate::audit;
use crate::scan::banner::{apply_service_info, enrich_ports, identify_open_port};
use crate::scan::host::{discover_host, enrich_host_identity, resolve_hostname, HostDiscovery};
use crate::scan::ports::{scan_ports, tick_progress, OpenPort};
use crate::scan::services::{common_ports, discovery_probe_ports};
use crate::scan::targets::{parse_port_spec, parse_targets, validate_against_allowlist};
use crate::scan::udp::{common_udp_ports, scan_udp_ports};
use crate::scan::vuln::{assess_host, VulnFinding};
use futures::stream::{self, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

#[derive(Default)]
pub struct ScanState {
    pub cancelled: Mutex<Option<Arc<AtomicBool>>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub targets: String,
    pub ports: String,
    pub use_common_ports: bool,
    pub allowlist: Vec<String>,
    pub host_concurrency: usize,
    pub port_concurrency: usize,
    pub timeout_ms: u64,
    pub use_icmp: bool,
    pub scan_ports: bool,
    #[serde(default)]
    pub scan_udp: bool,
    pub probe_all_targets: bool,
    /// Lightweight banner / TLS / HTTP service identification after open ports are found.
    #[serde(default)]
    pub identify_services: bool,
    /// Basic vulnerability / exposure checks (best on a single IP).
    #[serde(default)]
    pub vuln_scan: bool,
    pub authorized: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostResult {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub manufacturer: Option<String>,
    pub latency_ms: Option<u64>,
    pub alive: bool,
    pub open_ports: Vec<OpenPort>,
    /// Host summary notes (unique roll-up of notable port notes).
    pub notes: Vec<String>,
    #[serde(default)]
    pub vulns: Vec<VulnFinding>,
}

#[derive(Debug, Clone)]
struct AliveHost {
    ip: IpAddr,
    hostname: Option<String>,
    mac: Option<String>,
    manufacturer: Option<String>,
    latency_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub scan_id: String,
    pub phase: String,
    pub completed: usize,
    pub total: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteEvent {
    pub scan_id: String,
    pub cancelled: bool,
    pub hosts_alive: usize,
    pub hosts_total: usize,
    pub open_port_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanLogEvent {
    pub scan_id: String,
    pub ts: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortFoundEvent {
    pub scan_id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub manufacturer: Option<String>,
    pub latency_ms: Option<u64>,
    pub port: OpenPort,
}

pub fn cancel_scan(state: &ScanState) -> bool {
    if let Some(flag) = state.cancelled.lock().as_ref() {
        flag.store(true, Ordering::Relaxed);
        true
    } else {
        false
    }
}

pub async fn start_scan(
    app: AppHandle,
    state: Arc<ScanState>,
    request: ScanRequest,
) -> Result<String, String> {
    if !request.authorized {
        return Err(
            "You must confirm authorized internal use before starting a scan.".into(),
        );
    }

    {
        let guard = state.cancelled.lock();
        if let Some(flag) = guard.as_ref() {
            if !flag.load(Ordering::Relaxed) {
                return Err("A scan is already running.".into());
            }
        }
    }

    let targets = parse_targets(&request.targets).map_err(|e| e.to_string())?;
    validate_against_allowlist(&targets, &request.allowlist).map_err(|e| e.to_string())?;

    let ports = if request.use_common_ports {
        common_ports()
    } else {
        parse_port_spec(&request.ports).map_err(|e| e.to_string())?
    };

    let scan_id = Uuid::new_v4().to_string();
    let cancelled = Arc::new(AtomicBool::new(false));
    *state.cancelled.lock() = Some(Arc::clone(&cancelled));

    audit::append_entry(&format!(
        "scan_start id={scan_id} targets={} ports={} user={}",
        targets.len(),
        ports.len(),
        whoami()
    ));

    let app2 = app.clone();
    let cancelled2 = Arc::clone(&cancelled);
    let state2 = Arc::clone(&state);
    let scan_id2 = scan_id.clone();

    tauri::async_runtime::spawn(async move {
        let result = run_scan(
            app2.clone(),
            scan_id2.clone(),
            targets,
            ports,
            request,
            cancelled2,
        )
        .await;

        if let Err(err) = result {
            emit_log(&app2, &scan_id2, "warn", &format!("Scan error: {err}"));
            let _ = app2.emit("scan-error", err);
            audit::append_entry(&format!("scan_error id={scan_id2} err"));
        }

        if let Some(flag) = state2.cancelled.lock().as_ref() {
            flag.store(true, Ordering::Relaxed);
        }
    });

    Ok(scan_id)
}

async fn run_scan(
    app: AppHandle,
    scan_id: String,
    targets: Vec<IpAddr>,
    ports: Vec<u16>,
    request: ScanRequest,
    cancelled: Arc<AtomicBool>,
) -> Result<(), String> {
    let total = targets.len();
    let host_concurrency = request.host_concurrency.clamp(1, 512);
    let port_concurrency = request.port_concurrency.clamp(1, 1024);
    let timeout_ms = request.timeout_ms.clamp(100, 10_000);
    let probe_ports = discovery_probe_ports();

    emit_log(
        &app,
        &scan_id,
        "info",
        &format!(
            "Scan started — {total} target(s), {} TCP port(s), host concurrency {host_concurrency}",
            ports.len()
        ),
    );

    let _ = app.emit(
        "scan-progress",
        ProgressEvent {
            scan_id: scan_id.clone(),
            phase: "discovery".into(),
            completed: 0,
            total,
            message: format!("Discovering {total} hosts…"),
        },
    );

    let completed = Arc::new(AtomicUsize::new(0));
    let alive_hosts = Arc::new(Mutex::new(Vec::<AliveHost>::new()));

    stream::iter(targets.clone())
        .for_each_concurrent(host_concurrency, |ip| {
            let app = app.clone();
            let cancelled = Arc::clone(&cancelled);
            let completed = Arc::clone(&completed);
            let alive_hosts = Arc::clone(&alive_hosts);
            let scan_id = scan_id.clone();
            let probe_ports = probe_ports.clone();
            async move {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }

                let discovery = if request.probe_all_targets {
                    emit_log(
                        &app,
                        &scan_id,
                        "info",
                        &format!("Probing {ip} (skip discovery — assume live)"),
                    );
                    let hostname = resolve_hostname(ip, timeout_ms).await;
                    let (mac, manufacturer) = enrich_host_identity(ip).await;
                    Some(HostDiscovery {
                        ip: ip.to_string(),
                        hostname,
                        latency_ms: 0,
                        icmp_ok: false,
                        mac,
                        manufacturer,
                    })
                } else {
                    discover_host(ip, &probe_ports, timeout_ms, request.use_icmp).await
                };

                if let Some(host) = discovery {
                    let parsed: IpAddr = host.ip.parse().unwrap_or(ip);
                    emit_log(
                        &app,
                        &scan_id,
                        "info",
                        &format!(
                            "Host up {ip}{}{}{}",
                            host.hostname
                                .as_ref()
                                .map(|h| format!(" ({h})"))
                                .unwrap_or_default(),
                            host.mac
                                .as_ref()
                                .map(|m| format!(" MAC {m}"))
                                .unwrap_or_default(),
                            if host.latency_ms > 0 {
                                format!(" {}ms", host.latency_ms)
                            } else {
                                String::new()
                            }
                        ),
                    );
                    alive_hosts.lock().push(AliveHost {
                        ip: parsed,
                        hostname: host.hostname.clone(),
                        mac: host.mac.clone(),
                        manufacturer: host.manufacturer.clone(),
                        latency_ms: host.latency_ms,
                    });

                    // Show the host row immediately (ports fill in live).
                    let _ = app.emit(
                        "host-result",
                        HostResult {
                            ip: host.ip.clone(),
                            hostname: host.hostname.clone(),
                            mac: host.mac.clone(),
                            manufacturer: host.manufacturer.clone(),
                            latency_ms: Some(host.latency_ms),
                            alive: true,
                            open_ports: vec![],
                            notes: vec![],
                            vulns: vec![],
                        },
                    );

                    if !request.scan_ports && !request.scan_udp {
                        let _ = app.emit(
                            "host-result",
                            HostResult {
                                ip: host.ip,
                                hostname: host.hostname,
                                mac: host.mac,
                                manufacturer: host.manufacturer,
                                latency_ms: Some(host.latency_ms),
                                alive: true,
                                open_ports: vec![],
                                notes: vec![],
                                vulns: vec![],
                            },
                        );
                    }
                }

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if done % 8 == 0 || done == total {
                    let _ = app.emit(
                        "scan-progress",
                        ProgressEvent {
                            scan_id: scan_id.clone(),
                            phase: "discovery".into(),
                            completed: done,
                            total,
                            message: format!("Discovery {done}/{total}"),
                        },
                    );
                }
            }
        })
        .await;

    if cancelled.load(Ordering::Relaxed) {
        emit_log(&app, &scan_id, "warn", "Scan cancelled during discovery");
        emit_complete(&app, &scan_id, true, 0, total, 0);
        audit::append_entry(&format!("scan_cancelled id={scan_id}"));
        return Ok(());
    }

    let hosts = alive_hosts.lock().clone();
    let hosts_alive = hosts.len();
    emit_log(
        &app,
        &scan_id,
        "info",
        &format!("Discovery done — {hosts_alive}/{total} host(s) up"),
    );

    if !request.scan_ports && !request.scan_udp {
        emit_complete(&app, &scan_id, false, hosts_alive, total, 0);
        audit::append_entry(&format!(
            "scan_complete id={scan_id} alive={hosts_alive} total={total}"
        ));
        return Ok(());
    }

    let udp_ports = if request.scan_udp {
        common_udp_ports()
    } else {
        Vec::new()
    };

    let tcp_work = if request.scan_ports {
        hosts.len().saturating_mul(ports.len())
    } else {
        0
    };
    let udp_work = if request.scan_udp {
        hosts.len().saturating_mul(udp_ports.len())
    } else {
        0
    };
    let work_total = (tcp_work + udp_work).max(1);
    let report_every = ((work_total / 100).max(32)).min(512);

    let phase_label = match (request.scan_ports, request.scan_udp) {
        (true, true) => "tcp+udp".to_string(),
        (false, true) => "udp".to_string(),
        _ => "tcp".to_string(),
    };

    emit_log(
        &app,
        &scan_id,
        "info",
        &format!(
            "Port scan ({phase_label}) — {hosts_alive} host(s), {} TCP + {} UDP probe(s), concurrency {port_concurrency}",
            if request.scan_ports { ports.len() } else { 0 },
            udp_ports.len()
        ),
    );

    let _ = app.emit(
        "scan-progress",
        ProgressEvent {
            scan_id: scan_id.clone(),
            phase: "ports".into(),
            completed: 0,
            total: work_total,
            message: format!(
                "Port scanning ({phase_label}) — 0/{work_total} probes"
            ),
        },
    );

    let ports_checked = Arc::new(AtomicUsize::new(0));
    let open_count = Arc::new(AtomicUsize::new(0));
    let do_tcp = request.scan_ports;
    let do_udp = request.scan_udp;
    let identify = request.identify_services;
    let do_vuln = request.vuln_scan;

    stream::iter(hosts)
        .for_each_concurrent(host_concurrency.min(64), |host| {
            let app = app.clone();
            let cancelled = Arc::clone(&cancelled);
            let ports_checked = Arc::clone(&ports_checked);
            let open_count = Arc::clone(&open_count);
            let scan_id = scan_id.clone();
            let ports = ports.clone();
            let udp_ports = udp_ports.clone();
            let phase_label = phase_label.clone();
            async move {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }

                let ip_str = host.ip.to_string();

                if do_tcp {
                    emit_log(
                        &app,
                        &scan_id,
                        "info",
                        &format!(
                            "TCP scan {ip_str} — {} ports (timeout {timeout_ms}ms)",
                            ports.len()
                        ),
                    );

                    let on_checked = {
                        let app = app.clone();
                        let scan_id = scan_id.clone();
                        let ports_checked = Arc::clone(&ports_checked);
                        let open_count = Arc::clone(&open_count);
                        let ip_str = ip_str.clone();
                        let phase_label = phase_label.clone();
                        Arc::new(move || {
                            tick_progress(&ports_checked, work_total, report_every, |n, total| {
                                let opens = open_count.load(Ordering::Relaxed);
                                let _ = app.emit(
                                    "scan-progress",
                                    ProgressEvent {
                                        scan_id: scan_id.clone(),
                                        phase: "ports".into(),
                                        completed: n.min(total),
                                        total,
                                        message: format!(
                                            "Port scan ({phase_label}) {n}/{total} — {opens} open — {ip_str}"
                                        ),
                                    },
                                );
                            });
                        }) as crate::scan::ports::PortCheckedFn
                    };

                    let on_open = {
                        let app = app.clone();
                        let scan_id = scan_id.clone();
                        let open_count = Arc::clone(&open_count);
                        let host = host.clone();
                        let cancelled = Arc::clone(&cancelled);
                        Arc::new(move |port: OpenPort| {
                            open_count.fetch_add(1, Ordering::Relaxed);
                            let svc = port.service.clone().unwrap_or_else(|| "?".into());
                            emit_log(
                                &app,
                                &scan_id,
                                "open",
                                &format!(
                                    "OPEN {} {}/{} {}",
                                    host.ip, port.protocol, port.port, svc
                                ),
                            );
                            let _ = app.emit(
                                "port-found",
                                PortFoundEvent {
                                    scan_id: scan_id.clone(),
                                    ip: host.ip.to_string(),
                                    hostname: host.hostname.clone(),
                                    mac: host.mac.clone(),
                                    manufacturer: host.manufacturer.clone(),
                                    latency_ms: Some(host.latency_ms),
                                    port: port.clone(),
                                },
                            );

                            if identify && port.protocol == "tcp" && !cancelled.load(Ordering::Relaxed)
                            {
                                let app = app.clone();
                                let scan_id = scan_id.clone();
                                let host = host.clone();
                                let mut port = port;
                                tauri::async_runtime::spawn(async move {
                                    let info = identify_open_port(
                                        host.ip,
                                        port.port,
                                        timeout_ms.max(800),
                                    )
                                    .await;
                                    apply_service_info(&mut port, info);
                                    if let Some(ref banner) = port.banner {
                                        emit_log(
                                            &app,
                                            &scan_id,
                                            "info",
                                            &format!(
                                                "Identified {} TCP/{} — {banner}",
                                                host.ip, port.port
                                            ),
                                        );
                                    }
                                    for note in &port.notes {
                                        if note.contains("SMB version")
                                            || note.contains("HTTP version")
                                            || note.contains("SMBv1")
                                        {
                                            emit_log(
                                                &app,
                                                &scan_id,
                                                "info",
                                                &format!(
                                                    "Note {} TCP/{} — {note}",
                                                    host.ip, port.port
                                                ),
                                            );
                                        }
                                    }
                                    let _ = app.emit(
                                        "port-found",
                                        PortFoundEvent {
                                            scan_id: scan_id.clone(),
                                            ip: host.ip.to_string(),
                                            hostname: host.hostname.clone(),
                                            mac: host.mac.clone(),
                                            manufacturer: host.manufacturer.clone(),
                                            latency_ms: Some(host.latency_ms),
                                            port,
                                        },
                                    );
                                });
                            }
                        }) as crate::scan::ports::PortOpenFn
                    };

                    let mut open_ports = scan_ports(
                        host.ip,
                        &ports,
                        timeout_ms,
                        port_concurrency,
                        Arc::clone(&cancelled),
                        Some(on_checked),
                        Some(on_open),
                    )
                    .await;

                    if identify && !open_ports.is_empty() && !cancelled.load(Ordering::Relaxed) {
                        // Final pass fills any banners that async identify missed / races.
                        emit_log(
                            &app,
                            &scan_id,
                            "info",
                            &format!(
                                "Service identify pass on {ip_str} ({} open TCP)",
                                open_ports.iter().filter(|p| p.protocol == "tcp").count()
                            ),
                        );
                        enrich_ports(host.ip, &mut open_ports, timeout_ms.max(800)).await;
                    }

                    if do_udp && !cancelled.load(Ordering::Relaxed) {
                        emit_log(
                            &app,
                            &scan_id,
                            "info",
                            &format!("UDP probe {ip_str} — {} common services", udp_ports.len()),
                        );
                        let udp_timeout = timeout_ms.max(500);
                        let on_checked = {
                            let app = app.clone();
                            let scan_id = scan_id.clone();
                            let ports_checked = Arc::clone(&ports_checked);
                            let open_count = Arc::clone(&open_count);
                            let ip_str = ip_str.clone();
                            let phase_label = phase_label.clone();
                            Arc::new(move || {
                                tick_progress(&ports_checked, work_total, report_every, |n, total| {
                                    let opens = open_count.load(Ordering::Relaxed);
                                    let _ = app.emit(
                                        "scan-progress",
                                        ProgressEvent {
                                            scan_id: scan_id.clone(),
                                            phase: "ports".into(),
                                            completed: n.min(total),
                                            total,
                                            message: format!(
                                                "Port scan ({phase_label}) {n}/{total} — {opens} open — {ip_str}"
                                            ),
                                        },
                                    );
                                });
                            }) as crate::scan::ports::PortCheckedFn
                        };
                        let on_open = {
                            let app = app.clone();
                            let scan_id = scan_id.clone();
                            let open_count = Arc::clone(&open_count);
                            let host = host.clone();
                            Arc::new(move |port: OpenPort| {
                                open_count.fetch_add(1, Ordering::Relaxed);
                                let svc = port.service.clone().unwrap_or_else(|| "?".into());
                                emit_log(
                                    &app,
                                    &scan_id,
                                    "open",
                                    &format!(
                                        "OPEN {} {}/{} {}",
                                        host.ip, port.protocol, port.port, svc
                                    ),
                                );
                                let _ = app.emit(
                                    "port-found",
                                    PortFoundEvent {
                                        scan_id: scan_id.clone(),
                                        ip: host.ip.to_string(),
                                        hostname: host.hostname.clone(),
                                        mac: host.mac.clone(),
                                        manufacturer: host.manufacturer.clone(),
                                        latency_ms: Some(host.latency_ms),
                                        port,
                                    },
                                );
                            }) as crate::scan::ports::PortOpenFn
                        };

                        let udp_found = scan_udp_ports(
                            host.ip,
                            &udp_ports,
                            udp_timeout,
                            port_concurrency.min(32),
                            Arc::clone(&cancelled),
                            Some(on_checked),
                            Some(on_open),
                        )
                        .await;
                        open_ports.extend(udp_found);
                    }

                    let notes = host_summary_notes(&open_ports);
                    let mut vulns = Vec::new();
                    if do_vuln && !cancelled.load(Ordering::Relaxed) {
                        emit_log(
                            &app,
                            &scan_id,
                            "info",
                            &format!("Vulnerability checks on {ip_str}…"),
                        );
                        vulns = assess_host(host.ip, &open_ports, timeout_ms.max(800)).await;
                        for v in &vulns {
                            emit_log(
                                &app,
                                &scan_id,
                                "warn",
                                &format!(
                                    "[{}] {}{} — {}",
                                    v.severity.to_uppercase(),
                                    v.title,
                                    v.port
                                        .map(|p| format!(" (port {p})"))
                                        .unwrap_or_default(),
                                    v.detail
                                ),
                            );
                        }
                        emit_log(
                            &app,
                            &scan_id,
                            "info",
                            &format!(
                                "Vulnerability checks done on {ip_str} — {} finding(s)",
                                vulns.len()
                            ),
                        );
                    }

                    emit_log(
                        &app,
                        &scan_id,
                        "info",
                        &format!(
                            "Finished {ip_str} — {} open port(s)",
                            open_ports.len()
                        ),
                    );

                    let _ = app.emit(
                        "host-result",
                        HostResult {
                            ip: ip_str,
                            hostname: host.hostname,
                            mac: host.mac,
                            manufacturer: host.manufacturer,
                            latency_ms: Some(host.latency_ms),
                            alive: true,
                            open_ports,
                            notes,
                            vulns,
                        },
                    );
                } else if do_udp {
                    // UDP-only path
                    emit_log(
                        &app,
                        &scan_id,
                        "info",
                        &format!("UDP probe {ip_str} — {} common services", udp_ports.len()),
                    );
                    let udp_timeout = timeout_ms.max(500);
                    let on_checked = {
                        let app = app.clone();
                        let scan_id = scan_id.clone();
                        let ports_checked = Arc::clone(&ports_checked);
                        let open_count = Arc::clone(&open_count);
                        let ip_str = ip_str.clone();
                        let phase_label = phase_label.clone();
                        Arc::new(move || {
                            tick_progress(&ports_checked, work_total, report_every, |n, total| {
                                let opens = open_count.load(Ordering::Relaxed);
                                let _ = app.emit(
                                    "scan-progress",
                                    ProgressEvent {
                                        scan_id: scan_id.clone(),
                                        phase: "ports".into(),
                                        completed: n.min(total),
                                        total,
                                        message: format!(
                                            "Port scan ({phase_label}) {n}/{total} — {opens} open — {ip_str}"
                                        ),
                                    },
                                );
                            });
                        }) as crate::scan::ports::PortCheckedFn
                    };
                    let on_open = {
                        let app = app.clone();
                        let scan_id = scan_id.clone();
                        let open_count = Arc::clone(&open_count);
                        let host = host.clone();
                        Arc::new(move |port: OpenPort| {
                            open_count.fetch_add(1, Ordering::Relaxed);
                            emit_log(
                                &app,
                                &scan_id,
                                "open",
                                &format!(
                                    "OPEN {} {}/{} {}",
                                    host.ip,
                                    port.protocol,
                                    port.port,
                                    port.service.clone().unwrap_or_else(|| "?".into())
                                ),
                            );
                            let _ = app.emit(
                                "port-found",
                                PortFoundEvent {
                                    scan_id: scan_id.clone(),
                                    ip: host.ip.to_string(),
                                    hostname: host.hostname.clone(),
                                    mac: host.mac.clone(),
                                    manufacturer: host.manufacturer.clone(),
                                    latency_ms: Some(host.latency_ms),
                                    port,
                                },
                            );
                        }) as crate::scan::ports::PortOpenFn
                    };

                    let open_ports = scan_udp_ports(
                        host.ip,
                        &udp_ports,
                        udp_timeout,
                        port_concurrency.min(32),
                        Arc::clone(&cancelled),
                        Some(on_checked),
                        Some(on_open),
                    )
                    .await;
                    let notes = host_summary_notes(&open_ports);
                    let mut vulns = Vec::new();
                    if do_vuln && !cancelled.load(Ordering::Relaxed) {
                        vulns = assess_host(host.ip, &open_ports, timeout_ms.max(800)).await;
                    }
                    let _ = app.emit(
                        "host-result",
                        HostResult {
                            ip: ip_str,
                            hostname: host.hostname,
                            mac: host.mac,
                            manufacturer: host.manufacturer,
                            latency_ms: Some(host.latency_ms),
                            alive: true,
                            open_ports,
                            notes,
                            vulns,
                        },
                    );
                }
            }
        })
        .await;

    let cancelled_flag = cancelled.load(Ordering::Relaxed);
    let open_port_count = open_count.load(Ordering::Relaxed);

    // Snap progress bar to 100% when finished (unless cancelled mid-way).
    if !cancelled_flag {
        let _ = app.emit(
            "scan-progress",
            ProgressEvent {
                scan_id: scan_id.clone(),
                phase: "ports".into(),
                completed: work_total,
                total: work_total,
                message: format!(
                    "Port scan complete — {open_port_count} open port(s) on {hosts_alive} host(s)"
                ),
            },
        );
    }

    emit_log(
        &app,
        &scan_id,
        if cancelled_flag { "warn" } else { "info" },
        &format!(
            "{} — {open_port_count} open port(s), {hosts_alive}/{total} hosts",
            if cancelled_flag {
                "Scan cancelled"
            } else {
                "Scan complete"
            }
        ),
    );

    emit_complete(
        &app,
        &scan_id,
        cancelled_flag,
        hosts_alive,
        total,
        open_port_count,
    );
    audit::append_entry(&format!(
        "scan_complete id={scan_id} alive={hosts_alive} total={total} open_ports={open_port_count} cancelled={cancelled_flag}"
    ));
    Ok(())
}

fn emit_log(app: &AppHandle, scan_id: &str, level: &str, message: &str) {
    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
    let _ = app.emit(
        "scan-log",
        ScanLogEvent {
            scan_id: scan_id.to_string(),
            ts,
            level: level.to_string(),
            message: message.to_string(),
        },
    );
}

fn emit_complete(
    app: &AppHandle,
    scan_id: &str,
    cancelled: bool,
    hosts_alive: usize,
    hosts_total: usize,
    open_port_count: usize,
) {
    let _ = app.emit(
        "scan-complete",
        CompleteEvent {
            scan_id: scan_id.to_string(),
            cancelled,
            hosts_alive,
            hosts_total,
            open_port_count,
        },
    );
}

/// Compact host-level roll-up for the summary table (not repeated on every CSV port row).
fn host_summary_notes(ports: &[OpenPort]) -> Vec<String> {
    let mut notes = Vec::new();
    for p in ports {
        for n in &p.notes {
            // Prefer short exposure tags on the host summary.
            if matches!(
                n.as_str(),
                "SMB exposed"
                    | "RDP exposed"
                    | "Telnet exposed"
                    | "FTP exposed"
                    | "VNC exposed"
                    | "WinRM exposed"
                    | "SNMP exposed"
                    | "NetBIOS-NS exposed"
                    | "TFTP exposed"
            ) || n.contains("SMBv1")
            {
                if !notes.iter().any(|x| x == n) {
                    notes.push(n.clone());
                }
            }
        }
    }
    notes
}

fn whoami() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into())
}
