use crate::scan::services::service_name;
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPort {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Port-specific risk / info notes (not host-wide).
    #[serde(default)]
    pub notes: Vec<String>,
}

pub type PortCheckedFn = Arc<dyn Fn() + Send + Sync>;
pub type PortOpenFn = Arc<dyn Fn(OpenPort) + Send + Sync>;

pub async fn scan_ports(
    ip: IpAddr,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
    cancelled: Arc<AtomicBool>,
    on_checked: Option<PortCheckedFn>,
    on_open: Option<PortOpenFn>,
) -> Vec<OpenPort> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let timeout_ms = timeout_ms.max(50);
    let open_ports = Arc::new(parking_lot::Mutex::new(Vec::<OpenPort>::new()));

    stream::iter(ports.iter().copied())
        .for_each_concurrent(concurrency.max(1), |port| {
            let sem = Arc::clone(&sem);
            let cancelled = Arc::clone(&cancelled);
            let on_checked = on_checked.clone();
            let on_open = on_open.clone();
            let open_ports = Arc::clone(&open_ports);
            async move {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(_permit) = sem.acquire().await else {
                    return;
                };
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                let addr = SocketAddr::new(ip, port);
                let ok = matches!(
                    timeout(
                        Duration::from_millis(timeout_ms),
                        TcpStream::connect(addr)
                    )
                    .await,
                    Ok(Ok(_))
                );
                drop(_permit);

                if let Some(cb) = on_checked.as_ref() {
                    cb();
                }

                if ok {
                    let found = OpenPort {
                        port,
                        protocol: "tcp".into(),
                        service: service_name(port).map(|s| s.to_string()),
                        product: None,
                        version: None,
                        banner: None,
                        notes: port_risk_notes(port, "tcp"),
                    };
                    if let Some(cb) = on_open.as_ref() {
                        cb(found.clone());
                    }
                    open_ports.lock().push(found);
                }
            }
        })
        .await;

    let mut result = open_ports.lock().clone();
    result.sort_by_key(|p| p.port);
    result
}

/// Risk notes that apply only to this specific port.
pub fn port_risk_notes(port: u16, protocol: &str) -> Vec<String> {
    let mut notes = Vec::new();
    if protocol == "tcp" {
        match port {
            21 => notes.push("FTP exposed".into()),
            23 => notes.push("Telnet exposed".into()),
            139 | 445 => notes.push("SMB exposed".into()),
            3389 => notes.push("RDP exposed".into()),
            5900 | 5901 => notes.push("VNC exposed".into()),
            5985 | 5986 => notes.push("WinRM exposed".into()),
            _ => {}
        }
    } else if protocol == "udp" {
        match port {
            69 => notes.push("TFTP exposed".into()),
            137 => notes.push("NetBIOS-NS exposed".into()),
            161 => notes.push("SNMP exposed".into()),
            _ => {}
        }
    }
    notes
}

/// Shared counter helper for port-level progress reporting.
pub fn tick_progress(
    checked: &AtomicUsize,
    total: usize,
    report_every: usize,
    mut emit: impl FnMut(usize, usize),
) {
    let n = checked.fetch_add(1, Ordering::Relaxed) + 1;
    let every = report_every.max(1);
    if n == 1 || n == total || n % every == 0 {
        emit(n, total);
    }
}
