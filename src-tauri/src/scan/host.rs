use crate::scan::localnet::is_on_local_subnet;
use crate::scan::mac::{arp_probe_rtt, lookup_mac};
use crate::scan::netbios::lookup_netbios_name;
use crate::scan::oui::lookup_manufacturer;
use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

/// Probe whether a host appears alive via ARP (LAN), ICMP, and/or TCP probes.
pub async fn discover_host(
    ip: IpAddr,
    probe_ports: &[u16],
    timeout_ms: u64,
    use_icmp: bool,
) -> Option<HostDiscovery> {
    let mut alive = false;
    let mut icmp_ok = false;
    let mut latency_ms: Option<u64> = None;

    // Same-subnet: ARP first — more accurate when ICMP is firewalled.
    if is_on_local_subnet(ip) {
        if let Some(rtt) = arp_probe_rtt(ip).await {
            alive = true;
            latency_ms = Some(rtt);
        }
    }

    if !alive && use_icmp {
        if let Some(rtt) = icmp_ping_rtt(ip, timeout_ms).await {
            icmp_ok = true;
            alive = true;
            latency_ms = Some(rtt);
        }
    }

    if !alive {
        for port in probe_ports {
            if let Some(rtt) = tcp_probe_rtt(ip, *port, timeout_ms).await {
                alive = true;
                latency_ms = Some(rtt);
                break;
            }
        }
    }

    if !alive {
        return None;
    }

    let hostname = resolve_hostname(ip, timeout_ms).await;
    let (mac, manufacturer) = resolve_mac_vendor(ip).await;

    Some(HostDiscovery {
        ip: ip.to_string(),
        hostname,
        latency_ms: latency_ms.unwrap_or(0),
        icmp_ok,
        mac,
        manufacturer,
    })
}

/// Enrich a known-alive host with MAC + manufacturer (local L2 only for MAC).
pub async fn enrich_host_identity(ip: IpAddr) -> (Option<String>, Option<String>) {
    resolve_mac_vendor(ip).await
}

/// Reverse DNS, then NetBIOS name fallback for Windows estates.
pub async fn resolve_hostname(ip: IpAddr, timeout_ms: u64) -> Option<String> {
    if let Some(name) = reverse_dns(ip).await {
        if !name.is_empty() {
            return Some(name);
        }
    }
    lookup_netbios_name(ip, timeout_ms).await
}

async fn resolve_mac_vendor(ip: IpAddr) -> (Option<String>, Option<String>) {
    let mac = lookup_mac(ip).await;
    let manufacturer = mac.as_deref().and_then(lookup_manufacturer);
    (mac, manufacturer)
}

async fn tcp_probe_rtt(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<u64> {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Some(started.elapsed().as_millis() as u64),
        _ => None,
    }
}

/// Single ICMP echo; returns parsed RTT in ms when the host replies.
async fn icmp_ping_rtt(ip: IpAddr, timeout_ms: u64) -> Option<u64> {
    let mut cmd = Command::new("ping");

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.args(["-n", "1", "-w", &timeout_ms.to_string(), &ip.to_string()]);
    }

    #[cfg(not(windows))]
    {
        let secs = ((timeout_ms + 999) / 1000).max(1).to_string();
        cmd.args(["-c", "1", "-W", &secs, &ip.to_string()]);
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let started = Instant::now();
    let output = timeout(Duration::from_millis(timeout_ms + 800), cmd.output())
        .await
        .ok()?
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    if let Some(rtt) = parse_ping_rtt_ms(&text) {
        return Some(rtt);
    }

    Some(started.elapsed().as_millis() as u64)
}

fn parse_ping_rtt_ms(output: &str) -> Option<u64> {
    for token in output.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("time=") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(ms) = digits.parse::<u64>() {
                return Some(ms);
            }
        }
        if lower.starts_with("time<") {
            return Some(1);
        }
    }

    let lower = output.to_ascii_lowercase();
    if let Some(idx) = lower.find("time=") {
        let rest = &lower[idx + 5..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(ms) = digits.parse::<u64>() {
            return Some(ms);
        }
    }
    if lower.contains("time<1ms") || lower.contains("time<1 ms") {
        return Some(1);
    }
    None
}

async fn reverse_dns(ip: IpAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
        .await
        .ok()
        .flatten()
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostDiscovery {
    pub ip: String,
    pub hostname: Option<String>,
    pub latency_ms: u64,
    pub icmp_ok: bool,
    pub mac: Option<String>,
    pub manufacturer: Option<String>,
}
