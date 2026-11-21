use crate::scan::ports::{PortCheckedFn, PortOpenFn};
use crate::scan::services::udp_service_name;
use futures::stream::{self, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use super::ports::OpenPort;

/// Common UDP services that often reply to a small probe payload.
pub fn common_udp_ports() -> Vec<u16> {
    // Intentionally omit DHCP(67) — discover probes can be disruptive on LAN.
    vec![53, 69, 123, 137, 161, 500, 1434, 1900, 5353, 11211]
}

pub async fn scan_udp_ports(
    ip: IpAddr,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
    cancelled: Arc<AtomicBool>,
    on_checked: Option<PortCheckedFn>,
    on_open: Option<PortOpenFn>,
) -> Vec<OpenPort> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1).min(64)));
    let timeout_ms = timeout_ms.clamp(200, 5_000);
    let open_ports = Arc::new(parking_lot::Mutex::new(Vec::<OpenPort>::new()));
    let conc = concurrency.max(1).min(64);

    stream::iter(ports.iter().copied())
        .for_each_concurrent(conc, |port| {
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
                let open = udp_probe(ip, port, timeout_ms).await;
                drop(_permit);

                if let Some(cb) = on_checked.as_ref() {
                    cb();
                }

                if open {
                    let found = OpenPort {
                        port,
                        protocol: "udp".into(),
                        service: udp_service_name(port).map(|s| s.to_string()),
                        product: None,
                        version: None,
                        banner: None,
                        notes: crate::scan::ports::port_risk_notes(port, "udp"),
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

/// Returns true only when the target sends a UDP reply (confirmed open).
/// Timeouts are treated as closed/filtered and are not reported.
async fn udp_probe(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let bind_addr = match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let Ok(sock) = UdpSocket::bind(bind_addr).await else {
        return false;
    };
    let target = SocketAddr::new(ip, port);
    if sock.connect(target).await.is_err() {
        return false;
    }

    let payload = udp_payload(port);
    if sock.send(&payload).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 2048];
    matches!(
        timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf)).await,
        Ok(Ok(n)) if n > 0
    )
}

fn udp_payload(port: u16) -> Vec<u8> {
    match port {
        53 | 5353 => dns_query_payload(),
        67 => dhcp_discover_lite(),
        69 => tftp_read_request(),
        123 => ntp_client_payload(),
        137 => netbios_stat_payload(),
        161 => snmp_get_sysdescr(),
        500 => ike_sa_init_lite(),
        1434 => b"\x02".to_vec(), // SQL Server Browser
        1900 => ssdp_msearch().into_bytes(),
        11211 => b"stats\r\n".to_vec(),
        _ => b"\0".to_vec(),
    }
}

fn dns_query_payload() -> Vec<u8> {
    // Query: A? localhost.  (works for DNS and often mDNS responders)
    let mut p = Vec::with_capacity(32);
    p.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    p.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // QNAME localhost
    p.push(9);
    p.extend_from_slice(b"localhost");
    p.push(0);
    p.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    p.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    p
}

fn ntp_client_payload() -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 0x1b; // LI=0, VN=3, Mode=3 (client)
    p
}

fn snmp_get_sysdescr() -> Vec<u8> {
    // SNMPv1 GetRequest, community "public", OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    vec![
        0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x1c,
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
        0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ]
}

fn netbios_stat_payload() -> Vec<u8> {
    // NBSTAT query for "*"
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&0x0001u16.to_be_bytes()); // TID
    p.extend_from_slice(&0x0000u16.to_be_bytes()); // Flags
    p.extend_from_slice(&1u16.to_be_bytes()); // Questions
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    // Encoded name "*"
    p.push(32);
    p.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    p.push(0);
    p.extend_from_slice(&0x0021u16.to_be_bytes()); // NBSTAT
    p.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    p
}

fn ssdp_msearch() -> String {
    "M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: ssdp:all\r\n\
\r\n"
        .to_string()
}

fn tftp_read_request() -> Vec<u8> {
    // RRQ "ipscan" netascii — error reply still proves the service is open
    let mut p = vec![0x00, 0x01];
    p.extend_from_slice(b"ipscan");
    p.push(0);
    p.extend_from_slice(b"netascii");
    p.push(0);
    p
}

fn dhcp_discover_lite() -> Vec<u8> {
    // Minimal DHCP-ish bootp payload; many servers ignore, some reply
    let mut p = vec![0u8; 244];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // Ethernet
    p[2] = 6; // hw len
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    p[240] = 53; // DHCP Message Type
    p[241] = 1;
    p[242] = 1; // Discover
    p[243] = 255; // End
    p
}

fn ike_sa_init_lite() -> Vec<u8> {
    // Tiny non-compliant IKE header — rarely answered, harmless
    let mut p = vec![0u8; 28];
    p[16] = 0x20; // Next payload
    p[17] = 0x10; // Version 1.0-ish
    p[18] = 0x22; // Exchange type
    p
}
