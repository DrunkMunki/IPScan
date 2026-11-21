//! Lightweight vulnerability / exposure checks (clean-room).
//! Inspired by the *role* of OpenVAS — not a fork and not linked to Greenbone feeds.

use crate::scan::ports::OpenPort;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnFinding {
    pub ip: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

/// Run basic checks against already-discovered open ports on one host.
pub async fn assess_host(ip: IpAddr, ports: &[OpenPort], timeout_ms: u64) -> Vec<VulnFinding> {
    let timeout_ms = timeout_ms.clamp(300, 5_000);
    let mut findings = Vec::new();
    let ip_str = ip.to_string();

    for p in ports {
        if p.protocol != "tcp" {
            // UDP SNMP already noted at discover time when it replied.
            if p.protocol == "udp" && p.port == 161 {
                findings.push(finding(
                    &ip_str,
                    Some(p.port),
                    "udp",
                    "medium",
                    "SNMP service replies",
                    "UDP/161 responded to a probe — verify community strings are not public/default.",
                ));
            }
            continue;
        }

        match p.port {
            21 => {
                findings.push(finding(
                    &ip_str,
                    Some(21),
                    "tcp",
                    "medium",
                    "FTP exposed",
                    "Cleartext FTP is reachable. Prefer SFTP/FTPS and disable anonymous access.",
                ));
                if let Some(anon) = check_ftp_anonymous(ip, timeout_ms).await {
                    findings.push(anon);
                }
            }
            23 => findings.push(finding(
                &ip_str,
                Some(23),
                "tcp",
                "high",
                "Telnet exposed",
                "Telnet transmits credentials in cleartext. Replace with SSH.",
            )),
            139 | 445 => {
                let sev = if p
                    .notes
                    .iter()
                    .any(|n| n.to_ascii_lowercase().contains("smbv1"))
                {
                    "high"
                } else {
                    "medium"
                };
                let detail = match (&p.version, &p.banner) {
                    (Some(v), Some(b)) => format!("SMB {v} reachable ({b}). Restrict to trusted networks; require signing."),
                    (Some(v), None) => format!("SMB {v} reachable. Restrict to trusted networks; require signing."),
                    _ => "SMB/CIFS is reachable. Restrict to trusted networks; require signing.".into(),
                };
                findings.push(finding(
                    &ip_str,
                    Some(p.port),
                    "tcp",
                    sev,
                    "SMB exposed",
                    &detail,
                ));
                if p.notes.iter().any(|n| n.to_ascii_lowercase().contains("smbv1")) {
                    findings.push(finding(
                        &ip_str,
                        Some(p.port),
                        "tcp",
                        "high",
                        "SMBv1 enabled",
                        "SMBv1 is obsolete and associated with serious historical vulnerabilities (e.g. EternalBlue-class). Disable SMBv1.",
                    ));
                }
                if p.notes.iter().any(|n| n.contains("signing not required")) {
                    findings.push(finding(
                        &ip_str,
                        Some(p.port),
                        "tcp",
                        "medium",
                        "SMB signing not required",
                        "Without mandatory signing, SMB sessions may be susceptible to relay/MitM on local networks.",
                    ));
                }
            }
            3389 => findings.push(finding(
                &ip_str,
                Some(3389),
                "tcp",
                "medium",
                "RDP exposed",
                "Remote Desktop is reachable. Limit source IPs, require NLA, and prefer VPN/bastion access.",
            )),
            5900 | 5901 => findings.push(finding(
                &ip_str,
                Some(p.port),
                "tcp",
                "medium",
                "VNC exposed",
                "VNC is often weakly authenticated. Restrict access and prefer SSH tunnels.",
            )),
            6379 => {
                if check_redis_unauth(ip, timeout_ms).await {
                    findings.push(finding(
                        &ip_str,
                        Some(6379),
                        "tcp",
                        "high",
                        "Redis without AUTH",
                        "Redis answered PING without authentication.",
                    ));
                }
            }
            9200 => {
                if check_http_path(ip, p.port, false, "/_cat/health", timeout_ms)
                    .await
                    .is_some()
                {
                    findings.push(finding(
                        &ip_str,
                        Some(9200),
                        "tcp",
                        "high",
                        "Elasticsearch API open",
                        "Elasticsearch health endpoint responded without auth.",
                    ));
                }
            }
            27017 => findings.push(finding(
                &ip_str,
                Some(27017),
                "tcp",
                "medium",
                "MongoDB port open",
                "Verify authentication is enabled and binding is not 0.0.0.0 without controls.",
            )),
            _ => {}
        }

        // HTTP(S) checks driven by service label / product notes.
        let svc = p.service.as_deref().unwrap_or("");
        if svc.starts_with("http") {
            let https = svc.contains("https") || matches!(p.port, 443 | 8443 | 9443);
            if p.notes.iter().any(|n| n.contains("version disclosed")) {
                findings.push(finding(
                    &ip_str,
                    Some(p.port),
                    "tcp",
                    "low",
                    "HTTP server version disclosed",
                    p.notes
                        .iter()
                        .find(|n| n.contains("version disclosed"))
                        .map(|s| s.as_str())
                        .unwrap_or("Server header exposes product/version."),
                ));
            }
            if p.notes.iter().any(|n| n.contains("directory listing")) {
                findings.push(finding(
                    &ip_str,
                    Some(p.port),
                    "tcp",
                    "medium",
                    "HTTP directory listing",
                    "Web server appears to allow directory indexes.",
                ));
            }
            if let Some(body) = check_http_path(ip, p.port, https, "/", timeout_ms).await {
                if body.to_ascii_lowercase().contains("index of /") {
                    findings.push(finding(
                        &ip_str,
                        Some(p.port),
                        "tcp",
                        "medium",
                        "HTTP directory listing",
                        "Root path returned an directory index page.",
                    ));
                }
            }
        }
    }

    // De-dup by title+port
    findings.sort_by(|a, b| {
        (&a.port, &a.title).cmp(&(&b.port, &b.title))
    });
    findings.dedup_by(|a, b| a.port == b.port && a.title == b.title);
    findings
}

fn finding(
    ip: &str,
    port: Option<u16>,
    protocol: &str,
    severity: &str,
    title: &str,
    detail: &str,
) -> VulnFinding {
    VulnFinding {
        ip: ip.to_string(),
        port,
        protocol: Some(protocol.into()),
        severity: severity.into(),
        title: title.into(),
        detail: detail.into(),
    }
}

async fn check_ftp_anonymous(ip: IpAddr, timeout_ms: u64) -> Option<VulnFinding> {
    let mut stream = connect(ip, 21, timeout_ms).await?;
    let mut buf = vec![0u8; 512];
    let _ = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await;
    let _ = timeout(
        Duration::from_millis(timeout_ms),
        stream.write_all(b"USER anonymous\r\n"),
    )
    .await;
    let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    if text.starts_with("331") || text.starts_with("230") {
        let _ = timeout(
            Duration::from_millis(timeout_ms),
            stream.write_all(b"PASS anonymous@\r\n"),
        )
        .await;
        let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        let text = String::from_utf8_lossy(&buf[..n]);
        if text.starts_with("230") {
            return Some(finding(
                &ip.to_string(),
                Some(21),
                "tcp",
                "high",
                "FTP anonymous login allowed",
                "Server accepted anonymous USER/PASS.",
            ));
        }
    }
    None
}

async fn check_redis_unauth(ip: IpAddr, timeout_ms: u64) -> bool {
    let Some(mut stream) = connect(ip, 6379, timeout_ms).await else {
        return false;
    };
    if timeout(
        Duration::from_millis(timeout_ms),
        stream.write_all(b"PING\r\n"),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .is_none()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).contains("+PONG"),
        _ => false,
    }
}

async fn check_http_path(
    ip: IpAddr,
    port: u16,
    https: bool,
    path: &str,
    timeout_ms: u64,
) -> Option<String> {
    if https {
        return None; // keep TLS path light; banner phase already inspected HTTPS
    }
    let mut stream = connect(ip, port, timeout_ms).await?;
    let host = match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{v}]"),
    };
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: IPScan/0.1\r\nConnection: close\r\n\r\n"
    );
    timeout(
        Duration::from_millis(timeout_ms),
        stream.write_all(req.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while buf.len() < 4096 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

async fn connect(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()
}
