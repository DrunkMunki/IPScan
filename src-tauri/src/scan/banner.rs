//! Lightweight service identification (connect-scan banner / TLS / HTTP).
//! Clean-room probes — not derived from nmap-service-probes.

use crate::scan::ports::OpenPort;
use crate::scan::services::service_name;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default)]
pub struct ServiceInfo {
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub notes: Vec<String>,
}

/// Enrich an already-open TCP port with banner / TLS / HTTP / SMB details.
pub async fn identify_open_port(ip: IpAddr, port: u16, timeout_ms: u64) -> ServiceInfo {
    let timeout_ms = timeout_ms.clamp(200, 5_000);
    let mut info = ServiceInfo {
        service: service_name(port).map(|s| s.to_string()),
        ..Default::default()
    };

    if looks_like_smb_port(port, info.service.as_deref()) {
        if let Some(smb_info) = probe_smb(ip, port, timeout_ms).await {
            merge(&mut info, smb_info);
            return info;
        }
    }

    if looks_like_tls_port(port, info.service.as_deref()) {
        if let Some(tls_info) = probe_tls_http(ip, port, timeout_ms).await {
            merge(&mut info, tls_info);
            return info;
        }
    }

    if looks_like_http_port(port, info.service.as_deref()) {
        if let Some(http_info) = probe_http(ip, port, timeout_ms).await {
            merge(&mut info, http_info);
            return info;
        }
    }

    if let Some(banner_info) = probe_greeting(ip, port, timeout_ms).await {
        merge(&mut info, banner_info);
        return info;
    }

    // Last resort: try HTTP even on unknown ports (catches alt HTTP like 81).
    if info.service.is_none() {
        if let Some(http_info) = probe_http(ip, port, timeout_ms).await {
            merge(&mut info, http_info);
        }
    }

    info
}

pub async fn enrich_ports(
    ip: IpAddr,
    ports: &mut [OpenPort],
    timeout_ms: u64,
) {
    for port in ports.iter_mut() {
        if port.protocol != "tcp" {
            continue;
        }
        let info = identify_open_port(ip, port.port, timeout_ms).await;
        apply_service_info(port, info);
    }
}

pub fn apply_service_info(port: &mut OpenPort, info: ServiceInfo) {
    if let Some(s) = info.service {
        port.service = Some(s);
    }
    if info.product.is_some() {
        port.product = info.product;
    }
    if info.version.is_some() {
        port.version = info.version;
    }
    if info.banner.is_some() {
        port.banner = info.banner;
    }
    for note in info.notes {
        if !port.notes.iter().any(|n| n == &note) {
            port.notes.push(note);
        }
    }
}

fn merge(dst: &mut ServiceInfo, src: ServiceInfo) {
    if src.service.is_some() {
        dst.service = src.service;
    }
    if src.product.is_some() {
        dst.product = src.product;
    }
    if src.version.is_some() {
        dst.version = src.version;
    }
    if src.banner.is_some() {
        dst.banner = src.banner;
    }
    for note in src.notes {
        if !dst.notes.iter().any(|n| n == &note) {
            dst.notes.push(note);
        }
    }
}

fn looks_like_smb_port(port: u16, service: Option<&str>) -> bool {
    matches!(port, 139 | 445)
        || service
            .map(|s| matches!(s, "smb" | "microsoft-ds" | "netbios-ssn"))
            .unwrap_or(false)
}

fn looks_like_tls_port(port: u16, service: Option<&str>) -> bool {
    matches!(
        port,
        443 | 465 | 636 | 993 | 995 | 8443 | 9443 | 10443
    ) || service
        .map(|s| {
            matches!(
                s,
                "https" | "https-alt" | "smtps" | "imaps" | "pop3s" | "ldaps"
            )
        })
        .unwrap_or(false)
}

fn looks_like_http_port(port: u16, service: Option<&str>) -> bool {
    matches!(
        port,
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8088 | 8888 | 9000 | 9080 | 9090
    ) || service
        .map(|s| s.starts_with("http"))
        .unwrap_or(false)
}

async fn connect(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()
}

async fn read_some(stream: &mut TcpStream, timeout_ms: u64, max: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max.min(4096)];
    match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.truncate(n);
            buf
        }
        _ => Vec::new(),
    }
}

fn sanitize_banner(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
        .collect();
    let trimmed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.len() > 200 {
        format!("{}…", &trimmed[..197])
    } else {
        trimmed
    }
}

async fn probe_greeting(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<ServiceInfo> {
    let mut stream = connect(ip, port, timeout_ms).await?;
    let data = read_some(&mut stream, timeout_ms, 1024).await;
    if data.is_empty() {
        // Active probe for protocols that wait for client first.
        let _ = timeout(
            Duration::from_millis(timeout_ms / 2),
            stream.write_all(b"\r\n"),
        )
        .await;
        let data = read_some(&mut stream, timeout_ms, 1024).await;
        if data.is_empty() {
            return None;
        }
        return parse_greeting(port, &data);
    }
    parse_greeting(port, &data)
}

fn parse_greeting(port: u16, data: &[u8]) -> Option<ServiceInfo> {
    let text = String::from_utf8_lossy(data);
    let first_line = text.lines().next().unwrap_or("").trim();
    if first_line.is_empty() {
        return None;
    }
    let banner = sanitize_banner(first_line);
    let lower = first_line.to_ascii_lowercase();

    let mut info = ServiceInfo {
        banner: Some(banner.clone()),
        ..Default::default()
    };

    if lower.starts_with("ssh-") {
        info.service = Some("ssh".into());
        // SSH-2.0-OpenSSH_8.9p1
        if let Some(rest) = first_line.strip_prefix("SSH-") {
            let mut parts = rest.splitn(2, '-');
            let _proto = parts.next();
            if let Some(product) = parts.next() {
                let product = product.trim();
                if let Some((name, ver)) = product.split_once('_') {
                    info.product = Some(name.to_string());
                    info.version = Some(ver.split_whitespace().next().unwrap_or(ver).to_string());
                } else {
                    info.product = Some(product.split_whitespace().next().unwrap_or(product).into());
                }
            }
        }
        return Some(info);
    }

    if lower.starts_with("220") || lower.contains("ftp") {
        info.service = Some(if port == 21 || lower.contains("ftp") {
            "ftp".into()
        } else {
            "smtp".into()
        });
        if lower.contains("ftp") {
            info.service = Some("ftp".into());
        }
        if lower.contains("smtp") || lower.contains("esmtp") {
            info.service = Some("smtp".into());
        }
        info.product = extract_product_token(first_line);
        return Some(info);
    }

    if lower.starts_with("+ok") {
        info.service = Some(if port == 110 { "pop3" } else { "pop3" }.into());
        return Some(info);
    }

    if lower.starts_with("* ok") || lower.starts_with("* ok ") {
        info.service = Some("imap".into());
        return Some(info);
    }

    if lower.starts_with("rfb ") {
        info.service = Some("vnc".into());
        info.product = Some("VNC".into());
        info.version = first_line
            .split_whitespace()
            .nth(1)
            .map(|s| s.to_string());
        return Some(info);
    }

    // Generic banner keep with existing service name.
    Some(info)
}

fn extract_product_token(line: &str) -> Option<String> {
    // "220 foo.example ESMTP Postfix" → Postfix
    let tokens: Vec<&str> = line.split_whitespace().collect();
    tokens
        .iter()
        .rev()
        .find(|t| {
            let t = t.to_ascii_lowercase();
            !matches!(
                t.as_str(),
                "220" | "esmtp" | "smtp" | "ftp" | "ready" | "service"
            ) && t.chars().any(|c| c.is_ascii_alphabetic())
        })
        .map(|t| (*t).to_string())
}

async fn probe_http(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<ServiceInfo> {
    let mut stream = connect(ip, port, timeout_ms).await?;
    let host = match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{v}]"),
    };
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: IPScan/0.1\r\nConnection: close\r\n\r\n"
    );
    timeout(
        Duration::from_millis(timeout_ms),
        stream.write_all(req.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while buf.len() < 8192 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 200 {
            // Have headers; keep reading a bit for title.
            if buf.len() > 1500 {
                break;
            }
        }
    }

    if buf.is_empty() {
        return None;
    }
    parse_http_response(&buf)
}

fn parse_http_response(data: &[u8]) -> Option<ServiceInfo> {
    let text = String::from_utf8_lossy(data);
    if !text.starts_with("HTTP/") && !text.contains("\r\n") {
        return None;
    }

    let mut info = ServiceInfo {
        service: Some("http".into()),
        ..Default::default()
    };

    let mut powered_by: Option<String> = None;

    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("server") && !value.is_empty() {
                info.product = Some(value.split('/').next().unwrap_or(value).to_string());
                if let Some((_, ver)) = value.split_once('/') {
                    info.version = Some(
                        ver.split_whitespace()
                            .next()
                            .unwrap_or(ver)
                            .to_string(),
                    );
                }
                info.banner = Some(sanitize_banner(&format!("Server: {value}")));
                info.notes
                    .push(format!("HTTP version disclosed: {value}"));
            } else if name.eq_ignore_ascii_case("x-powered-by") && !value.is_empty() {
                powered_by = Some(value.to_string());
            }
        }
    }

    if let Some(pb) = powered_by {
        info.notes.push(format!("X-Powered-By: {pb}"));
        if info.product.is_none() {
            info.product = Some(pb.split('/').next().unwrap_or(&pb).to_string());
        }
        if info.version.is_none() {
            if let Some((_, ver)) = pb.split_once('/') {
                info.version = Some(ver.to_string());
            }
        }
    }

    if let Some(title) = extract_html_title(&text) {
        let title = sanitize_banner(&title);
        if !title.is_empty() {
            let banner = match &info.banner {
                Some(b) => format!("{b} | title={title}"),
                None => format!("title={title}"),
            };
            info.banner = Some(sanitize_banner(&banner));
            if title.eq_ignore_ascii_case("Index of /")
                || title.to_ascii_lowercase().starts_with("index of ")
            {
                info.notes.push("HTTP directory listing enabled".into());
            }
        }
    }

    if info.banner.is_none() {
        let first = text.lines().next().unwrap_or("").trim();
        if first.starts_with("HTTP/") {
            info.banner = Some(sanitize_banner(first));
        }
    }

    Some(info)
}

fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = &body[start..];
    let gt = after.find('>')?;
    let content = &after[gt + 1..];
    let end_rel = content.to_ascii_lowercase().find("</title>")?;
    Some(content[..end_rel].trim().to_string())
}

async fn probe_tls_http(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<ServiceInfo> {
    let tcp = connect(ip, port, timeout_ms).await?;
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let connector = tokio_native_tls::TlsConnector::from(connector);

    let host = match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => v.to_string(),
    };

    let mut tls = timeout(
        Duration::from_millis(timeout_ms),
        connector.connect(&host, tcp),
    )
    .await
    .ok()?
    .ok()?;

    let mut info = ServiceInfo {
        service: Some(if looks_like_http_port(port, Some("https")) || matches!(port, 443 | 8443 | 9443) {
            "https".into()
        } else {
            service_name(port).unwrap_or("ssl").into()
        }),
        ..Default::default()
    };

    if let Ok(Some(cert)) = tls.get_ref().peer_certificate() {
        if let Ok(der) = cert.to_der() {
            if let Some((cn, not_after)) = parse_cert_summary(&der) {
                let mut parts = Vec::new();
                if let Some(cn) = cn {
                    parts.push(format!("CN={cn}"));
                    info.product = info.product.clone().or(Some(format!("TLS cert {cn}")));
                }
                if let Some(na) = not_after {
                    parts.push(format!("notAfter={na}"));
                }
                if !parts.is_empty() {
                    info.banner = Some(parts.join(" "));
                }
            }
        }
    }

    // Try HTTP over TLS for Server/title.
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: IPScan/0.1\r\nConnection: close\r\n\r\n"
    );
    let _ = timeout(
        Duration::from_millis(timeout_ms),
        tls.write_all(req.as_bytes()),
    )
    .await;

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while buf.len() < 8192 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, tls.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
        if buf.len() > 1500 {
            break;
        }
    }

    if let Some(http_info) = parse_http_response(&buf) {
        let cert_banner = info.banner.clone();
        merge(&mut info, http_info);
        info.service = Some("https".into());
        match (cert_banner, info.banner.take()) {
            (Some(cert), Some(http)) if !http.contains(&cert) => {
                info.banner = Some(sanitize_banner(&format!("{cert} | {http}")));
            }
            (Some(cert), None) => info.banner = Some(cert),
            (_, Some(http)) => info.banner = Some(http),
            (None, None) => {}
        }
    }

    Some(info)
}

fn parse_cert_summary(der: &[u8]) -> Option<(Option<String>, Option<String>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));
    let not_after = cert.validity().not_after.to_rfc2822().ok();
    Some((cn, not_after))
}

/// SMB2 dialect negotiate (clean-room) — extracts dialect / signing hints.
async fn probe_smb(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<ServiceInfo> {
    let mut stream = connect(ip, port, timeout_ms).await?;
    let req = build_smb2_negotiate();
    timeout(
        Duration::from_millis(timeout_ms),
        stream.write_all(&req),
    )
    .await
    .ok()?
    .ok()?;

    let data = read_some(&mut stream, timeout_ms, 1024).await;
    if data.len() < 8 {
        return None;
    }

    // SMB2 response starts after 4-byte NetBIOS length: 0xFE 'S' 'M' 'B'
    let smb_off = if data.len() > 8 && data[4] == 0xfe && &data[5..8] == b"SMB" {
        4
    } else if data[0] == 0xfe && data.len() > 4 && &data[1..4] == b"SMB" {
        0
    } else if data.len() > 8 && data[4] == 0xff && &data[5..8] == b"SMB" {
        // SMB1 response
        return Some(ServiceInfo {
            service: Some("smb".into()),
            product: Some("SMB".into()),
            version: Some("1.0".into()),
            banner: Some("SMB1 negotiate response".into()),
            notes: vec![
                "SMB version 1.0".into(),
                "SMBv1 enabled (legacy / higher risk)".into(),
            ],
        });
    } else {
        return None;
    };

    if data.len() < smb_off + 70 {
        return Some(ServiceInfo {
            service: Some("smb".into()),
            product: Some("SMB".into()),
            banner: Some("SMB response (short)".into()),
            notes: vec!["SMB service responded".into()],
            ..Default::default()
        });
    }

    // SMB2 Negotiate Response: DialectRevision at offset 64+4 = StructureSize(2) + ...
    // Header is 64 bytes from smb_off. Negotiate body StructureSize at +64, Dialect at +64+4.
    let dialect = u16::from_le_bytes([data[smb_off + 68], data[smb_off + 69]]);
    let security_mode = data.get(smb_off + 70).copied().unwrap_or(0);
    let (dialect_name, ver) = match dialect {
        0x0202 => ("SMB 2.0.2", "2.0.2"),
        0x0210 => ("SMB 2.1", "2.1"),
        0x0300 => ("SMB 3.0", "3.0"),
        0x0302 => ("SMB 3.0.2", "3.0.2"),
        0x0311 => ("SMB 3.1.1", "3.1.1"),
        other => return Some(ServiceInfo {
            service: Some("smb".into()),
            product: Some("SMB".into()),
            version: Some(format!("0x{other:04x}")),
            banner: Some(format!("SMB dialect 0x{other:04x}")),
            notes: vec![format!("SMB dialect 0x{other:04x}")],
        }),
    };

    let signing_enabled = security_mode & 0x01 != 0;
    let signing_required = security_mode & 0x02 != 0;
    let mut notes = vec![format!("SMB version {ver} ({dialect_name})")];
    if signing_required {
        notes.push("SMB signing required".into());
    } else if signing_enabled {
        notes.push("SMB signing enabled but not required".into());
    } else {
        notes.push("SMB signing not required".into());
    }

    Some(ServiceInfo {
        service: Some("smb".into()),
        product: Some("SMB".into()),
        version: Some(ver.into()),
        banner: Some(format!("{dialect_name}; signing_mode=0x{security_mode:02x}")),
        notes,
    })
}

fn build_smb2_negotiate() -> Vec<u8> {
    // Dialects we advertise
    let dialects: [u16; 5] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    let negotiate_size = 36 + dialects.len() * 2;
    let smb_payload_len = 64 + negotiate_size;
    let mut pkt = Vec::with_capacity(4 + smb_payload_len);

    // NetBIOS session service header
    let nb_len = smb_payload_len as u32;
    pkt.push(0x00);
    pkt.push(((nb_len >> 16) & 0xff) as u8);
    pkt.push(((nb_len >> 8) & 0xff) as u8);
    pkt.push((nb_len & 0xff) as u8);

    // SMB2 header
    pkt.extend_from_slice(b"\xfeSMB");
    pkt.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    pkt.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Status / ChannelSequence
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Command NEGOTIATE
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Credits requested
    pkt.extend_from_slice(&0u32.to_le_bytes()); // Flags
    pkt.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    pkt.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    pkt.extend_from_slice(&0u32.to_le_bytes()); // ProcessId / AsyncId high
    pkt.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    pkt.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    pkt.extend_from_slice(&[0u8; 16]); // Signature

    // Negotiate request
    pkt.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    pkt.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    pkt.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode signing enabled
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    pkt.extend_from_slice(&1u32.to_le_bytes()); // Capabilities
    pkt.extend_from_slice(&[0u8; 16]); // ClientGuid
    pkt.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    pkt.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    pkt.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    for d in dialects {
        pkt.extend_from_slice(&d.to_le_bytes());
    }

    pkt
}
