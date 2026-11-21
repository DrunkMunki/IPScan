//! NetBIOS Name Service (UDP/137) hostname lookup — node status query.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Query NetBIOS node status and return the first useful workstation/server name.
pub async fn lookup_netbios_name(ip: IpAddr, timeout_ms: u64) -> Option<String> {
    let IpAddr::V4(v4) = ip else {
        return None;
    };
    let timeout_ms = timeout_ms.clamp(200, 3_000);

    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let target = SocketAddr::new(IpAddr::V4(v4), 137);
    sock.connect(target).await.ok()?;

    let tx_id: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .subsec_nanos()
        & 0xffff) as u16;

    let packet = build_node_status_request(tx_id);
    sock.send(&packet).await.ok()?;

    let mut buf = [0u8; 576];
    let n = timeout(Duration::from_millis(timeout_ms), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_node_status_name(&buf[..n])
}

fn build_node_status_request(tx_id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags
    pkt.extend_from_slice(&1u16.to_be_bytes()); // questions
    pkt.extend_from_slice(&0u16.to_be_bytes()); // answers
    pkt.extend_from_slice(&0u16.to_be_bytes()); // authority
    pkt.extend_from_slice(&0u16.to_be_bytes()); // additional

    // Encoded NetBIOS name for "*" (wildcard) + NUL type, 16 chars → 32 encoded bytes.
    let mut name = [b' '; 15];
    name[0] = b'*';
    let mut encoded = Vec::with_capacity(34);
    encoded.push(32); // length
    for b in name.iter().copied().chain(std::iter::once(0u8)) {
        encoded.push(((b >> 4) & 0x0f) + b'A');
        encoded.push((b & 0x0f) + b'A');
    }
    encoded.push(0); // end of name
    pkt.extend_from_slice(&encoded);
    pkt.extend_from_slice(&0x0021u16.to_be_bytes()); // NBSTAT
    pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
    pkt
}

fn parse_node_status_name(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }
    // Skip question name to find answer RDATA. Node status responses typically
    // echo the question then include answers with name + NBSTAT rdata.
    let mut i = 12;
    // Skip QNAME
    while i < data.len() {
        let len = data[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len >= 0xc0 {
            i += 2;
            break;
        }
        i += 1 + len;
    }
    i += 4; // qtype + qclass
    if i + 12 > data.len() {
        // Fall through: search for printable name blocks in the whole packet.
        return extract_names_from_rdata(data);
    }

    // Answer NAME (may be pointer)
    if data[i] >= 0xc0 {
        i += 2;
    } else {
        while i < data.len() {
            let len = data[i] as usize;
            if len == 0 {
                i += 1;
                break;
            }
            if len >= 0xc0 {
                i += 2;
                break;
            }
            i += 1 + len;
        }
    }
    if i + 10 > data.len() {
        return extract_names_from_rdata(data);
    }
    let _atype = u16::from_be_bytes([data[i], data[i + 1]]);
    i += 8; // type, class, ttl
    if i + 2 > data.len() {
        return None;
    }
    let rdlen = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    if i + rdlen > data.len() || rdlen < 1 {
        return extract_names_from_rdata(data);
    }
    extract_names_from_rdata(&data[i..i + rdlen]).or_else(|| extract_names_from_rdata(data))
}

fn extract_names_from_rdata(rdata: &[u8]) -> Option<String> {
    // Node status RDATA: num_names (1) + N * (15-byte name + suffix + flags)
    if rdata.is_empty() {
        return None;
    }

    // Try structured parse first.
    let num = rdata[0] as usize;
    if num > 0 && num < 32 && rdata.len() >= 1 + num * 18 {
        let mut best: Option<(u8, String)> = None;
        for n in 0..num {
            let base = 1 + n * 18;
            let raw = &rdata[base..base + 15];
            let suffix = rdata[base + 15];
            let name = String::from_utf8_lossy(raw)
                .trim()
                .trim_end_matches('\0')
                .trim()
                .to_string();
            if !is_useful_nb_name(&name) {
                continue;
            }
            let rank = match suffix {
                0x00 => 0u8, // workstation
                0x20 => 1,   // server
                0x03 => 2,   // messenger
                _ => 5,
            };
            if best.as_ref().map(|(r, _)| rank < *r).unwrap_or(true) {
                best = Some((rank, name));
            }
        }
        if let Some((_, name)) = best {
            return Some(name);
        }
    }

    // Fallback: scan for 15-char ASCII blocks.
    let mut i = 0;
    while i + 16 <= rdata.len() {
        let chunk = &rdata[i..i + 15];
        if chunk.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            let name = String::from_utf8_lossy(chunk)
                .trim()
                .to_string();
            if is_useful_nb_name(&name) {
                return Some(name);
            }
        }
        i += 1;
    }
    let _ = Ipv4Addr::UNSPECIFIED; // silence unused in non-windows paths if any
    None
}

fn is_useful_nb_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 15 {
        return false;
    }
    if name.starts_with('*') || name.starts_with("__") {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    if upper == "WORKGROUP" || upper == "DOMAIN" || upper == "LOCAL" {
        return false;
    }
    name.chars()
        .any(|c| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}
