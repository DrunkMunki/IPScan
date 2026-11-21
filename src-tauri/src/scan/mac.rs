use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use std::time::Instant;

/// Resolve a MAC address for an IPv4 host via the Windows ARP stack.
///
/// Works for hosts on the **same L2/broadcast domain**. Remote routed subnets
/// generally will not return a MAC (the gateway MAC is not the target's MAC).
pub async fn lookup_mac(ip: IpAddr) -> Option<String> {
    tokio::task::spawn_blocking(move || lookup_mac_blocking(ip))
        .await
        .ok()
        .flatten()
}

/// ARP probe used for LAN host discovery. Returns RTT in ms when the stack
/// resolves a MAC (same L2 only).
pub async fn arp_probe_rtt(ip: IpAddr) -> Option<u64> {
    tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        lookup_mac_blocking(ip)?;
        Some(started.elapsed().as_millis() as u64)
    })
    .await
    .ok()
    .flatten()
}

fn lookup_mac_blocking(ip: IpAddr) -> Option<String> {
    let IpAddr::V4(v4) = ip else {
        return None;
    };

    #[cfg(windows)]
    {
        windows_send_arp(v4).or_else(|| windows_arp_table_lookup(v4))
    }

    #[cfg(not(windows))]
    {
        let _ = v4;
        None
    }
}

#[cfg(windows)]
fn windows_send_arp(v4: Ipv4Addr) -> Option<String> {
    #[link(name = "iphlpapi")]
    extern "system" {
        fn SendARP(
            dest_ip: u32,
            src_ip: u32,
            mac_addr: *mut u8,
            phy_addr_len: *mut u32,
        ) -> u32;
    }

    // Windows IPAddr / inet_addr layout: first octet in the low byte
    // (native endian packing of the dotted-quad bytes). NOT big-endian.
    let dest_ip = u32::from_ne_bytes(v4.octets());
    let mut mac = [0u8; 8];
    let mut len: u32 = 6;

    // NO_ERROR == 0
    let status = unsafe { SendARP(dest_ip, 0, mac.as_mut_ptr(), &mut len) };
    if status != 0 || len < 6 {
        return None;
    }

    let formatted = format_mac(&mac[..6]);
    if is_useless_mac(&formatted) {
        return None;
    }
    Some(formatted)
}

/// Fallback: parse `arp -a` (hidden console) for a cached entry.
#[cfg(windows)]
fn windows_arp_table_lookup(v4: Ipv4Addr) -> Option<String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new("arp")
        .args(["-a", &v4.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let needle = v4.to_string();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with(&needle) {
            continue;
        }
        // e.g. "192.168.2.2           00-1a-8c-00-42-f4     dynamic"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let mac = parts[1].replace('-', ":").to_ascii_uppercase();
        if mac.split(':').count() == 6 && !is_useless_mac(&mac) {
            return Some(mac);
        }
    }
    None
}

fn is_useless_mac(mac: &str) -> bool {
    matches!(
        mac.to_ascii_uppercase().as_str(),
        "00:00:00:00:00:00" | "FF:FF:FF:FF:FF:FF"
    )
}

pub fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn mac_to_compact_hex(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}
