use getifaddrs::{getifaddrs, Address, InterfaceFlags};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalNetworkInfo {
    pub interface_name: String,
    pub ip: String,
    pub cidr: String,
    pub prefix_len: u8,
}

/// Detect the best local IPv4 subnet for a default scan target.
/// Prefers up, non-loopback, private addresses (e.g. 192.168.2.101 -> 192.168.2.0/24).
pub fn detect_local_network() -> Result<LocalNetworkInfo, String> {
    let mut candidates: Vec<LocalNetworkInfo> = Vec::new();

    for interface in getifaddrs().map_err(|e| format!("Could not enumerate interfaces: {e}"))? {
        if interface.flags.contains(InterfaceFlags::LOOPBACK) {
            continue;
        }
        if !interface.flags.contains(InterfaceFlags::UP) {
            continue;
        }

        let Address::V4(v4) = interface.address else {
            continue;
        };

        let ip = v4.address;
        if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
            continue;
        }

        let detected_prefix = v4
            .netmask
            .map(ipv4_mask_to_prefix)
            .unwrap_or(24);
        // Keep the default scan practical (avoid huge ranges like /16).
        let prefix_len = detected_prefix.clamp(24, 30);

        let Ok(net) = Ipv4Net::new(ip, prefix_len) else {
            continue;
        };
        let network = net.trunc();

        candidates.push(LocalNetworkInfo {
            interface_name: interface.name,
            ip: ip.to_string(),
            cidr: network.to_string(),
            prefix_len,
        });
    }

    if candidates.is_empty() {
        return Err("No active local IPv4 interface found.".into());
    }

    candidates.sort_by_key(|c| score_candidate(&c.ip));
    Ok(candidates.into_iter().next().unwrap())
}

fn ipv4_mask_to_prefix(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    let ones = bits.count_ones() as u8;
    // Accept contiguous masks; otherwise fall back to /24.
    if bits == 0 {
        return 24;
    }
    if (!bits).trailing_ones() as u8 == 32 - ones {
        ones.clamp(8, 30)
    } else {
        24
    }
}

/// True when `ip` falls inside any up, non-loopback local interface subnet
/// (using the interface's real netmask, not the clamped scan default).
pub fn is_on_local_subnet(ip: IpAddr) -> bool {
    let IpAddr::V4(target) = ip else {
        return false;
    };
    let Ok(interfaces) = getifaddrs() else {
        return false;
    };
    for interface in interfaces {
        if interface.flags.contains(InterfaceFlags::LOOPBACK) {
            continue;
        }
        if !interface.flags.contains(InterfaceFlags::UP) {
            continue;
        }
        let Address::V4(v4) = interface.address else {
            continue;
        };
        let Some(mask) = v4.netmask else {
            continue;
        };
        let prefix = ipv4_mask_to_prefix(mask);
        let Ok(net) = Ipv4Net::new(v4.address, prefix) else {
            continue;
        };
        if net.contains(&target) {
            return true;
        }
    }
    false
}

fn score_candidate(ip: &str) -> u8 {
    // Lower is better.
    let Ok(addr) = ip.parse::<Ipv4Addr>() else {
        return 100;
    };
    if addr.is_private() {
        let o = addr.octets();
        if o[0] == 192 && o[1] == 168 {
            0
        } else if o[0] == 10 {
            1
        } else if o[0] == 172 && (16..=31).contains(&o[1]) {
            2
        } else {
            3
        }
    } else {
        50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_something() {
        let info = detect_local_network().expect("local net");
        println!("{:?}", info);
        assert!(info.cidr.contains('/'));
    }
}
