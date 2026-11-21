use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("{0}")]
    Message(String),
}

pub fn parse_targets(input: &str) -> Result<Vec<IpAddr>, TargetError> {
    let mut ips = Vec::new();
    for raw in input
        .split(|c: char| c == ',' || c == '\n' || c == ';' || c == ' ')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        ips.extend(expand_token(raw)?);
    }
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(TargetError::Message(
            "No valid IP targets found. Use CIDR, range, or IP list.".into(),
        ));
    }
    if ips.len() > 65_536 {
        return Err(TargetError::Message(format!(
            "Target set too large ({} hosts). Limit is 65536 for safety.",
            ips.len()
        )));
    }
    Ok(ips)
}

fn expand_token(token: &str) -> Result<Vec<IpAddr>, TargetError> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    if token.contains('/') {
        let net: Ipv4Net = token
            .parse()
            .map_err(|_| TargetError::Message(format!("Invalid CIDR: {token}")))?;
        return Ok(net.hosts().map(IpAddr::V4).collect());
    }

    if let Some((start, end)) = token.split_once('-') {
        return expand_range(start.trim(), end.trim());
    }

    // Hostname / DNS forward lookup
    match dns_lookup::lookup_host(token) {
        Ok(list) if !list.is_empty() => Ok(list),
        _ => Err(TargetError::Message(format!(
            "Could not resolve target: {token}"
        ))),
    }
}

fn expand_range(start: &str, end: &str) -> Result<Vec<IpAddr>, TargetError> {
    let start_ip: Ipv4Addr = start
        .parse()
        .map_err(|_| TargetError::Message(format!("Invalid range start: {start}")))?;

    let end_ip: Ipv4Addr = if end.contains('.') {
        end.parse()
            .map_err(|_| TargetError::Message(format!("Invalid range end: {end}")))?
    } else {
        let last = end
            .parse::<u8>()
            .map_err(|_| TargetError::Message(format!("Invalid range end octet: {end}")))?;
        let o = start_ip.octets();
        Ipv4Addr::new(o[0], o[1], o[2], last)
    };

    let start_n = u32::from(start_ip);
    let end_n = u32::from(end_ip);
    if end_n < start_n {
        return Err(TargetError::Message(
            "Range end must be greater than or equal to start.".into(),
        ));
    }
    if end_n - start_n > 65_536 {
        return Err(TargetError::Message(
            "IP range exceeds 65536 hosts.".into(),
        ));
    }

    Ok((start_n..=end_n)
        .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
        .collect())
}

pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, TargetError> {
    let mut ports = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a
                .trim()
                .parse()
                .map_err(|_| TargetError::Message(format!("Invalid port: {a}")))?;
            let end: u16 = b
                .trim()
                .parse()
                .map_err(|_| TargetError::Message(format!("Invalid port: {b}")))?;
            if start == 0 || end == 0 || start > end {
                return Err(TargetError::Message(format!(
                    "Invalid port range: {part}"
                )));
            }
            ports.extend(start..=end);
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| TargetError::Message(format!("Invalid port: {part}")))?;
            if p == 0 {
                return Err(TargetError::Message("Port 0 is not allowed.".into()));
            }
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(TargetError::Message("No ports specified.".into()));
    }
    if ports.len() > 65_535 {
        return Err(TargetError::Message(
            "Too many ports (max 65535 per scan).".into(),
        ));
    }
    Ok(ports)
}

pub fn validate_against_allowlist(
    targets: &[IpAddr],
    allowlist: &[String],
) -> Result<(), TargetError> {
    if allowlist.is_empty() {
        return Err(TargetError::Message(
            "Allowlist is empty. Add authorized company CIDR ranges before scanning.".into(),
        ));
    }

    let nets: Result<Vec<Ipv4Net>, _> = allowlist
        .iter()
        .map(|s| {
            s.parse::<Ipv4Net>()
                .map_err(|_| TargetError::Message(format!("Invalid allowlist CIDR: {s}")))
        })
        .collect();
    let nets = nets?;

    for ip in targets {
        let IpAddr::V4(v4) = ip else {
            return Err(TargetError::Message(
                "IPv6 targets are not supported in this MVP.".into(),
            ));
        };
        if !nets.iter().any(|n| n.contains(v4)) {
            return Err(TargetError::Message(format!(
                "Target {ip} is outside the configured allowlist."
            )));
        }
    }
    Ok(())
}