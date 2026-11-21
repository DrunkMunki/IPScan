use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProfile {
    pub id: String,
    pub name: String,
    pub targets: String,
    pub ports: String,
    pub use_common_ports: bool,
    pub host_concurrency: usize,
    pub port_concurrency: usize,
    pub timeout_ms: u64,
    pub use_icmp: bool,
    pub scan_ports: bool,
    #[serde(default)]
    pub scan_udp: bool,
    pub probe_all_targets: bool,
    #[serde(default)]
    pub identify_services: bool,
    #[serde(default)]
    pub vuln_scan: bool,
}

fn app_dir() -> Result<PathBuf, String> {
    let base = dirs::data_dir().ok_or_else(|| "Could not resolve app data directory.".to_string())?;
    let dir = base.join("com.onyx.ipscan");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn profiles_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("profiles.json"))
}

fn allowlist_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("allowlist.json"))
}

pub fn load_profiles() -> Result<Vec<ScanProfile>, String> {
    let path = profiles_path()?;
    if !path.exists() {
        return Ok(default_profiles());
    }
    let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

pub fn save_profiles(profiles: &[ScanProfile]) -> Result<(), String> {
    let path = profiles_path()?;
    let data = serde_json::to_string_pretty(profiles).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

pub fn upsert_profile(profile: ScanProfile) -> Result<Vec<ScanProfile>, String> {
    let mut profiles = load_profiles()?;
    if let Some(existing) = profiles.iter_mut().find(|p| p.id == profile.id) {
        *existing = profile;
    } else {
        profiles.push(profile);
    }
    save_profiles(&profiles)?;
    Ok(profiles)
}

pub fn delete_profile(id: &str) -> Result<Vec<ScanProfile>, String> {
    let mut profiles = load_profiles()?;
    profiles.retain(|p| p.id != id);
    save_profiles(&profiles)?;
    Ok(profiles)
}

pub fn load_allowlist() -> Result<Vec<String>, String> {
    let path = allowlist_path()?;
    if !path.exists() {
        return Ok(default_allowlist());
    }
    let data = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

pub fn save_allowlist(cidrs: &[String]) -> Result<(), String> {
    for cidr in cidrs {
        let _: ipnet::Ipv4Net = cidr
            .parse()
            .map_err(|_| format!("Invalid allowlist CIDR: {cidr}"))?;
    }
    let path = allowlist_path()?;
    let data = serde_json::to_string_pretty(cidrs).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| e.to_string())
}

fn default_allowlist() -> Vec<String> {
    vec![
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "127.0.0.0/8".into(),
    ]
}

fn default_profiles() -> Vec<ScanProfile> {
    vec![
        ScanProfile {
            id: "user-vlan-quick".into(),
            name: "User VLAN quick".into(),
            targets: "192.168.1.0/24".into(),
            ports: String::new(),
            use_common_ports: true,
            host_concurrency: 64,
            port_concurrency: 100,
            timeout_ms: 400,
            use_icmp: true,
            scan_ports: true,
            scan_udp: false,
            probe_all_targets: false,
            identify_services: false,
            vuln_scan: false,
        },
        ScanProfile {
            id: "server-subnet-deep".into(),
            name: "Server subnet deep".into(),
            targets: "10.0.0.0/24".into(),
            ports: "1-1024,3306,3389,5432,8080,8443".into(),
            use_common_ports: false,
            host_concurrency: 48,
            port_concurrency: 120,
            timeout_ms: 600,
            use_icmp: true,
            scan_ports: true,
            scan_udp: true,
            probe_all_targets: false,
            identify_services: true,
            vuln_scan: false,
        },
    ]
}