use crate::scan::mac::mac_to_compact_hex;
use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Embedded IEEE OUI / vendor prefixes (nmap mac-prefixes format).
/// Same idea as the aallan gist and OUI Master Database — compact, offline lookup.
static OUI_DB: Lazy<HashMap<String, String>> = Lazy::new(load_oui_db);

const OUI_DATA: &str = include_str!("../../resources/nmap-mac-prefixes.txt");

fn load_oui_db() -> HashMap<String, String> {
    let mut map = HashMap::with_capacity(60_000);
    for line in OUI_DATA.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((prefix, vendor)) = line.split_once(|c: char| c.is_whitespace()) else {
            continue;
        };
        let prefix = prefix.trim().to_ascii_uppercase();
        let vendor = vendor.trim();
        if prefix.len() >= 6 && !vendor.is_empty() {
            map.insert(prefix, vendor.to_string());
        }
    }
    map
}

/// Look up manufacturer from a MAC address using longest-prefix match (9 / 7 / 6 hex).
pub fn lookup_manufacturer(mac: &str) -> Option<String> {
    let hex = mac_to_compact_hex(mac);
    if hex.len() < 6 {
        return None;
    }

    for len in [9usize, 7, 6] {
        if hex.len() >= len {
            if let Some(vendor) = OUI_DB.get(&hex[..len]) {
                return Some(vendor.clone());
            }
        }
    }
    None
}

pub fn oui_entry_count() -> usize {
    OUI_DB.len()
}
