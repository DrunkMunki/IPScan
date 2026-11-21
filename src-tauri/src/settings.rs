//! Persistent app settings stored in the Windows registry (HKCU).

use std::path::{Path, PathBuf};

#[cfg(windows)]
const REG_KEY: &str = r"Software\Onyx\IPScan";
#[cfg(windows)]
const AUDIT_PATH_VALUE: &str = "AuditLogPath";

/// Default audit log path under the user's app data directory.
pub fn default_audit_path() -> Result<PathBuf, String> {
    let base = dirs::data_dir().ok_or_else(|| "Could not resolve app data directory.".to_string())?;
    Ok(base.join("com.onyx.ipscan").join("audit.log"))
}

/// Resolve the active audit log path (registry override, else default).
pub fn audit_log_path() -> Result<PathBuf, String> {
    if let Some(custom) = read_audit_path_setting()? {
        let path = PathBuf::from(custom);
        if path.as_os_str().is_empty() {
            return default_audit_path();
        }
        return Ok(path);
    }
    default_audit_path()
}

pub fn read_audit_path_setting() -> Result<Option<String>, String> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let Ok(key) = hkcu.open_subkey(REG_KEY) else {
            return Ok(None);
        };
        match key.get_value::<String, _>(AUDIT_PATH_VALUE) {
            Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    #[cfg(not(windows))]
    {
        Ok(None)
    }
}

pub fn write_audit_path_setting(path: &str) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Audit log path cannot be empty.".into());
    }

    let path_buf = PathBuf::from(trimmed);
    validate_audit_path(&path_buf)?;

    if let Some(parent) = path_buf.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!("Could not create audit log directory {}: {e}", parent.display())
            })?;
        }
    }

    // Ensure the log file exists so Explorer / editors can open it immediately.
    if !path_buf.exists() {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path_buf)
            .map_err(|e| format!("Could not create audit log file: {e}"))?;
    }

    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = hkcu
            .create_subkey(REG_KEY)
            .map_err(|e| format!("Could not open registry key: {e}"))?;
        key.set_value(AUDIT_PATH_VALUE, &trimmed.to_string())
            .map_err(|e| format!("Could not write registry value: {e}"))?;
    }

    #[cfg(not(windows))]
    {
        let _ = trimmed;
    }

    Ok(())
}

pub fn clear_audit_path_setting() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey_with_flags(REG_KEY, winreg::enums::KEY_SET_VALUE) {
            let _ = key.delete_value(AUDIT_PATH_VALUE);
        }
    }

    default_audit_path()
}

fn validate_audit_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("Audit log path cannot be empty.".into());
    }
    if path.is_dir() {
        return Err("Audit log path must be a file path, not a directory.".into());
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("log") || ext.eq_ignore_ascii_case("txt") => Ok(()),
        Some(_) => Ok(()), // allow other extensions
        None => Ok(()),    // allow extensionless filenames
    }
}

/// Reveal the audit log in Explorer (creates an empty file if missing).
pub fn open_audit_log_location() -> Result<(), String> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if !path.exists() {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // `/select,` highlights the file in Explorer.
        let arg = format!("/select,{}", path.display());
        Command::new("explorer")
            .arg(arg)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("Could not open Explorer: {e}"))?;
        Ok(())
    }

    #[cfg(not(windows))]
    {
        Err("Opening audit log location is only supported on Windows.".into())
    }
}
