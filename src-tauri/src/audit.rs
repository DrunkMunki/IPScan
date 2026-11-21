use crate::settings;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

pub fn append_entry(message: &str) {
    let Ok(path) = settings::audit_log_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let line = format!("{} {}\n", Local::now().format("%Y-%m-%dT%H:%M:%S"), message);
    let _ = file.write_all(line.as_bytes());
}

pub fn audit_path() -> Result<String, String> {
    Ok(settings::audit_log_path()?
        .to_string_lossy()
        .to_string())
}

pub fn default_audit_path_string() -> Result<String, String> {
    Ok(settings::default_audit_path()?
        .to_string_lossy()
        .to_string())
}

pub fn set_audit_path(path: &str) -> Result<String, String> {
    settings::write_audit_path_setting(path)?;
    append_entry(&format!("audit_path_changed path={path}"));
    audit_path()
}

pub fn reset_audit_path() -> Result<String, String> {
    let path = settings::clear_audit_path_setting()?;
    ensure_parent(&path)?;
    append_entry(&format!(
        "audit_path_reset path={}",
        path.to_string_lossy()
    ));
    Ok(path.to_string_lossy().to_string())
}

pub fn open_audit_location() -> Result<(), String> {
    settings::open_audit_log_location()
}

fn ensure_parent(path: &PathBuf) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    Ok(())
}
