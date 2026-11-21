mod audit;
mod config;
mod ping;
mod scan;
mod settings;

use config::ScanProfile;
use ping::{PingResultRow, PingRuntime, PingSession, PingStatSummary};
use scan::{
    cancel_scan, common_ports, common_udp_ports, extended_common_ports, start_scan, ScanRequest,
    ScanState,
};
use std::sync::Arc;
use tauri::{AppHandle, State};

#[tauri::command]
async fn start_network_scan(
    app: tauri::AppHandle,
    state: State<'_, Arc<ScanState>>,
    request: ScanRequest,
) -> Result<String, String> {
    start_scan(app, Arc::clone(state.inner()), request).await
}

#[tauri::command]
fn cancel_network_scan(state: State<'_, Arc<ScanState>>) -> bool {
    cancel_scan(state.inner())
}

#[tauri::command]
fn get_common_ports() -> Vec<u16> {
    common_ports()
}

#[tauri::command]
fn get_extended_common_ports() -> Vec<u16> {
    extended_common_ports()
}

#[tauri::command]
fn get_common_udp_ports() -> Vec<u16> {
    common_udp_ports()
}

#[tauri::command]
fn get_profiles() -> Result<Vec<ScanProfile>, String> {
    config::load_profiles()
}

#[tauri::command]
fn save_profile(profile: ScanProfile) -> Result<Vec<ScanProfile>, String> {
    config::upsert_profile(profile)
}

#[tauri::command]
fn remove_profile(id: String) -> Result<Vec<ScanProfile>, String> {
    config::delete_profile(&id)
}

#[tauri::command]
fn get_allowlist() -> Result<Vec<String>, String> {
    config::load_allowlist()
}

#[tauri::command]
fn set_allowlist(cidrs: Vec<String>) -> Result<(), String> {
    config::save_allowlist(&cidrs)
}

#[tauri::command]
fn export_results(path: String, format: String, contents: String) -> Result<(), String> {
    let normalized = format.to_lowercase();
    if normalized != "csv" && normalized != "json" {
        return Err("Format must be csv or json.".into());
    }
    std::fs::write(&path, contents).map_err(|e| e.to_string())?;
    audit::append_entry(&format!("export path={path} format={normalized}"));
    Ok(())
}

#[tauri::command]
fn get_audit_path() -> Result<String, String> {
    audit::audit_path()
}

#[tauri::command]
fn get_default_audit_path() -> Result<String, String> {
    audit::default_audit_path_string()
}

#[tauri::command]
fn set_audit_path(path: String) -> Result<String, String> {
    audit::set_audit_path(&path)
}

#[tauri::command]
fn reset_audit_path() -> Result<String, String> {
    audit::reset_audit_path()
}

#[tauri::command]
fn open_audit_location() -> Result<(), String> {
    audit::open_audit_location()
}

#[tauri::command]
fn get_oui_stats() -> usize {
    scan::oui::oui_entry_count()
}

#[tauri::command]
fn get_local_network() -> Result<scan::localnet::LocalNetworkInfo, String> {
    scan::localnet::detect_local_network()
}

#[tauri::command]
fn ping_list_sessions(runtime: State<'_, Arc<PingRuntime>>) -> Result<Vec<PingSession>, String> {
    let running = ping::runner::running_ids(runtime.inner());
    ping::list_sessions(&running)
}

#[tauri::command]
fn ping_create_session(
    title: String,
    target: String,
    interval_ms: u64,
) -> Result<PingSession, String> {
    ping::create_session(&title, &target, interval_ms)
}

#[tauri::command]
async fn ping_start(
    app: AppHandle,
    runtime: State<'_, Arc<PingRuntime>>,
    session_id: String,
) -> Result<(), String> {
    ping::start_ping_session(app, Arc::clone(runtime.inner()), session_id).await
}

#[tauri::command]
fn ping_stop(runtime: State<'_, Arc<PingRuntime>>, session_id: String) -> bool {
    ping::stop_ping_session(runtime.inner(), &session_id)
}

#[tauri::command]
fn ping_list_results(
    session_id: String,
    limit: Option<u32>,
) -> Result<Vec<PingResultRow>, String> {
    ping::list_recent_results(&session_id, limit.unwrap_or(500))
}

#[tauri::command]
fn ping_get_stats(session_id: String) -> Result<PingStatSummary, String> {
    ping::get_session_stats(&session_id)
}

#[tauri::command]
fn ping_clear_session(
    runtime: State<'_, Arc<PingRuntime>>,
    session_id: String,
) -> Result<(), String> {
    ping::stop_ping_session(runtime.inner(), &session_id);
    ping::clear_session_results(&session_id)
}

#[tauri::command]
fn ping_delete_session(
    runtime: State<'_, Arc<PingRuntime>>,
    session_id: String,
) -> Result<(), String> {
    ping::stop_ping_session(runtime.inner(), &session_id);
    ping::delete_session(&session_id)
}

#[tauri::command]
fn ping_clear_all(runtime: State<'_, Arc<PingRuntime>>) -> Result<(), String> {
    ping::stop_all_pings(runtime.inner());
    ping::clear_all_sessions()
}

#[tauri::command]
fn ping_import_csv(path: String, interval_ms: u64) -> Result<Vec<PingSession>, String> {
    ping::import_targets_from_csv(&path, interval_ms)
}

#[tauri::command]
fn ping_export_db(path: String) -> Result<(), String> {
    ping::export_database(&path)
}

#[tauri::command]
fn ping_import_db(
    runtime: State<'_, Arc<PingRuntime>>,
    path: String,
) -> Result<Vec<PingSession>, String> {
    ping::stop_all_pings(runtime.inner());
    ping::import_database(&path)?;
    let running = ping::runner::running_ids(runtime.inner());
    ping::list_sessions(&running)
}

#[tauri::command]
fn ping_stop_all(runtime: State<'_, Arc<PingRuntime>>) -> usize {
    let before = ping::runner::running_ids(runtime.inner()).len();
    ping::stop_all_pings(runtime.inner());
    before
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(ScanState::default()))
        .manage(Arc::new(PingRuntime::default()))
        .setup(|_app| {
            if let Err(e) = ping::init_db() {
                eprintln!("ping db init failed: {e}");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_network_scan,
            cancel_network_scan,
            get_common_ports,
            get_extended_common_ports,
            get_common_udp_ports,
            get_profiles,
            save_profile,
            remove_profile,
            get_allowlist,
            set_allowlist,
            export_results,
            get_audit_path,
            get_default_audit_path,
            set_audit_path,
            reset_audit_path,
            open_audit_location,
            get_oui_stats,
            get_local_network,
            ping_list_sessions,
            ping_create_session,
            ping_start,
            ping_stop,
            ping_list_results,
            ping_get_stats,
            ping_clear_session,
            ping_delete_session,
            ping_clear_all,
            ping_import_csv,
            ping_export_db,
            ping_import_db,
            ping_stop_all
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
