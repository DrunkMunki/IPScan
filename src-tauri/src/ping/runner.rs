use crate::ping::db::{self, PingResultRow};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::process::Command;
use tokio::time::{sleep, timeout};

#[derive(Default)]
pub struct PingRuntime {
    pub running: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingLiveEvent {
    pub session_id: String,
    pub result: PingResultRow,
}

pub fn stop_ping_session(runtime: &PingRuntime, session_id: &str) -> bool {
    if let Some(flag) = runtime.running.lock().remove(session_id) {
        flag.store(true, Ordering::Relaxed);
        true
    } else {
        false
    }
}

pub fn stop_all_pings(runtime: &PingRuntime) {
    let mut map = runtime.running.lock();
    for (_, flag) in map.drain() {
        flag.store(true, Ordering::Relaxed);
    }
}

pub fn running_ids(runtime: &PingRuntime) -> Vec<String> {
    runtime.running.lock().keys().cloned().collect()
}

pub async fn start_ping_session(
    app: AppHandle,
    runtime: Arc<PingRuntime>,
    session_id: String,
) -> Result<(), String> {
    {
        let map = runtime.running.lock();
        if map.contains_key(&session_id) {
            return Err("This ping tab is already running.".into());
        }
    }

    let session = db::get_session(&session_id)?
        .ok_or_else(|| "Ping session not found.".to_string())?;

    let cancel = Arc::new(AtomicBool::new(false));
    runtime
        .running
        .lock()
        .insert(session_id.clone(), Arc::clone(&cancel));

    let app2 = app.clone();
    let runtime2 = Arc::clone(&runtime);
    let target = session.target.clone();
    let interval = Duration::from_millis(session.interval_ms);
    let session_id2 = session_id.clone();

    tauri::async_runtime::spawn(async move {
        while !cancel.load(Ordering::Relaxed) {
            let outcome = run_one_ping(&target, 2_000).await;
            match db::insert_result(
                &session_id2,
                outcome.success,
                outcome.latency_ms,
                outcome.ttl,
                &outcome.message,
            ) {
                Ok(row) => {
                    let _ = app2.emit(
                        "ping-result",
                        PingLiveEvent {
                            session_id: session_id2.clone(),
                            result: row,
                        },
                    );
                }
                Err(err) => {
                    let _ = app2.emit("ping-error", format!("{session_id2}: {err}"));
                }
            }

            // Sleep in small slices so stop is responsive.
            let mut waited = Duration::ZERO;
            while waited < interval {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let step = Duration::from_millis(200).min(interval - waited);
                sleep(step).await;
                waited += step;
            }
        }

        runtime2.running.lock().remove(&session_id2);
        let _ = app2.emit("ping-stopped", session_id2);
    });

    Ok(())
}

struct PingOutcome {
    success: bool,
    latency_ms: Option<f64>,
    ttl: Option<i64>,
    message: String,
}

async fn run_one_ping(target: &str, timeout_ms: u64) -> PingOutcome {
    let mut cmd = Command::new("ping");

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.args(["-n", "1", "-w", &timeout_ms.to_string(), target]);
    }

    #[cfg(not(windows))]
    {
        let secs = ((timeout_ms + 999) / 1000).max(1).to_string();
        cmd.args(["-c", "1", "-W", &secs, target]);
    }

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = match timeout(Duration::from_millis(timeout_ms + 1500), cmd.output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return PingOutcome {
                success: false,
                latency_ms: None,
                ttl: None,
                message: format!("ping failed to start: {e}"),
            };
        }
        Err(_) => {
            return PingOutcome {
                success: false,
                latency_ms: None,
                ttl: None,
                message: "ping timed out".into(),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = if stdout.trim().is_empty() {
        stderr.to_string()
    } else {
        stdout.to_string()
    };

    if !output.status.success() {
        let msg = first_useful_line(&text).unwrap_or("Request timed out / host unreachable");
        return PingOutcome {
            success: false,
            latency_ms: None,
            ttl: None,
            message: msg.to_string(),
        };
    }

    let latency = parse_ping_rtt_ms(&text);
    let ttl = parse_ping_ttl(&text);
    let summary = match latency {
        Some(ms) => format!("Reply from {target}: time={ms:.0}ms{}", ttl.map(|t| format!(" ttl={t}")).unwrap_or_default()),
        None => first_useful_line(&text)
            .unwrap_or("Reply received")
            .to_string(),
    };

    PingOutcome {
        success: true,
        latency_ms: latency,
        ttl,
        message: summary,
    }
}

fn first_useful_line(text: &str) -> Option<&str> {
    text.lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty() && !l.starts_with("Pinging") && !l.starts_with("Ping statistics"))
}

fn parse_ping_rtt_ms(output: &str) -> Option<f64> {
    for token in output.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("time=") {
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(ms) = num.parse::<f64>() {
                return Some(ms);
            }
        }
        if lower.starts_with("time<") {
            return Some(1.0);
        }
    }
    let lower = output.to_ascii_lowercase();
    if let Some(idx) = lower.find("time=") {
        let rest = &lower[idx + 5..];
        let num: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if let Ok(ms) = num.parse::<f64>() {
            return Some(ms);
        }
    }
    None
}

fn parse_ping_ttl(output: &str) -> Option<i64> {
    for token in output.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("ttl=") {
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(ttl) = digits.parse::<i64>() {
                return Some(ttl);
            }
        }
    }
    None
}
