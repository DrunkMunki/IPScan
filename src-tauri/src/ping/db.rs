use chrono::Local;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingSession {
    pub id: String,
    pub title: String,
    pub target: String,
    pub interval_ms: u64,
    pub table_name: String,
    pub created_at: String,
    pub updated_at: String,
    pub running: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingResultRow {
    pub id: i64,
    pub session_id: String,
    pub ts: String,
    pub success: bool,
    pub latency_ms: Option<f64>,
    pub ttl: Option<i64>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingStatSummary {
    pub session_id: String,
    pub total: u64,
    pub success: u64,
    pub failed: u64,
    pub drop_percent: f64,
    pub avg_latency_ms: Option<f64>,
    pub min_latency_ms: Option<f64>,
    pub max_latency_ms: Option<f64>,
    pub last_ts: Option<String>,
    pub last_success: Option<bool>,
}

fn db_path() -> Result<PathBuf, String> {
    // %AppData%\ipscan\ping.db on Windows
    let base = dirs::data_dir().ok_or_else(|| "Could not resolve app data directory.".to_string())?;
    let dir = base.join("ipscan");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("ping.db"))
}

fn wal_sidecar_paths(db: &PathBuf) -> (PathBuf, PathBuf) {
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    let shm = PathBuf::from(format!("{}-shm", db.display()));
    (wal, shm)
}

fn checkpoint_and_close() -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Export the live ping database (sessions + history) to `dest`.
pub fn export_database(dest: &str) -> Result<(), String> {
    let dest_path = PathBuf::from(dest);
    if dest_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("db"))
        != Some(true)
    {
        return Err("Export path must end with .db".into());
    }
    checkpoint_and_close()?;
    let src = db_path()?;
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::copy(&src, &dest_path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Replace the live ping database with a previously exported `.db` file.
/// Caller must stop all running pings first.
pub fn import_database(src: &str) -> Result<(), String> {
    let src_path = PathBuf::from(src);
    if !src_path.is_file() {
        return Err("Database file not found.".into());
    }
    checkpoint_and_close()?;
    let dest = db_path()?;
    let (wal, shm) = wal_sidecar_paths(&dest);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&shm);
    std::fs::copy(&src_path, &dest).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&shm);
    init_db()?;
    // Prove the imported file has the expected schema.
    let _ = list_sessions(&[])?;
    Ok(())
}

fn is_header_label(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "ip" | "host" | "hostname" | "target" | "address" | "title" | "name"
    )
}

fn parse_csv_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut first_data_line = true;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let cell = first_csv_field(trimmed);
        if cell.is_empty() {
            continue;
        }
        if first_data_line {
            first_data_line = false;
            if is_header_label(&cell) {
                continue;
            }
        } else if is_header_label(&cell) {
            continue;
        }
        if seen.insert(cell.to_ascii_lowercase()) {
            out.push(cell);
        }
    }
    out
}

fn first_csv_field(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    let quoted = chars.peek() == Some(&'"');
    if quoted {
        chars.next();
        while let Some(c) = chars.next() {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    out.push('"');
                } else {
                    break;
                }
            } else {
                out.push(c);
            }
        }
    } else {
        for c in chars {
            if c == ',' || c == ';' || c == '\t' {
                break;
            }
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// Create a ping tab for each IP/hostname found in a CSV (first column, or one per line).
pub fn import_targets_from_csv(path: &str, interval_ms: u64) -> Result<Vec<PingSession>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let targets = parse_csv_targets(&text);
    if targets.is_empty() {
        return Err("No IP/hostname values found in CSV.".into());
    }
    if targets.len() > 500 {
        return Err(format!(
            "CSV has {} targets (max 500). Split the file and import in batches.",
            targets.len()
        ));
    }
    let mut sessions = Vec::with_capacity(targets.len());
    for target in targets {
        sessions.push(create_session("", &target, interval_ms)?);
    }
    Ok(sessions)
}

pub fn open_connection() -> Result<Connection, String> {
    let path = db_path()?;
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
        .map_err(|e| e.to_string())?;
    Ok(conn)
}

pub fn init_db() -> Result<(), String> {
    let conn = open_connection()?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS ping_sessions (
            id TEXT PRIMARY KEY NOT NULL,
            title TEXT NOT NULL,
            target TEXT NOT NULL,
            interval_ms INTEGER NOT NULL,
            table_name TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn sanitize_table_name(session_id: &str) -> String {
    let hex: String = session_id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    format!("ping_tab_{hex}")
}

fn create_tab_table(conn: &Connection, table_name: &str) -> Result<(), String> {
    if !table_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("Invalid ping table name.".into());
    }
    let sql = format!(
        r#"
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            success INTEGER NOT NULL,
            latency_ms REAL,
            ttl INTEGER,
            message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{table_name}_ts ON {table_name}(ts);
        "#
    );
    conn.execute_batch(&sql).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn create_session(title: &str, target: &str, interval_ms: u64) -> Result<PingSession, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("Ping target is required.".into());
    }
    let interval_ms = interval_ms.clamp(500, 3_600_000);
    let id = Uuid::new_v4().to_string();
    let table_name = sanitize_table_name(&id);
    let now = Local::now().to_rfc3339();
    let title = if title.trim().is_empty() {
        target.to_string()
    } else {
        title.trim().to_string()
    };

    let conn = open_connection()?;
    create_tab_table(&conn, &table_name)?;
    conn.execute(
        "INSERT INTO ping_sessions (id, title, target, interval_ms, table_name, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![id, title, target, interval_ms as i64, table_name, now, now],
    )
    .map_err(|e| e.to_string())?;

    Ok(PingSession {
        id,
        title,
        target: target.to_string(),
        interval_ms,
        table_name,
        created_at: now.clone(),
        updated_at: now,
        running: false,
    })
}

pub fn list_sessions(running: &[String]) -> Result<Vec<PingSession>, String> {
    let conn = open_connection()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, title, target, interval_ms, table_name, created_at, updated_at
             FROM ping_sessions ORDER BY created_at ASC",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok(PingSession {
                id: row.get(0)?,
                title: row.get(1)?,
                target: row.get(2)?,
                interval_ms: row.get::<_, i64>(3)? as u64,
                table_name: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                running: false,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows {
        let mut s = row.map_err(|e| e.to_string())?;
        s.running = running.iter().any(|id| id == &s.id);
        out.push(s);
    }
    Ok(out)
}

pub fn get_session(id: &str) -> Result<Option<PingSession>, String> {
    let conn = open_connection()?;
    conn.query_row(
        "SELECT id, title, target, interval_ms, table_name, created_at, updated_at
         FROM ping_sessions WHERE id = ?1",
        params![id],
        |row| {
            Ok(PingSession {
                id: row.get(0)?,
                title: row.get(1)?,
                target: row.get(2)?,
                interval_ms: row.get::<_, i64>(3)? as u64,
                table_name: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                running: false,
            })
        },
    )
    .optional()
    .map_err(|e| e.to_string())
}

pub fn touch_session(id: &str) -> Result<(), String> {
    let conn = open_connection()?;
    let now = Local::now().to_rfc3339();
    conn.execute(
        "UPDATE ping_sessions SET updated_at = ?1 WHERE id = ?2",
        params![now, id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn insert_result(
    session_id: &str,
    success: bool,
    latency_ms: Option<f64>,
    ttl: Option<i64>,
    message: &str,
) -> Result<PingResultRow, String> {
    let session = get_session(session_id)?.ok_or_else(|| "Ping session not found.".to_string())?;
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let conn = open_connection()?;
    conn.execute(
        &format!(
            "INSERT INTO {} (ts, success, latency_ms, ttl, message) VALUES (?1, ?2, ?3, ?4, ?5)",
            session.table_name
        ),
        params![ts, success as i64, latency_ms, ttl, message],
    )
    .map_err(|e| e.to_string())?;
    let id = conn.last_insert_rowid();
    touch_session(session_id)?;
    Ok(PingResultRow {
        id,
        session_id: session_id.to_string(),
        ts,
        success,
        latency_ms,
        ttl,
        message: message.to_string(),
    })
}

pub fn list_recent_results(session_id: &str, limit: u32) -> Result<Vec<PingResultRow>, String> {
    let session = get_session(session_id)?.ok_or_else(|| "Ping session not found.".to_string())?;
    let limit = limit.clamp(1, 5_000);
    let conn = open_connection()?;
    let sql = format!(
        "SELECT id, ts, success, latency_ms, ttl, message FROM {} ORDER BY id DESC LIMIT ?1",
        session.table_name
    );
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(PingResultRow {
                id: row.get(0)?,
                session_id: session_id.to_string(),
                ts: row.get(1)?,
                success: row.get::<_, i64>(2)? != 0,
                latency_ms: row.get(3)?,
                ttl: row.get(4)?,
                message: row.get(5)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    out.reverse();
    Ok(out)
}

pub fn get_session_stats(session_id: &str) -> Result<PingStatSummary, String> {
    let session = get_session(session_id)?.ok_or_else(|| "Ping session not found.".to_string())?;
    let conn = open_connection()?;
    let sql = format!(
        "SELECT
            COUNT(*),
            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END),
            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END),
            AVG(CASE WHEN success = 1 THEN latency_ms END),
            MIN(CASE WHEN success = 1 THEN latency_ms END),
            MAX(CASE WHEN success = 1 THEN latency_ms END),
            MAX(ts)
         FROM {}",
        session.table_name
    );
    let (total, success, failed, avg, min, max, last_ts): (
        i64,
        i64,
        i64,
        Option<f64>,
        Option<f64>,
        Option<f64>,
        Option<String>,
    ) = conn
        .query_row(&sql, [], |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    let last_success: Option<bool> = conn
        .query_row(
            &format!(
                "SELECT success FROM {} ORDER BY id DESC LIMIT 1",
                session.table_name
            ),
            [],
            |row| Ok(row.get::<_, i64>(0)? != 0),
        )
        .optional()
        .map_err(|e| e.to_string())?;

    let drop_percent = if total > 0 {
        (failed as f64) * 100.0 / (total as f64)
    } else {
        0.0
    };

    Ok(PingStatSummary {
        session_id: session_id.to_string(),
        total: total as u64,
        success: success as u64,
        failed: failed as u64,
        drop_percent,
        avg_latency_ms: avg,
        min_latency_ms: min,
        max_latency_ms: max,
        last_ts,
        last_success,
    })
}

pub fn clear_session_results(session_id: &str) -> Result<(), String> {
    let session = get_session(session_id)?.ok_or_else(|| "Ping session not found.".to_string())?;
    let conn = open_connection()?;
    conn.execute(&format!("DELETE FROM {}", session.table_name), [])
        .map_err(|e| e.to_string())?;
    touch_session(session_id)?;
    Ok(())
}

pub fn delete_session(session_id: &str) -> Result<(), String> {
    let session = get_session(session_id)?.ok_or_else(|| "Ping session not found.".to_string())?;
    let conn = open_connection()?;
    conn.execute(
        &format!("DROP TABLE IF EXISTS {}", session.table_name),
        [],
    )
    .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM ping_sessions WHERE id = ?1", params![session_id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn clear_all_sessions() -> Result<(), String> {
    let sessions = list_sessions(&[])?;
    let conn = open_connection()?;
    for s in sessions {
        let _ = conn.execute(&format!("DROP TABLE IF EXISTS {}", s.table_name), []);
    }
    conn.execute("DELETE FROM ping_sessions", [])
        .map_err(|e| e.to_string())?;
    Ok(())
}
