use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::db;

/// One agent conversation session. Rows in the `sessions` table;
/// conversation history is the `chat_json` column (no `chat.json` files).
const DEFAULT_PROJECT: &str = "default";
const DEFAULT_NAME: &str = "New session";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: String,
    pub model: String,
    pub created_at: u64,
    pub updated_at: u64,
}

fn effective_project(project: Option<&str>) -> &str {
    project.unwrap_or(DEFAULT_PROJECT)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Monotonic counter mixed into ids so rapid creation can never collide on
/// the nanosecond timestamp alone.
static ID_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn new_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = ID_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    format!("s-{nanos:x}-{seq:x}")
}

fn row_to_session(
    id: String,
    name: String,
    model: String,
    created_at: i64,
    updated_at: i64,
) -> Session {
    Session {
        id,
        name,
        model,
        created_at: created_at.max(0) as u64,
        updated_at: updated_at.max(0) as u64,
    }
}

pub fn create(project: Option<&str>, model: &str) -> Result<Session, String> {
    let id = new_id();
    let ts = now() as i64;
    let conn = db::connect()?;
    conn.execute(
        "INSERT INTO sessions (id, project_name, name, model, created_at, updated_at, chat_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, '[]')",
        params![
            id,
            effective_project(project),
            DEFAULT_NAME,
            model,
            ts
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(row_to_session(
        id,
        DEFAULT_NAME.to_string(),
        model.to_string(),
        ts,
        ts,
    ))
}

pub fn get(project: Option<&str>, id: &str) -> Result<Session, String> {
    let conn = db::connect()?;
    conn.query_row(
        "SELECT id, name, model, created_at, updated_at FROM sessions
         WHERE id = ?1 AND project_name = ?2",
        params![id, effective_project(project)],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )
    .map(|(id, name, model, created_at, updated_at)| {
        row_to_session(id, name, model, created_at, updated_at)
    })
    .map_err(|_| format!("session not found: {id}"))
}

/// All sessions, most recently used first.
pub fn list(project: Option<&str>) -> Result<Vec<Session>, String> {
    let conn = db::connect()?;
    let mut stmt = conn
        .prepare(
            "SELECT id, name, model, created_at, updated_at FROM sessions
             WHERE project_name = ?1 ORDER BY updated_at DESC",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![effective_project(project)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        match row {
            Ok((id, name, model, created_at, updated_at)) => {
                out.push(row_to_session(id, name, model, created_at, updated_at));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(out)
}

pub fn set_name(project: Option<&str>, id: &str, name: &str) -> Result<(), String> {
    let name = name.trim();
    let conn = db::connect()?;
    let n = if name.is_empty() {
        conn.execute(
            "UPDATE sessions SET updated_at = ?1 WHERE id = ?2 AND project_name = ?3",
            params![now() as i64, id, effective_project(project)],
        )
        .map_err(|e| e.to_string())?
    } else {
        conn.execute(
            "UPDATE sessions SET name = ?1, updated_at = ?2
             WHERE id = ?3 AND project_name = ?4",
            params![name, now() as i64, id, effective_project(project)],
        )
        .map_err(|e| e.to_string())?
    };
    if n == 0 {
        return Err(format!("session not found: {id}"));
    }
    Ok(())
}

pub fn set_model(project: Option<&str>, id: &str, model: &str) -> Result<(), String> {
    if model.is_empty() {
        return Ok(());
    }
    let conn = db::connect()?;
    conn.execute(
        "UPDATE sessions SET model = ?1 WHERE id = ?2 AND project_name = ?3",
        params![model, id, effective_project(project)],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn touch(project: Option<&str>, id: &str) -> Result<(), String> {
    let conn = db::connect()?;
    conn.execute(
        "UPDATE sessions SET updated_at = ?1 WHERE id = ?2 AND project_name = ?3",
        params![now() as i64, id, effective_project(project)],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn remove(project: Option<&str>, id: &str) -> Result<(), String> {
    let conn = db::connect()?;
    conn.execute(
        "DELETE FROM sessions WHERE id = ?1 AND project_name = ?2",
        params![id, effective_project(project)],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn save_history(project: Option<&str>, id: &str, json: &str) -> Result<(), String> {
    let conn = db::connect()?;
    conn.execute(
        "UPDATE sessions SET chat_json = ?1 WHERE id = ?2 AND project_name = ?3",
        params![json, id, effective_project(project)],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn load_history(project: Option<&str>, id: &str) -> Option<String> {
    let conn = db::connect().ok()?;
    conn.query_row(
        "SELECT chat_json FROM sessions WHERE id = ?1 AND project_name = ?2",
        params![id, effective_project(project)],
        |row| row.get(0),
    )
    .ok()
}

/// Remove pre-SQLite filesystem metadata. No migration: stale
/// `project.json` / `sessions/` / `memory/*.md` / `history/` dirs and the
/// top-level `config.json` are deleted; LLM-written project files are kept.
pub fn cleanup_legacy() {
    db::cleanup_legacy_filesystem();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn ids_are_unique_under_rapid_creation() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let id = new_id();
            assert!(seen.insert(id), "id collision");
        }
    }

    #[test]
    fn session_crud_and_history() {
        crate::testhome::with_test_home(|_| {
            let s = create(Some("p"), "model-a").unwrap();
            assert_eq!(s.model, "model-a");
            set_name(Some("p"), &s.id, "  renamed  ").unwrap();
            assert_eq!(get(Some("p"), &s.id).unwrap().name, "renamed");
            // Empty/whitespace names bump recency but keep the name.
            set_name(Some("p"), &s.id, "   ").unwrap();
            assert_eq!(get(Some("p"), &s.id).unwrap().name, "renamed");
            set_model(Some("p"), &s.id, "model-b").unwrap();
            assert_eq!(get(Some("p"), &s.id).unwrap().model, "model-b");
            touch(Some("p"), &s.id).unwrap();

            save_history(Some("p"), &s.id, "[{\"role\":\"user\"}]").unwrap();
            assert!(load_history(Some("p"), &s.id).is_some());

            let all = list(Some("p")).unwrap();
            assert_eq!(all.len(), 1);

            remove(Some("p"), &s.id).unwrap();
            assert!(get(Some("p"), &s.id).is_err());
            assert!(load_history(Some("p"), &s.id).is_none());
        });
    }
}
