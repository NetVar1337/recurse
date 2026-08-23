use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::project;

/// Storage layout per project:
///
/// ```text
/// ~/.recurse/<project>/
///   project.json
///   memory/<key>.md              # shared by every session of the project
///   sessions/<id>/
///     session.json               # id, name, model, timestamps
///     chat.json                  # that session's conversation history
/// ```
const DEFAULT_PROJECT: &str = "default";
const DEFAULT_NAME: &str = "New session";

/// One agent conversation session.
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

fn sessions_dir(project: Option<&str>) -> Result<PathBuf, String> {
    Ok(project::project_dir(effective_project(project))?.join("sessions"))
}

fn session_dir(project: Option<&str>, id: &str) -> Result<PathBuf, String> {
    Ok(sessions_dir(project)?.join(id))
}

fn meta_path(project: Option<&str>, id: &str) -> Result<PathBuf, String> {
    Ok(session_dir(project, id)?.join("session.json"))
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

pub fn create(project: Option<&str>, model: &str) -> Result<Session, String> {
    let id = new_id();
    let ts = now();
    let s = Session {
        id: id.clone(),
        name: DEFAULT_NAME.to_string(),
        model: model.to_string(),
        created_at: ts,
        updated_at: ts,
    };
    let dir = session_dir(project, &id)?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_meta(project, &s)?;
    Ok(s)
}

fn write_meta(project: Option<&str>, s: &Session) -> Result<(), String> {
    let path = meta_path(project, &s.id)?;
    let json = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| e.to_string())
}

pub fn get(project: Option<&str>, id: &str) -> Result<Session, String> {
    let path = meta_path(project, id)?;
    let s = fs::read_to_string(&path).map_err(|e| format!("read session: {e}"))?;
    serde_json::from_str(&s).map_err(|e| format!("parse session: {e}"))
}

/// All sessions, most recently used first.
pub fn list(project: Option<&str>) -> Result<Vec<Session>, String> {
    let dir = sessions_dir(project)?;
    let mut out = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(&dir).map_err(|e| e.to_string())?.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if let Some(id) = path.file_name().and_then(|n| n.to_str()) {
                if let Ok(s) = get(project, id) {
                    out.push(s);
                }
            }
        }
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.updated_at));
    Ok(out)
}

pub fn set_name(project: Option<&str>, id: &str, name: &str) -> Result<(), String> {
    let mut s = get(project, id)?;
    let name = name.trim();
    if !name.is_empty() {
        s.name = name.to_string();
    }
    s.updated_at = now();
    write_meta(project, &s)
}

pub fn set_model(project: Option<&str>, id: &str, model: &str) -> Result<(), String> {
    let mut s = get(project, id)?;
    if !model.is_empty() {
        s.model = model.to_string();
    }
    write_meta(project, &s)
}

pub fn touch(project: Option<&str>, id: &str) -> Result<(), String> {
    let mut s = get(project, id)?;
    s.updated_at = now();
    write_meta(project, &s)
}

pub fn remove(project: Option<&str>, id: &str) -> Result<(), String> {
    let dir = session_dir(project, id)?;
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn save_history(project: Option<&str>, id: &str, json: &str) -> Result<(), String> {
    let path = session_dir(project, id)?.join("chat.json");
    fs::write(&path, json).map_err(|e| e.to_string())
}

pub fn load_history(project: Option<&str>, id: &str) -> Option<String> {
    let path = session_dir(project, id).ok()?.join("chat.json");
    fs::read_to_string(path).ok()
}

/// Remove the obsolete `<project>/history` directories that predate sessions.
/// Only directories owned by this app are touched; the config (API key) is kept.
pub fn cleanup_legacy() {
    let Some(home) = dirs::home_dir() else {
        return;
    };
    let root = home.join(".recurse");
    if !root.is_dir() {
        return;
    }
    if let Ok(entries) = fs::read_dir(&root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let legacy = path.join("history");
            if legacy.exists() {
                let _ = fs::remove_dir_all(&legacy);
            }
            // Drop a stray empty "default" project (no-project leftovers).
            if path.file_name().and_then(|n| n.to_str()) == Some(DEFAULT_PROJECT) {
                let _ = fs::remove_dir_all(&path);
            }
        }
    }
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
            // Empty/whitespace names are ignored.
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
