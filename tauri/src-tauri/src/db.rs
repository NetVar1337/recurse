//! SQLite storage, owned by the Tauri host.
//!
//! Single file at `~/.recurse/recurse.db` (WAL mode). Table ownership:
//!
//! - host (`db.rs`, `project.rs`, `sessions.rs`, `config.rs`, `renames.rs`,
//!   `providers.rs`): `config`, `projects`, `sessions`, `models`,
//!   `function_names`, `provider_credentials`
//! - recurse_agent (`recurse_agent::memory`): `memories`, `memories_fts`
//!
//! The filesystem under `~/.recurse/<project>/` is reserved for
//! LLM-written project code (`project_read_file` / `project_write_file`);
//! all metadata, model info and memories live in this DB.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    name TEXT PRIMARY KEY,
    binary_path TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    name TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    chat_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_sessions_project
    ON sessions (project_name, updated_at DESC);
CREATE TABLE IF NOT EXISTS models (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    context_length INTEGER NOT NULL DEFAULT 0,
    prompt_price TEXT NOT NULL DEFAULT '',
    is_free INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS function_names (
    binary_path TEXT NOT NULL,
    addr INTEGER NOT NULL,
    name TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (binary_path, addr)
);
CREATE TABLE IF NOT EXISTS provider_credentials (
    provider_id TEXT PRIMARY KEY,
    api_key TEXT,
    oauth_json TEXT,
    updated_at INTEGER NOT NULL
);
";

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The user's home directory, honoring a `HOME` environment variable
/// override before falling back to the OS default.
///
/// `dirs::home_dir()` alone is not enough: on Windows its implementation
/// resolves the real profile directory via the Known Folder API and
/// **ignores `$HOME` entirely** — `crate::testhome`'s test isolation
/// (`std::env::set_var("HOME", …)`) is a silent no-op there, so every
/// `with_test_home`-based test was actually reading/writing the real
/// user's `~/.recurse` on Windows instead of a throwaway directory. On
/// Unix, `dirs::home_dir()` already reads `$HOME` itself, so checking it
/// here first is a harmless no-op — this makes the override work
/// uniformly on every platform instead of only where `dirs` happens to
/// agree with it.
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(dirs::home_dir)
}

pub fn db_path() -> Result<PathBuf, String> {
    let home = home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    Ok(home.join(".recurse").join("recurse.db"))
}

/// Open the DB, creating parent dirs and running all migrations
/// (host tables + recurse_agent memory tables). Safe to call on every access.
pub fn connect() -> Result<Connection, String> {
    let path = db_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create db dir: {e}"))?;
    }
    let conn = Connection::open(&path).map_err(|e| format!("open db: {e}"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| format!("db busy timeout: {e}"))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .map_err(|e| format!("db pragmas: {e}"))?;
    conn.execute_batch(SCHEMA_SQL)
        .map_err(|e| format!("db schema: {e}"))?;
    recurse_agent::memory::ensure_schema(&conn)?;
    Ok(conn)
}

/// Memory store bound to the same DB file. All memory CRUD/search goes
/// through recurse_agent — the host never touches the `memories` tables.
pub fn memory_store() -> Result<recurse_agent::memory::MemoryStore, String> {
    Ok(recurse_agent::memory::MemoryStore::new(db_path()?))
}

/// Delete pre-SQLite filesystem metadata. No migration: stale
/// `project.json` / `sessions/` / `memory/*.md` / `config.json` / legacy
/// `history/` dirs are removed, LLM-written project files are kept.
pub fn cleanup_legacy_filesystem() {
    let Some(home) = home_dir() else {
        return;
    };
    let root = home.join(".recurse");
    if !root.is_dir() {
        return;
    }
    // Top-level config from the JSON era.
    let _ = std::fs::remove_file(root.join("config.json"));
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // Stray empty "default" project leftovers.
        if path.file_name().and_then(|n| n.to_str()) == Some("default")
            && path.join("project.json").exists()
        {
            let _ = std::fs::remove_dir_all(&path);
            continue;
        }
        let _ = std::fs::remove_file(path.join("project.json"));
        let _ = std::fs::remove_dir_all(path.join("sessions"));
        let _ = std::fs::remove_dir_all(path.join("memory"));
        let _ = std::fs::remove_dir_all(path.join("history"));
    }
}
