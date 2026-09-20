//! Agent memory: findings stored as markdown files under a caller-provided
//! directory (`<key>.md`), concatenated in sorted order to seed the system
//! prompt on subsequent sessions, so knowledge survives reopen.
//!
//! Storage-agnostic like the rest of the library: the host resolves and owns
//! the directory (e.g. `<project>/memory`) and passes it in — this module
//! only reads and writes files by name.

use std::fs;
use std::path::{Path, PathBuf};

/// Sanitize a memory key into a safe single file-name component.
fn sanitize_key(key: &str) -> String {
    let slug: String = key
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        "note".to_string()
    } else {
        slug
    }
}

fn key_path(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("{}.md", sanitize_key(key)))
}

pub fn save(dir: &Path, key: &str, value: &str) -> Result<(), String> {
    let path = key_path(dir, key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let content = format!("# {key}\n\n{value}\n");
    fs::write(&path, content).map_err(|e| e.to_string())
}

pub fn load(dir: &Path, key: &str) -> Result<String, String> {
    let path = key_path(dir, key);
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

pub fn remove(dir: &Path, key: &str) -> Result<(), String> {
    let path = key_path(dir, key);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// List memory keys (file stems, without `.md`), sorted.
pub fn list(dir: &Path) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    if dir.is_dir() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "md").unwrap_or(false) {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        out.push(stem.to_string());
                    }
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Concatenated memory, used to seed the system prompt on session start.
/// Missing or unreadable entries are skipped silently.
#[must_use]
pub fn summary(dir: &Path) -> String {
    let mut out = String::new();
    for key in list(dir).unwrap_or_default() {
        if let Ok(content) = load(dir, &key) {
            out.push_str(&content);
            out.push('\n');
        }
    }
    out
}
