use std::fs;
use std::path::PathBuf;

use crate::project;

/// Per-project agent memory. Findings are stored as markdown files under
/// `~/.recurse/<project>/memory/<key>.md` and injected back into the agent's
/// system prompt on subsequent sessions, so knowledge survives reopen.
///
/// `project` is the current project name (or a default when no project is
/// active).
const DEFAULT_PROJECT: &str = "default";

fn memory_dir(project: &str) -> Result<PathBuf, String> {
    Ok(project::project_dir(project)?.join("memory"))
}

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

fn key_path(project: &str, key: &str) -> Result<PathBuf, String> {
    Ok(memory_dir(project)?.join(format!("{}.md", sanitize_key(key))))
}

fn effective_project(project: Option<&str>) -> &str {
    project.unwrap_or(DEFAULT_PROJECT)
}

pub fn save(project: Option<&str>, key: &str, value: &str) -> Result<(), String> {
    let project = effective_project(project);
    let path = key_path(project, key)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let content = format!("# {key}\n\n{value}\n");
    fs::write(&path, content).map_err(|e| e.to_string())
}

pub fn load(project: Option<&str>, key: &str) -> Result<String, String> {
    let project = effective_project(project);
    let path = key_path(project, key)?;
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

pub fn remove(project: Option<&str>, key: &str) -> Result<(), String> {
    let project = effective_project(project);
    let path = key_path(project, key)?;
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// List memory keys (file stems, without `.md`).
pub fn list(project: Option<&str>) -> Result<Vec<String>, String> {
    let project = effective_project(project);
    let dir = memory_dir(project)?;
    let mut out = Vec::new();
    if dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&dir) {
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
///
/// When `query` is provided and the optional `qmd` CLI is installed, memory
/// entries are ordered by its relevance ranking for the query; otherwise the
/// default sorted order applies. Any absence or failure of the external tool
/// degrades silently to plain concatenation.
#[must_use]
pub fn summary(project: Option<&str>) -> String {
    let keys = ranked_keys(project, None);
    let mut out = String::new();
    for key in keys {
        if let Ok(content) = load(project, &key) {
            out.push_str(&content);
            out.push('\n');
        }
    }
    out
}

/// Query-aware summary used by the agent: memory ranked by relevance to the
/// user's message when `qmd` is available.
#[must_use]
pub fn summary_for(project: Option<&str>, query: &str) -> String {
    let keys = ranked_keys(project, Some(query));
    let mut out = String::new();
    for key in keys {
        if let Ok(content) = load(project, &key) {
            out.push_str(&content);
            out.push('\n');
        }
    }
    out
}

/// Keys ordered by `qmd` relevance to `query` when available, else sorted.
fn ranked_keys(project: Option<&str>, query: Option<&str>) -> Vec<String> {
    let mut keys = list(project).unwrap_or_default();
    if let Some(q) = query {
        if let Ok(dir) = memory_dir(effective_project(project)) {
            if dir.is_dir() {
                if let Ok(ranked) = qmd_rank(&dir, q) {
                    keys.sort_by_key(|k| ranked.iter().position(|r| r == k).unwrap_or(usize::MAX));
                }
            }
        }
    }
    keys
}

/// Ask the optional `qmd` CLI to rank memory files by relevance.
/// Contract: `qmd search <query> <dir>` prints matching file paths, best
/// first. Missing binary or any error yields an empty ranking.
fn qmd_rank(dir: &std::path::Path, query: &str) -> Result<Vec<String>, ()> {
    use std::process::{Command, Stdio};
    let out = Command::new("qmd")
        .arg("search")
        .arg(query)
        .arg(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ())?;
    if !out.status.success() {
        return Err(());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut ranked: Vec<String> = Vec::new();
    for line in text.lines() {
        let p = std::path::Path::new(line.trim());
        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
            if !ranked.iter().any(|r: &String| r == stem) {
                ranked.push(stem.to_string());
            }
        }
    }
    Ok(ranked)
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn sanitize_rules() {
        assert_eq!(sanitize_key("Hello World!"), "Hello_World");
        assert_eq!(sanitize_key("--a--"), "--a--");
        assert_eq!(sanitize_key("///"), "note");
        assert_eq!(sanitize_key("ok_1-2"), "ok_1-2");
    }

    #[test]
    fn save_load_remove_list_and_summary_order() {
        crate::testhome::with_test_home(|_| {
            save(Some("p"), "beta", "second").unwrap();
            save(Some("p"), "alpha", "first").unwrap();
            assert_eq!(load(Some("p"), "alpha").unwrap(), "# alpha\n\nfirst\n");
            assert_eq!(list(Some("p")).unwrap(), vec!["alpha", "beta"]);
            let sum = summary(Some("p"));
            let a = sum.find("# alpha").unwrap();
            let b = sum.find("# beta").unwrap();
            assert!(a < b, "default order is sorted");
            remove(Some("p"), "alpha").unwrap();
            assert!(load(Some("p"), "alpha").is_err());
            remove(Some("p"), "missing").unwrap(); // idempotent
        });
    }
}
