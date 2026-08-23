use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A single reverse-engineering project. Backed by a directory at
/// `~/.recurse/<name>/` containing `project.json` (this metadata) plus any
/// files the project accumulates over time (reasoning graphs, chat history,
/// notes, extracted artifacts, etc.).
#[derive(Clone, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    pub binary_path: String,
    pub created_at: u64,
    pub updated_at: u64,
}

fn root() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    Ok(home.join(".recurse"))
}

pub fn project_dir(name: &str) -> Result<PathBuf, String> {
    Ok(root()?.join(name))
}

fn meta_path(name: &str) -> Result<PathBuf, String> {
    Ok(project_dir(name)?.join("project.json"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Project names become directory names, so they must be a single safe path
/// component (no separators, no traversal, non-empty).
pub fn validate_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("project name is empty".into());
    }
    if n == "." || n == ".." || n.contains('/') || n.contains('\\') || n.contains("..") {
        return Err("project name must be a single directory name".into());
    }
    Ok(())
}

pub fn create(name: &str, binary_path: &str) -> Result<Project, String> {
    let name = name.trim().to_string();
    validate_name(&name)?;
    if binary_path.trim().is_empty() {
        return Err("binary path is empty".into());
    }
    let dir = project_dir(&name)?;
    fs::create_dir_all(&dir).map_err(|e| format!("create project dir: {e}"))?;
    let ts = now();
    let p = Project {
        name,
        binary_path: binary_path.to_string(),
        created_at: ts,
        updated_at: ts,
    };
    write_meta(&p)?;
    Ok(p)
}

fn write_meta(p: &Project) -> Result<(), String> {
    let path = meta_path(&p.name)?;
    let s = serde_json::to_string_pretty(p).map_err(|e| e.to_string())?;
    fs::write(&path, s).map_err(|e| e.to_string())
}

fn read_meta(name: &str) -> Result<Project, String> {
    let path = meta_path(name)?;
    let s = fs::read_to_string(&path).map_err(|e| format!("read project.json: {e}"))?;
    serde_json::from_str(&s).map_err(|e| format!("parse project.json: {e}"))
}

/// All projects, most recently opened first.
pub fn list() -> Result<Vec<Project>, String> {
    let root = root()?;
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(&root) else {
        return Ok(out); // ~/.recurse doesn't exist yet
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if let Ok(p) = read_meta(name) {
                out.push(p);
            }
        }
    }
    out.sort_by_key(|p| std::cmp::Reverse(p.updated_at));
    Ok(out)
}

pub fn get(name: &str) -> Result<Project, String> {
    read_meta(name)
}

/// Bump `updated_at` (called when a project is opened).
pub fn touch(name: &str) -> Result<(), String> {
    let mut p = read_meta(name)?;
    p.updated_at = now();
    write_meta(&p)
}

pub fn remove(name: &str) -> Result<(), String> {
    let dir = project_dir(name)?;
    fs::remove_dir_all(&dir).map_err(|e| e.to_string())
}

/// Validate and normalize a project-relative path.
///
/// Rejects anything that could escape the project directory: absolute paths,
/// `..` components (which lexical `Path::starts_with` checks miss for
/// not-yet-existing files, e.g. writing "a/../../evil" resolves through the
/// OS even though the joined path string keeps the project prefix), and
/// empty segments beyond redundancy. Returns the cleaned relative path.
fn clean_rel(rel: &str) -> Result<String, String> {
    let path = Path::new(rel);
    if path.is_absolute() {
        return Err("absolute paths are not allowed".into());
    }
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(c) => {
                if c == ".." {
                    return Err("path escapes the project directory".into());
                }
                parts.push(c);
            }
            std::path::Component::CurDir => {}
            _ => return Err("path escapes the project directory".into()),
        }
    }
    if parts.is_empty() {
        return Err("path is empty".into());
    }
    let mut out = PathBuf::new();
    for p in parts {
        out.push(p);
    }
    out.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "path is not valid UTF-8".to_string())
}

/// Resolve a project-relative path and keep it inside the project directory.
fn safe_join(name: &str, rel: &str) -> Result<PathBuf, String> {
    let dir = project_dir(name)?;
    let rel = clean_rel(rel)?;
    let base = fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
    let joined = dir.join(&rel);
    let canon = fs::canonicalize(&joined).unwrap_or_else(|_| joined.clone());
    if !canon.starts_with(&base) {
        return Err("path escapes the project directory".into());
    }
    Ok(joined)
}

pub fn read_file(name: &str, rel: &str) -> Result<String, String> {
    let path = safe_join(name, rel)?;
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

pub fn write_file(name: &str, rel: &str, content: &str) -> Result<(), String> {
    let path = safe_join(name, rel)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&path, content).map_err(|e| e.to_string())
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, base, out);
        } else if let Ok(rel) = path.strip_prefix(base) {
            if let Some(s) = rel.to_str() {
                out.push(s.to_string());
            }
        }
    }
}

/// Recursive list of files in a project, as project-relative paths.
pub fn list_files(name: &str) -> Result<Vec<String>, String> {
    let dir = project_dir(name)?;
    let mut out = Vec::new();
    if dir.is_dir() {
        walk(&dir, &dir, &mut out);
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn name_validation() {
        assert!(validate_name("ok").is_ok());
        assert!(validate_name("  spaced  ").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name(".").is_err());
        assert!(validate_name("..").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("a\\b").is_err());
        assert!(validate_name("x..y").is_err());
    }

    #[test]
    fn project_crud_and_file_isolation() {
        crate::testhome::with_test_home(|_| {
            let p = create("proj", "/bin/true").unwrap();
            assert_eq!(p.name, "proj");
            assert_eq!(get("proj").unwrap().binary_path, "/bin/true");
            touch("proj").unwrap();

            write_file("proj", "notes/deep/file.txt", "hello").unwrap();
            assert_eq!(read_file("proj", "notes/deep/file.txt").unwrap(), "hello");

            // Traversal attempts are rejected outright.
            for bad in ["../evil", "a/../../evil", "/etc/passwd", "..", ""] {
                assert!(read_file("proj", bad).is_err(), "read {bad}");
                assert!(write_file("proj", bad, "x").is_err(), "write {bad}");
            }

            let files = list_files("proj").unwrap();
            assert!(files.contains(&"notes/deep/file.txt".to_string()));

            create("aaa", "/bin/true").unwrap();
            remove("aaa").unwrap();
            assert!(get("aaa").is_err());
        });
    }
}
