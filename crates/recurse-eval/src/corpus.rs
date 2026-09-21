//! Corpus management, Rust only: download each task's zip from crackmes.one,
//! extract (password `crackmes.one`), recursively expand nested archives
//! (.zip/.tar/.tgz/.tar.gz/.gz), and locate the binary.
//!
//! Binaries live under `<corpus>/<hexid>/` (gitignored) and are joined to
//! the tier manifest by `hexid`. Bulk crawling is avoided by design: one
//! small download per task, only for tasks in the active tier.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::Task;

const DOWNLOAD_URL: &str = "https://crackmes.one/download/crackme/";
const ZIP_PASSWORD: &[u8] = b"crackmes.one";
/// Cap nested-archive expansion rounds (zip-in-zip-in-tar ...).
const MAX_EXPAND_ROUNDS: usize = 5;

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent("recurse-eval/0.1")
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// Download the dataset JSONL once and cache it locally (15MB upstream).
pub async fn ensure_dataset_jsonl(cache: &Path, url: &str) -> Result<(), String> {
    if cache.is_file() {
        return Ok(());
    }
    if let Some(parent) = cache.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create corpus dir: {e}"))?;
    }
    let client = http_client()?;
    let bytes = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("download dataset: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download dataset: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("download dataset body: {e}"))?;
    std::fs::write(cache, &bytes).map_err(|e| format!("store dataset: {e}"))?;
    Ok(())
}

/// Ensure `corpus/<hexid>/` holds the extracted task files and return the
/// binary path. Reuses a previous fetch via the manifest `binary` path, or
/// via a `.fetched` marker when the binary is located by magic bytes.
pub async fn ensure_task_binary(corpus_dir: &Path, task: &Task) -> Result<PathBuf, String> {
    let task_dir = corpus_dir.join(&task.hexid);
    let manifest_path = task_dir.join(&task.binary);
    if manifest_path.is_file() {
        return Ok(manifest_path);
    }
    if task.binary.is_empty() && task_dir.join(".fetched").is_file() {
        return pick_binary_by_magic(&task_dir)
            .ok_or_else(|| format!("no binary found in cached {}", task_dir.display()));
    }
    std::fs::create_dir_all(&task_dir).map_err(|e| format!("create corpus dir: {e}"))?;

    let client = http_client()?;
    let bytes = client
        .get(format!("{DOWNLOAD_URL}{}", task.hexid))
        .send()
        .await
        .map_err(|e| format!("download {}: {e}", task.hexid))?
        .error_for_status()
        .map_err(|e| format!("download {}: {e}", task.hexid))?
        .bytes()
        .await
        .map_err(|e| format!("download body {}: {e}", task.hexid))?;

    if bytes.len() >= 2 && &bytes[..2] == b"PK" {
        extract_zip_bytes(&bytes, &task_dir)?;
    } else {
        // Single-file download (rare): store it and let nested expansion
        // below handle .gz/.tar wrappers.
        let name = format!("{}.bin", task.hexid);
        std::fs::write(task_dir.join(&name), &bytes).map_err(|e| format!("store {name}: {e}"))?;
    }
    expand_nested(&task_dir)?;

    if manifest_path.is_file() {
        let _ = std::fs::write(task_dir.join(".fetched"), "ok");
        make_executable(&manifest_path);
        return Ok(manifest_path);
    }
    // Manifest path missed (renamed upstream?) — fall back to magic-byte
    // detection: first ELF/MZ file, largest wins.
    let picked = pick_binary_by_magic(&task_dir).ok_or_else(|| {
        format!(
            "binary '{}' not found for {} after extraction",
            task.binary, task.hexid
        )
    })?;
    let _ = std::fs::write(task_dir.join(".fetched"), "ok");
    make_executable(&picked);
    Ok(picked)
}

/// Ensure the target binary is runnable. Archive extraction writes plain
/// files (no mode preservation), so without this the agent could analyze a
/// crackme but never execute it — i.e. the task couldn't be verified by
/// running it. Best-effort: a read-only filesystem is not fatal.
fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            // rwxr-xr-x, plus whatever was already set (e.g. group/other write).
            perms.set_mode(perms.mode() | 0o755);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Reject archive-slip paths: no absolute paths, no `..`, no empty segments.
/// Treats `\` as a separator too (7z/zip entries written on Windows).
fn sanitize_zip_path(name: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    let mut any = false;
    let normalized = name.replace('\\', "/");
    for part in normalized.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        out.push(part);
        any = true;
    }
    any.then_some(out)
}

/// Extract a zip, trying plain read per entry first and the site password
/// (`crackmes.one`) on encrypted entries. Used for top-level and nested
/// zips. Names come from the central directory first because the `zip`
/// crate refuses to open encrypted entries without a password.
fn extract_zip_bytes(bytes: &[u8], dir: &Path) -> Result<(), String> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("open zip: {e}"))?;
    let names: Vec<String> = archive.file_names().map(|s| s.to_string()).collect();
    for name in &names {
        let is_dir = name.ends_with('/');
        let Some(rel) = sanitize_zip_path(name) else {
            continue;
        };
        let out = dir.join(rel);
        if is_dir {
            std::fs::create_dir_all(&out).map_err(|e| format!("mkdir zip: {e}"))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir zip: {e}"))?;
        }
        // One unreadable entry (e.g. author-passworded file inside an
        // otherwise open archive) must not sink the whole extraction.
        match read_zip_file(&mut archive, name) {
            Ok(bytes) => {
                std::fs::write(&out, bytes).map_err(|e| format!("write zip: {e}"))?;
            }
            Err(e) => eprintln!("warning: skipping zip entry {name}: {e}"),
        }
    }
    Ok(())
}

fn read_zip_file(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<Vec<u8>, String> {
    use std::io::Read;
    // Plain entries first; encrypted ones fail here and retry with password.
    if let Ok(mut file) = archive.by_name(name) {
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_ok() {
            return Ok(buf);
        }
    }
    let mut file = archive
        .by_name_decrypt(name, ZIP_PASSWORD)
        .map_err(|e| format!("zip decrypt {name}: {e}"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| format!("zip read {name}: {e}"))?;
    Ok(buf)
}

/// Repeatedly expand nested archives in place until no progress (cap rounds).
fn expand_nested(dir: &Path) -> Result<(), String> {
    for _ in 0..MAX_EXPAND_ROUNDS {
        let mut archives = Vec::new();
        collect_archives(dir, &mut archives);
        if archives.is_empty() {
            return Ok(());
        }
        for path in archives {
            expand_one(&path)?;
        }
    }
    Ok(())
}

fn collect_archives(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip macOS resource forks and the manifest binary's own dir noise.
            if path.file_name().map(|n| n == "__MACOSX").unwrap_or(false) {
                continue;
            }
            collect_archives(&path, out);
        } else if archive_kind(&path).is_some() {
            out.push(path);
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum ArchiveKind {
    Zip,
    SevenZ,
    TarGz,
    Tar,
    Gz,
}

fn archive_kind(path: &Path) -> Option<ArchiveKind> {
    let name = path.file_name()?.to_str()?.to_lowercase();
    // `.jar` is a zip; expanding it surfaces the `.class` files.
    if name.ends_with(".zip") || name.ends_with(".jar") {
        Some(ArchiveKind::Zip)
    } else if name.ends_with(".7z") {
        Some(ArchiveKind::SevenZ)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Some(ArchiveKind::TarGz)
    } else if name.ends_with(".tar") {
        Some(ArchiveKind::Tar)
    } else if name.ends_with(".gz") {
        Some(ArchiveKind::Gz)
    } else {
        None
    }
}

/// Extract a 7z archive (some corpus entries nest one inside the outer zip).
/// Tries no password first, then the site password. Rust-only via
/// `sevenz-rust2` — no system `7z` binary required.
fn extract_7z_bytes(bytes: &[u8], dir: &Path) -> Result<(), String> {
    let mut last = String::new();
    for password in [
        sevenz_rust2::Password::empty(),
        sevenz_rust2::Password::new("crackmes.one"),
    ] {
        match extract_7z_once(bytes, dir, password) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn extract_7z_once(
    bytes: &[u8],
    dir: &Path,
    password: sevenz_rust2::Password,
) -> Result<(), String> {
    let mut reader = sevenz_rust2::ArchiveReader::new(Cursor::new(bytes), password)
        .map_err(|e| format!("open 7z: {e}"))?;
    let mut failure: Option<String> = None;
    reader
        .for_each_entries(|entry, rd| {
            if failure.is_some() {
                return Ok(false);
            }
            let Some(rel) = sanitize_zip_path(&entry.name) else {
                return Ok(true);
            };
            let out = dir.join(rel);
            if entry.is_directory {
                if let Err(e) = std::fs::create_dir_all(&out) {
                    failure = Some(format!("mkdir 7z: {e}"));
                    return Ok(false);
                }
                return Ok(true);
            }
            if let Some(parent) = out.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    failure = Some(format!("mkdir 7z: {e}"));
                    return Ok(false);
                }
            }
            let mut buf = Vec::new();
            if let Err(e) = rd.read_to_end(&mut buf) {
                failure = Some(format!("read 7z entry {}: {e}", entry.name));
                return Ok(false);
            }
            if let Err(e) = std::fs::write(&out, buf) {
                failure = Some(format!("write 7z entry {}: {e}", entry.name));
                return Ok(false);
            }
            Ok(true)
        })
        .map_err(|e| format!("extract 7z: {e}"))?;
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn expand_one(path: &Path) -> Result<(), String> {
    let Some(kind) = archive_kind(path) else {
        return Ok(());
    };
    let parent = path.parent().unwrap_or(path);
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    match kind {
        ArchiveKind::Zip => {
            // Expand in place (parent dir): nested zips that already
            // contain a top-level folder would otherwise double up
            // (`Arm_crackme/Arm_crackme/...`).
            extract_zip_bytes(&bytes, parent)?;
            let _ = std::fs::remove_file(path);
        }
        ArchiveKind::SevenZ => {
            extract_7z_bytes(&bytes, parent)?;
            let _ = std::fs::remove_file(path);
        }
        ArchiveKind::TarGz => {
            use flate2::read::GzDecoder;
            let gz = GzDecoder::new(Cursor::new(bytes));
            let mut archive = tar::Archive::new(gz);
            archive
                .unpack(parent)
                .map_err(|e| format!("untar {}: {e}", path.display()))?;
            let _ = std::fs::remove_file(path);
        }
        ArchiveKind::Tar => {
            let mut archive = tar::Archive::new(Cursor::new(bytes));
            archive
                .unpack(parent)
                .map_err(|e| format!("untar {}: {e}", path.display()))?;
            let _ = std::fs::remove_file(path);
        }
        ArchiveKind::Gz => {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let mut gz = GzDecoder::new(Cursor::new(bytes));
            let mut buf = Vec::new();
            gz.read_to_end(&mut buf)
                .map_err(|e| format!("gunzip {}: {e}", path.display()))?;
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unzipped");
            std::fs::write(parent.join(stem), buf).map_err(|e| format!("write {}: {e}", stem))?;
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(())
}

/// Java entry point from any extracted `META-INF/MANIFEST.MF`, so we analyze
/// `Main-Class` rather than an arbitrary (largest) class file.
fn java_main_class(dir: &Path) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|n| n.to_str()) != Some("MANIFEST.MF") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let main = text.lines().find_map(|l| {
                l.strip_prefix("Main-Class:")
                    .map(|v| v.trim().trim_end_matches('\r').to_string())
            });
            let Some(main) = main else { continue };
            let rel = format!("{}.class", main.replace('.', "/"));
            let candidate = path
                .parent()
                .and_then(|p| p.parent())
                .map(|root| root.join(&rel));
            if let Some(c) = candidate {
                if c.is_file() {
                    return Some(c);
                }
            }
            // Simple-name fallback: `com/foo/Main.class` may sit elsewhere.
            let simple = main.rsplit('.').next().unwrap_or(&main).to_string();
            let mut stack2 = vec![dir.to_path_buf()];
            while let Some(d) = stack2.pop() {
                let Ok(entries) = std::fs::read_dir(&d) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        stack2.push(p);
                    } else if p.file_name().and_then(|n| n.to_str())
                        == Some(format!("{simple}.class").as_str())
                    {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Fallback binary picker: ELF (`\x7fELF`) / PE (`MZ`) / Java class
/// (`CAFEBABE`); jar manifests resolve the entry class first, then largest
/// file wins.
fn pick_binary_by_magic(dir: &Path) -> Option<PathBuf> {
    if let Some(main) = java_main_class(dir) {
        return Some(main);
    }
    let mut best: Option<(u64, PathBuf)> = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if meta.len() == 0 || meta.len() > 100_000_000 {
                continue;
            }
            let mut magic = [0u8; 4];
            // ELF, PE/DOS (MZ), and Java class (CAFEBABE — `.class`
            // directly, which is how Java crackmes land here).
            let is_bin = std::fs::File::open(&path)
                .and_then(|mut f| {
                    use std::io::Read;
                    f.read_exact(&mut magic).map(|_| ())
                })
                .is_ok()
                && (magic.starts_with(b"\x7fELF")
                    || magic.starts_with(b"MZ")
                    || magic == [0xCA, 0xFE, 0xBA, 0xBE]);
            if is_bin && best.as_ref().is_none_or(|(s, _)| meta.len() > *s) {
                best = Some((meta.len(), path));
            }
        }
    }
    best.map(|(_, p)| p)
}
