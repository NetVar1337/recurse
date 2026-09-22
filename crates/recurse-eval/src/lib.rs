//! Headless eval harness for the Recurse agent — Rust only.
//!
//! Tiers are swappable YAML configs (`evals/<tier>.yaml`, see
//! `evals/easy.yaml`): dataset source, selection over every dataset field
//! (or frozen hexid lists), and run knobs. Same schema from easy to hard —
//! tier swaps are config-only, zero code changes.
//!
//! Grading is pure Rust (token-boundary flag match) — no Python verifier
//! scripts. The corpus fetcher ([corpus]) is Rust too (reqwest + zip).

pub mod config;
pub mod corpus;
pub mod runner;
pub mod select;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Load `.env` from the crate dir or any ancestor (so a repo-root `.env`
/// works). Existing environment variables always win — `just`, CI, or an
/// explicit `export` are never overridden by the file.
///
/// Called by the eval entry points so `.env` works no matter how the
/// harness is started (`just`, npm, or a bare `cargo test`).
/// Environment variables and `.env` are the only config sources: API keys
/// are not read from any other file.
pub fn load_dotenv() {
    let start = Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in start.ancestors() {
        let candidate = dir.join(".env");
        if !candidate.is_file() {
            continue;
        }
        // Parse and apply manually so pre-set variables win deterministically
        // rather than depending on the loader's override policy. Empty values
        // are skipped entirely: `RECURSE_LLM_API_KEY=` means "not set", not
        // "set to empty" (which would look like a configured key downstream).
        if let Ok(iter) = dotenvy::from_path_iter(&candidate) {
            for (key, value) in iter.flatten() {
                if value.trim().is_empty() || std::env::var_os(&key).is_some() {
                    continue;
                }
                // SAFETY: eval entry points are single-threaded at this stage,
                // before any worker threads are spawned.
                unsafe { std::env::set_var(key, value) };
            }
        }
        return;
    }
}

/// Repo root: the nearest ancestor whose `Cargo.toml` declares a workspace.
/// Falls back to the crate dir when the crate is built standalone.
pub fn workspace_root() -> PathBuf {
    let start = Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return dir.to_path_buf();
            }
        }
    }
    start.to_path_buf()
}

/// Build directory for the workspace (honours `CARGO_TARGET_DIR`).
pub fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join("target"))
}

/// Default trace directory: `<target>/eval-traces`.
pub fn default_trace_dir() -> PathBuf {
    target_dir().join("eval-traces")
}

/// Resolve a configured path: absolute paths pass through, relative ones are
/// taken against the crate dir. Keeps `EVAL_CONFIG` / `EVAL_CORPUS` /
/// `EVAL_TRACES` behaving identically from the repo root, `tauri/`, or the
/// crate dir.
pub fn crate_relative(p: impl AsRef<Path>) -> PathBuf {
    let p = p.as_ref();
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(p)
    }
}

/// Environment variable (`EVAL_*` / LLM) override. Empty values count as
/// unset, so `RECURSE_LLM_API_KEY=` in `.env` doesn't masquerade as a key.
pub fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// [`env_string`] resolved as a path (crate-relative when relative).
pub fn env_path(key: &str) -> Option<PathBuf> {
    env_string(key).map(crate_relative)
}

/// One eval task. Mirrors the crackmes-re-dataset record fields we grade on.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    pub hexid: String,
    pub name: String,
    #[serde(default)]
    pub difficulty: f64,
    #[serde(default)]
    pub quality: f64,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub nbsolutions: u64,
    /// Exact expected secret. Case-sensitive token-boundary match.
    pub flag: String,
    /// Binary path relative to `corpus/<hexid>/` after extraction.
    pub binary: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Grade a final answer against the expected flag: the flag must appear as
/// a standalone token (bounded by non-alphanumerics on both sides),
/// case-sensitive. This rejects `1234`-in-`a12345` style false positives
/// while accepting flags with symbols (`d00r1$m@licious`).
pub fn grade_flag(answer: &str, flag: &str) -> bool {
    if flag.chars().count() < 2 {
        return false;
    }
    contains_token(answer, flag)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-' || c == '$' || c == '@'
}

/// True when `flag` occurs in `answer` with non-word boundaries on both
/// sides (case-sensitive). Word chars are alphanumerics plus `_-$@` so
/// symbol-heavy flags still grade exactly.
pub fn contains_token(answer: &str, flag: &str) -> bool {
    if flag.is_empty() {
        return false;
    }
    let mut start = 0;
    while let Some(pos) = answer[start..].find(flag) {
        let s = start + pos;
        let e = s + flag.len();
        let left_ok = answer[..s]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let right_ok = answer[e..].chars().next().is_none_or(|c| !is_word_char(c));
        if left_ok && right_ok {
            return true;
        }
        start = s + 1;
        if start >= answer.len() {
            break;
        }
    }
    false
}

/// Map a task's dataset metadata to the agent's [`recurse_agent::agent::PromptTarget`].
/// `capabilities` come from the live engine so the prompt only advertises ops
/// the selected backend can serve.
pub fn prompt_target_for(
    task: &Task,
    binary_path: &str,
    capabilities: recurse_agent::engine::Capabilities,
) -> recurse_agent::agent::PromptTarget {
    let java = task.language.to_lowercase().contains("java") || task.arch == "java";
    let kind = if java {
        "java"
    } else if task.platform.contains("indows") {
        "pe"
    } else if task.platform.contains("inux") || task.platform.contains("nix") {
        "elf"
    } else if task.platform.contains("ac") || task.platform.contains("ach-O") {
        "mach0"
    } else {
        "?"
    }
    .to_string();
    let (arch, bits) = match task.arch.as_str() {
        "x86-64" => ("x86".to_string(), 64),
        "x86" => ("x86".to_string(), 32),
        "ARM" => ("arm".to_string(), 32),
        "java" => ("java".to_string(), 0),
        _ => ("?".to_string(), 0),
    };
    recurse_agent::agent::PromptTarget {
        path: binary_path.to_string(),
        arch,
        bits,
        kind,
        memory: String::new(),
        capabilities,
    }
}

/// Pricing for cost reporting, in USD per million tokens. OpenRouter's own
/// router ids are priced $0 (they route to free models), so a run against
/// them reports $0.00 rather than a fabricated estimate.
///
/// Unknown ids fall back to the DeepSeek rate so the number stays in the right
/// ballpark, and [`pricing_for`] says which rate was used.
pub fn pricing_for(model: &str) -> (f64, f64) {
    let m = model.to_lowercase();
    // Free routers and `:free` variants cost nothing.
    if m == "openrouter/free" || m.ends_with(":free") || m.contains("/free") {
        return (0.0, 0.0);
    }
    match m.as_str() {
        "deepseek/deepseek-v4-flash" | "deepseek/deepseek-v4-flash-0731" => (0.04, 0.08),
        "deepseek/deepseek-v4.1-flash" => (0.15, 0.60),
        "deepseek/deepseek-v3.2" | "deepseek/deepseek-v3.2-exp" => (0.269, 0.40),
        // Default: assume the mid-tier OSS rate this harness was priced at.
        _ => (0.15, 0.60),
    }
}

/// Human-readable rate label for the run log.
pub fn rate_label(model: &str) -> &'static str {
    let (i, _) = pricing_for(model);
    if i == 0.0 {
        "free"
    } else {
        "est."
    }
}

pub fn cost_usd(model: &str, in_tokens: u64, out_tokens: u64) -> f64 {
    let (in_rate, out_rate) = pricing_for(model);
    in_tokens as f64 / 1_000_000.0 * in_rate + out_tokens as f64 / 1_000_000.0 * out_rate
}
