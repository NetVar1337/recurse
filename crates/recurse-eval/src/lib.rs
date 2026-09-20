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

use serde::{Deserialize, Serialize};

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

/// Map a task's dataset metadata to the agent's [`librecurse::agent::PromptTarget`].
pub fn prompt_target_for(task: &Task, binary_path: &str) -> librecurse::agent::PromptTarget {
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
    librecurse::agent::PromptTarget {
        path: binary_path.to_string(),
        arch,
        bits,
        kind,
        memory: String::new(),
    }
}

/// Pricing for cost reporting (deepseek-v4.1-flash on OpenRouter,
/// verified 2026-09-20: $0.15/M in, $0.60/M out). Update when the eval
/// model changes.
pub const USD_PER_M_INPUT: f64 = 0.15;
pub const USD_PER_M_OUTPUT: f64 = 0.60;

pub fn cost_usd(in_tokens: u64, out_tokens: u64) -> f64 {
    in_tokens as f64 / 1_000_000.0 * USD_PER_M_INPUT
        + out_tokens as f64 / 1_000_000.0 * USD_PER_M_OUTPUT
}
