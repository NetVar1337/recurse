//! YAML eval configuration. One file fully describes a tier run: where the
//! dataset lives, which tasks to select (explicit hexids and/or filters over
//! every dataset field), and how to run them. Swapping tiers = new YAML file,
//! zero code changes.
//!
//! ```yaml
//! dataset:
//!   jsonl_url: https://raw.githubusercontent.com/.../crackmes_dataset.jsonl
//! select:
//!   difficulty_max: 1.5
//!   platforms: [linux]        # case-insensitive substring; empty = any
//!   archs: [x86-64, x86]
//!   tags_any: [Anti-debugging]
//!   min_quality: 3.0
//!   min_solutions: 5
//!   require_flag: true
//!   count: 10
//!   seed: 7
//! run:
//!   model: deepseek/deepseek-v4.1-flash
//!   backend: r2              # or native (env EVAL_BACKEND wins)
//!   max_turns: 40
//!   timeout_secs: 480
//! ```

use std::collections::HashMap;
use std::path::Path;

use librecurse::engine::BackendKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DatasetConfig {
    pub jsonl_url: String,
    pub jsonl_cache: String,
}

impl Default for DatasetConfig {
    fn default() -> Self {
        Self {
            jsonl_url: "https://raw.githubusercontent.com/crackmesone/crackmes-re-dataset/main/dataset/crackmes_dataset.jsonl".to_string(),
            jsonl_cache: "corpus/crackmes_dataset.jsonl".to_string(),
        }
    }
}

/// Task selection. `hexids`, when non-empty, wins exactly (order kept) and
/// every other filter is skipped — used for frozen tiers. Otherwise the
/// JSONL is filtered over all dataset fields, shuffled with `seed`, and the
/// first `count` tasks are taken.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SelectConfig {
    pub hexids: Vec<String>,
    pub difficulty_min: Option<f64>,
    pub difficulty_max: Option<f64>,
    pub platforms: Vec<String>,
    pub archs: Vec<String>,
    pub languages: Vec<String>,
    pub tags_any: Vec<String>,
    pub tags_none: Vec<String>,
    pub min_quality: Option<f64>,
    pub min_solutions: Option<u64>,
    pub require_flag: bool,
    pub require_unique_flag: bool,
    pub count: usize,
    pub seed: u64,
}

impl Default for SelectConfig {
    fn default() -> Self {
        Self {
            hexids: Vec::new(),
            difficulty_min: None,
            difficulty_max: None,
            platforms: Vec::new(),
            archs: Vec::new(),
            languages: Vec::new(),
            tags_any: Vec::new(),
            tags_none: Vec::new(),
            min_quality: None,
            min_solutions: None,
            require_flag: true,
            require_unique_flag: false,
            count: 10,
            seed: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct RunConfig {
    /// Empty = app default (`RECURSE_LLM_MODEL` / OpenRouter auto).
    pub model: String,
    /// Analysis backend for this tier: `r2` or `native`. `None` falls back to
    /// `RECURSE_BACKEND` (or the app default, `r2`). `EVAL_BACKEND` overrides
    /// this per run.
    pub backend: Option<BackendKind>,
    pub max_turns: usize,
    pub timeout_secs: u64,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            model: String::new(),
            backend: None,
            max_turns: 40,
            timeout_secs: 480,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct EvalConfig {
    pub tier: String,
    pub description: String,
    pub dataset: DatasetConfig,
    pub select: SelectConfig,
    pub run: RunConfig,
    /// Optional overrides; env (`EVAL_CORPUS`, `EVAL_TRACES`) wins when set.
    pub corpus_dir: Option<String>,
    pub trace_dir: Option<String>,
    /// Known `hexid -> corpus-relative binary path` hints. Anything missing
    /// here is located by magic-byte detection after extraction.
    #[serde(default)]
    pub binaries: HashMap<String, String>,
}

impl Default for EvalConfig {
    fn default() -> Self {
        Self {
            tier: "easy".to_string(),
            description: String::new(),
            dataset: DatasetConfig::default(),
            select: SelectConfig::default(),
            run: RunConfig::default(),
            corpus_dir: None,
            trace_dir: None,
            binaries: HashMap::new(),
        }
    }
}

impl EvalConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read eval config {}: {e}", path.display()))?;
        serde_yaml::from_str(&text)
            .map_err(|e| format!("parse eval config {}: {e}", path.display()))
    }
}
