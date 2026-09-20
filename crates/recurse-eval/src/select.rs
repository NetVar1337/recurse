//! Task selection over the dataset JSONL: filter across all record fields,
//! then deterministic seeded sampling. Pure logic, no IO except reading the
//! JSONL — trivially unit-testable.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::config::SelectConfig;
use crate::Task;

/// Deserialize `null` as the type's default instead of failing. The upstream
/// dataset writes explicit `null` for unknown string fields (e.g. `language`),
/// so a strict `String` breaks on real records.
fn null_as_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(de)?.unwrap_or_default())
}

/// Subset of the crackmes-re-dataset record we select on. Unknown fields
/// are ignored, so schema additions upstream never break us; `null` in any
/// string/vec field degrades to empty rather than failing the line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatasetRecord {
    #[serde(default, deserialize_with = "null_as_default")]
    pub hexid: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub name: String,
    #[serde(default)]
    pub difficulty: Option<f64>,
    #[serde(default)]
    pub quality: Option<f64>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub platform: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub arch: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub language: String,
    /// Float in the upstream data (`1.0`), so parse as f64 and round.
    #[serde(default)]
    pub nbsolutions: Option<f64>,
    #[serde(default)]
    pub flag: Option<String>,
    #[serde(default)]
    pub has_unique_flag: Option<bool>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub url: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub obfuscation_classes: Vec<String>,
}

impl DatasetRecord {
    /// Grading needs an exact, distinctive secret.
    fn usable_flag(&self) -> Option<&str> {
        self.flag
            .as_deref()
            .filter(|f| f.chars().count() >= 4 && !f.trim().is_empty())
    }
}

/// Selected task: dataset metadata plus the corpus-relative binary path
/// (empty when unknown — the corpus fetcher falls back to magic-byte
/// detection after extraction).
#[derive(Clone, Debug)]
pub struct SelectedTask {
    pub task: Task,
}

pub fn load_records(jsonl: &std::path::Path) -> Result<Vec<DatasetRecord>, String> {
    let text = std::fs::read_to_string(jsonl).map_err(|e| format!("read dataset: {e}"))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: DatasetRecord =
            serde_json::from_str(line).map_err(|e| format!("dataset line {i}: {e}"))?;
        out.push(rec);
    }
    Ok(out)
}

fn matches_any(hay: &str, needles: &[String]) -> bool {
    if needles.is_empty() {
        return true;
    }
    let hay = hay.to_lowercase();
    needles.iter().any(|n| hay.contains(&n.to_lowercase()))
}

/// Deterministic PRNG (mulberry32) — no extra deps for seeded sampling.
fn shuffle<T>(items: &mut [T], mut seed: u64) {
    if seed == 0 {
        seed = 0x9E3779B97F4A7C15;
    }
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_add(0x6D2B79F5);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };
    for i in (1..items.len()).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

/// Apply `select` to `records`. Explicit `hexids` win exactly (missing ids
/// are an error); otherwise filter → sort by hexid → seeded shuffle → take.
pub fn select_tasks(
    records: &[DatasetRecord],
    select: &SelectConfig,
    binary_hints: &std::collections::HashMap<String, String>,
) -> Result<Vec<Task>, String> {
    if !select.hexids.is_empty() {
        let by_id: HashSet<&str> = records.iter().map(|r| r.hexid.as_str()).collect();
        let mut out = Vec::new();
        for id in &select.hexids {
            if !by_id.contains(id.as_str()) {
                return Err(format!("tier hexid not in dataset: {id}"));
            }
            let rec = records.iter().find(|r| &r.hexid == id).ok_or_else(|| {
                // Unreachable: membership checked above.
                format!("tier hexid not in dataset: {id}")
            })?;
            out.push(task_from_record(rec, binary_hints));
        }
        return Ok(out);
    }

    let mut pool: Vec<&DatasetRecord> = records
        .iter()
        .filter(|r| {
            if select.require_flag && r.usable_flag().is_none() {
                return false;
            }
            if select.require_unique_flag && r.has_unique_flag != Some(true) {
                return false;
            }
            if let Some(min) = select.difficulty_min {
                if r.difficulty.is_none_or(|d| d < min) {
                    return false;
                }
            }
            if let Some(max) = select.difficulty_max {
                if r.difficulty.is_none_or(|d| d > max) {
                    return false;
                }
            }
            if !matches_any(&r.platform, &select.platforms) {
                return false;
            }
            if !matches_any(&r.arch, &select.archs) {
                return false;
            }
            if !matches_any(&r.language, &select.languages) {
                return false;
            }
            if !select.tags_any.is_empty()
                && !select.tags_any.iter().any(|t| {
                    r.obfuscation_classes
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(t))
                })
            {
                return false;
            }
            if select.tags_none.iter().any(|t| {
                r.obfuscation_classes
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(t))
            }) {
                return false;
            }
            if let Some(q) = select.min_quality {
                if r.quality.is_none_or(|v| v < q) {
                    return false;
                }
            }
            if let Some(n) = select.min_solutions {
                if r.nbsolutions.is_none_or(|v| v < n as f64) {
                    return false;
                }
            }
            true
        })
        .collect();
    if pool.len() < select.count {
        return Err(format!(
            "filter matched {} tasks, need {} — loosen the select block",
            pool.len(),
            select.count
        ));
    }
    pool.sort_by(|a, b| a.hexid.cmp(&b.hexid));
    shuffle(&mut pool, select.seed);
    Ok(pool
        .into_iter()
        .take(select.count)
        .map(|r| task_from_record(r, binary_hints))
        .collect())
}

fn task_from_record(
    r: &DatasetRecord,
    binary_hints: &std::collections::HashMap<String, String>,
) -> Task {
    Task {
        hexid: r.hexid.clone(),
        name: r.name.clone(),
        difficulty: r.difficulty.unwrap_or(0.0),
        quality: r.quality.unwrap_or(0.0),
        platform: r.platform.clone(),
        arch: r.arch.clone(),
        language: r.language.clone(),
        nbsolutions: r.nbsolutions.unwrap_or(0.0).max(0.0) as u64,
        flag: r.flag.clone().unwrap_or_default(),
        binary: binary_hints.get(&r.hexid).cloned().unwrap_or_default(),
        url: r.url.clone(),
        tags: r.obfuscation_classes.clone(),
    }
}
