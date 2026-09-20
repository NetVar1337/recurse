use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use librecurse::agent::LlmConfig;

/// Persisted user configuration at `~/.recurse/config.json`.
/// Only fields the user sets explicitly are written; everything else is
/// preserved across updates.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openrouter_api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

fn config_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    Ok(home.join(".recurse").join("config.json"))
}

/// Load the config file; returns an empty config if the file is missing or
/// unreadable (never errors — config is best-effort).
pub fn load() -> ConfigFile {
    config_path()
        .ok()
        .and_then(|p| fs::read_to_string(&p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write(cfg: &ConfigFile) -> Result<(), String> {
    let p = config_path()?;
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let s = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(&p, s).map_err(|e| e.to_string())?;
    Ok(())
}

fn update<F>(f: F) -> Result<(), String>
where
    F: FnOnce(&mut ConfigFile),
{
    let mut cfg = load();
    f(&mut cfg);
    write(&cfg)
}

pub fn set_api_key(key: Option<String>) -> Result<(), String> {
    update(|c| c.openrouter_api_key = key)
}

pub fn set_model(model: String) -> Result<(), String> {
    update(|c| c.model = Some(model))
}

/// Resolve the runtime LLM config the agent loop consumes.
/// Precedence: config file > environment > built-in defaults (the last two
/// come from [`LlmConfig::default`]).
pub fn llm_config() -> LlmConfig {
    let file = load();
    let fallback = LlmConfig::default();
    LlmConfig::new(
        file.endpoint.unwrap_or(fallback.endpoint),
        file.openrouter_api_key.or(fallback.api_key),
        file.model.unwrap_or(fallback.model),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn set_and_load_roundtrip() {
        crate::testhome::with_test_home(|_| {
            let cfg = load();
            assert!(cfg.openrouter_api_key.is_none());
            set_api_key(Some("sk-test".into())).unwrap();
            set_model("model-x".into()).unwrap();
            let cfg = load();
            assert_eq!(cfg.openrouter_api_key.as_deref(), Some("sk-test"));
            assert_eq!(cfg.model.as_deref(), Some("model-x"));
            // Updating one field preserves the other.
            set_model("model-y".into()).unwrap();
            let cfg = load();
            assert_eq!(cfg.model.as_deref(), Some("model-y"));
            assert_eq!(cfg.openrouter_api_key.as_deref(), Some("sk-test"));
        });
    }

    #[test]
    fn empty_key_clears_entry() {
        crate::testhome::with_test_home(|_| {
            set_api_key(Some("k".into())).unwrap();
            set_api_key(None).unwrap();
            assert!(load().openrouter_api_key.is_none());
        });
    }
}
