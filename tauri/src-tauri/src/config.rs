use rusqlite::params;
use serde::{Deserialize, Serialize};

use librecurse::agent::LlmConfig;

use crate::db;

/// Persisted user configuration, stored in the `config` table.
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
    /// Analysis backend (`r2` or `native`). Absent means the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

fn get_key(key: &str) -> Option<String> {
    let conn = db::connect().ok()?;
    conn.query_row(
        "SELECT value FROM config WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .ok()
}

/// Load the config; returns an empty config when nothing is stored
/// (never errors — config is best-effort).
pub fn load() -> ConfigFile {
    ConfigFile {
        openrouter_api_key: get_key("openrouter_api_key"),
        model: get_key("model"),
        endpoint: get_key("endpoint"),
        backend: get_key("backend"),
    }
}

fn set_key(key: &str, value: Option<String>) -> Result<(), String> {
    let conn = db::connect()?;
    match value {
        Some(v) => {
            conn.execute(
                "INSERT INTO config (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                params![key, v],
            )
            .map_err(|e| e.to_string())?;
        }
        None => {
            conn.execute("DELETE FROM config WHERE key = ?1", params![key])
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn set_api_key(key: Option<String>) -> Result<(), String> {
    set_key("openrouter_api_key", key)
}

pub fn set_model(model: String) -> Result<(), String> {
    set_key("model", Some(model))
}

pub fn set_endpoint(endpoint: String) -> Result<(), String> {
    set_key("endpoint", Some(endpoint))
}

pub fn set_backend(backend: Option<String>) -> Result<(), String> {
    set_key("backend", backend)
}

/// Resolve which analysis backend to instantiate. Precedence:
/// stored config > `RECURSE_BACKEND` environment > built-in default
/// (`native` in the default build, otherwise `r2`). Unknown names fall back
/// rather than making the app unusable.
pub fn backend() -> librecurse::engine::BackendKind {
    load()
        .backend
        .as_deref()
        .and_then(librecurse::engine::BackendKind::parse)
        .unwrap_or_else(librecurse::engine::BackendKind::from_env)
}

/// Resolve the runtime LLM config the agent loop consumes.
/// Precedence: config table > environment > built-in defaults (the last two
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
