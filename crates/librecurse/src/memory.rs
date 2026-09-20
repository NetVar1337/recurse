//! Agent memory, owned by librecurse.
//!
//! All memory lives in SQLite (same `recurse.db` file the host uses for
//! projects/sessions/config — this module owns the `memories` tables, the
//! host owns everything else). Full-text search uses FTS5 + BM25 so the
//! agent can retrieve findings on demand instead of having every note
//! concatenated into the system prompt.
//!
//! [`MemoryStore`] opens short-lived connections to the DB file. No
//! long-lived handles, no file-backed `.md` notes.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};
use serde_json::{json, Value};

/// DDL owned by this module. The host runs it once at startup on its own
/// connection (same DB file, WAL mode) via [`ensure_schema`].
pub const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS memories (
    project_name TEXT NOT NULL,
    key TEXT NOT NULL,
    content TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_name, key)
);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
    project_name UNINDEXED,
    key,
    content,
    tokenize='porter'
);
";

/// Run [`SCHEMA_SQL`] on an open connection. Idempotent.
pub fn ensure_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(SCHEMA_SQL)
        .map_err(|e| format!("memory schema failed: {e}"))
}

/// Sanitize a memory key into a safe non-empty slug.
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

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn open_conn(db_path: &Path) -> Result<Connection, String> {
    Connection::open(db_path).map_err(|e| format!("open memory db failed: {e}"))
}

/// Escape a user query into a safe FTS5 query: keep alphanumeric terms,
/// drop syntax characters, join with OR. Returns `None` when nothing
/// searchable remains.
fn fts_query(raw: &str) -> Option<String> {
    let terms: Vec<String> = raw
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .filter(|t| !t.is_empty() && t.len() < 64)
        .map(|t| format!("\"{t}\""))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" OR "))
    }
}

/// SQLite-backed memory store. Owns the `memories` + `memories_fts` tables;
/// opens a fresh connection per call so hosts never share handles.
#[derive(Clone, Debug)]
pub struct MemoryStore {
    db_path: PathBuf,
}

impl MemoryStore {
    pub fn new(db_path: PathBuf) -> Self {
        Self { db_path }
    }

    fn conn(&self) -> Result<Connection, String> {
        open_conn(&self.db_path)
    }

    pub fn save(&self, project: &str, key: &str, content: &str) -> Result<(), String> {
        let key = sanitize_key(key);
        let ts = now();
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO memories (project_name, key, content, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (project_name, key)
             DO UPDATE SET content = excluded.content, updated_at = excluded.updated_at",
            params![project, key, content, ts],
        )
        .map_err(|e| format!("memory save failed: {e}"))?;
        conn.execute(
            "DELETE FROM memories_fts WHERE project_name = ?1 AND key = ?2",
            params![project, key],
        )
        .map_err(|e| format!("memory fts delete failed: {e}"))?;
        conn.execute(
            "INSERT INTO memories_fts (project_name, key, content) VALUES (?1, ?2, ?3)",
            params![project, key, content],
        )
        .map_err(|e| format!("memory fts insert failed: {e}"))?;
        Ok(())
    }

    pub fn load(&self, project: &str, key: &str) -> Result<String, String> {
        let key = sanitize_key(key);
        let conn = self.conn()?;
        conn.query_row(
            "SELECT content FROM memories WHERE project_name = ?1 AND key = ?2",
            params![project, key],
            |row| row.get(0),
        )
        .map_err(|_| format!("memory not found: {key}"))
    }

    pub fn remove(&self, project: &str, key: &str) -> Result<(), String> {
        let key = sanitize_key(key);
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM memories WHERE project_name = ?1 AND key = ?2",
            params![project, key],
        )
        .map_err(|e| format!("memory remove failed: {e}"))?;
        conn.execute(
            "DELETE FROM memories_fts WHERE project_name = ?1 AND key = ?2",
            params![project, key],
        )
        .map_err(|e| format!("memory fts remove failed: {e}"))?;
        Ok(())
    }

    /// All keys for a project, sorted.
    pub fn list(&self, project: &str) -> Result<Vec<String>, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT key FROM memories WHERE project_name = ?1 ORDER BY key")
            .map_err(|e| format!("memory list failed: {e}"))?;
        let rows = stmt
            .query_map(params![project], |row| row.get(0))
            .map_err(|e| format!("memory list failed: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            match row {
                Ok(k) => out.push(k),
                Err(e) => return Err(format!("memory list failed: {e}")),
            }
        }
        Ok(out)
    }

    /// BM25-ranked full-text search over one project's memories.
    /// Returns `(key, snippet, rank)` with lower rank = better match.
    pub fn search(
        &self,
        project: &str,
        query: &str,
        limit: i64,
    ) -> Result<Vec<(String, String, f64)>, String> {
        let Some(match_query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        let limit = limit.clamp(1, 50);
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT m.key, m.content, bm25(memories_fts) AS rank
                 FROM memories_fts
                 JOIN memories m ON m.project_name = memories_fts.project_name
                                AND m.key = memories_fts.key
                 WHERE memories_fts MATCH ?1 AND memories_fts.project_name = ?2
                 ORDER BY rank LIMIT ?3",
            )
            .map_err(|e| format!("memory search failed: {e}"))?;
        let rows = stmt
            .query_map(params![match_query, project, limit], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, f64>(2)?))
            })
            .map_err(|e| format!("memory search failed: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            match row {
                Ok(r) => out.push(r),
                Err(e) => return Err(format!("memory search failed: {e}")),
            }
        }
        Ok(out)
    }

    /// Compact index for the system prompt: key list + total size, never
    /// the full bodies. Bodies are fetched via `memory_search` / `memory_load`.
    pub fn index(&self, project: &str) -> Result<String, String> {
        let keys = self.list(project)?;
        if keys.is_empty() {
            return Ok(String::new());
        }
        Ok(format!("saved findings ({}): {}", keys.len(), keys.join(", ")))
    }

    /// Small-project fast path: concatenated bodies capped at `max_chars`.
    /// Large projects should prefer [`MemoryStore::index`] + on-demand search.
    pub fn summary(&self, project: &str, max_chars: usize) -> Result<String, String> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT key, content FROM memories WHERE project_name = ?1 ORDER BY key")
            .map_err(|e| format!("memory summary failed: {e}"))?;
        let rows = stmt
            .query_map(params![project], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| format!("memory summary failed: {e}"))?;
        let mut out = String::new();
        for row in rows {
            match row {
                Ok((k, c)) => {
                    let entry = format!("# {k}\n\n{c}\n\n");
                    if out.len() + entry.len() > max_chars {
                        out.push_str("\n[... more findings saved; use memory_search to retrieve]");
                        break;
                    }
                    out.push_str(&entry);
                }
                Err(e) => return Err(format!("memory summary failed: {e}")),
            }
        }
        Ok(out)
    }

    /// Execute one memory tool call (`memory_save` / `memory_load` /
    /// `memory_search`) for the given project. Argument parsing mirrors
    /// the schemas in [`memory_tool_schema`].
    pub fn execute_tool(&self, project: &str, name: &str, args: &Value) -> Result<String, String> {
        match name {
            "memory_save" => {
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing string argument 'key'".to_string())?;
                let content = args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing string argument 'content'".to_string())?;
                self.save(project, key, content)?;
                Ok(format!("saved memory '{key}'"))
            }
            "memory_load" => {
                let key = args
                    .get("key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing string argument 'key'".to_string())?;
                self.load(project, key)
            }
            "memory_search" => {
                let query = args
                    .get("query")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "missing string argument 'query'".to_string())?;
                let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(5);
                let hits = self.search(project, query, limit)?;
                if hits.is_empty() {
                    return Ok("no matching findings".to_string());
                }
                let mut out = String::new();
                for (key, content, _rank) in hits {
                    let snippet: String = content.chars().take(1200).collect();
                    out.push_str(&format!("# {key}\n\n{snippet}\n\n"));
                }
                Ok(out)
            }
            other => Err(format!("unknown memory tool: {other}")),
        }
    }
}

fn tool(name: &str, description: &str, params: Value) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": params,
        }
    })
}

/// Tool declarations owned by librecurse. The host appends these to the
/// base `bash/read/write/edit` schema and routes execution to
/// [`MemoryStore::execute_tool`].
pub fn memory_tool_schema() -> Vec<Value> {
    vec![
        tool(
            "memory_save",
            "Save a reverse-engineering finding (function purpose, protocol detail, key insight) under a short key so it survives across sessions. Prefer small focused notes over dumps.",
            json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "Short key, e.g. fn_0x401000 or c2_protocol" },
                    "content": { "type": "string", "description": "Markdown finding to save" }
                },
                "required": ["key", "content"]
            }),
        ),
        tool(
            "memory_load",
            "Load one saved finding by key.",
            json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "Key returned by the memory index or search" }
                },
                "required": ["key"]
            }),
        ),
        tool(
            "memory_search",
            "Full-text (BM25) search over saved findings for this project. Use it before re-analyzing a function you may have seen.",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Keywords, e.g. decrypt c2 main" },
                    "limit": { "type": "integer", "description": "Max hits (default 5, max 50)" }
                },
                "required": ["query"]
            }),
        ),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn test_store() -> (MemoryStore, TempfileGuard) {
        let dir = std::env::temp_dir().join(format!(
            "librecurse-memtest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mem.db");
        let conn = Connection::open(&path).expect("open test db");
        ensure_schema(&conn).expect("schema");
        drop(conn);
        (MemoryStore::new(path), TempfileGuard(dir))
    }

    struct TempfileGuard(std::path::PathBuf);
    impl Drop for TempfileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn save_load_roundtrip() {
        let (s, _g) = test_store();
        s.save("p", "fn_0x401000", "decrypts c2 traffic").unwrap();
        assert_eq!(s.load("p", "fn_0x401000").unwrap(), "decrypts c2 traffic");
        assert_eq!(s.list("p").unwrap(), vec!["fn_0x401000".to_string()]);
        // Projects are isolated.
        assert!(s.list("other").unwrap().is_empty());
        s.remove("p", "fn_0x401000").unwrap();
        assert!(s.list("p").unwrap().is_empty());
    }

    #[test]
    fn bm25_search_ranks_relevant_first() {
        let (s, _g) = test_store();
        s.save("p", "a", "rc4 decryption routine for c2 traffic").unwrap();
        s.save("p", "b", "totally unrelated string table note").unwrap();
        let hits = s.search("p", "rc4 c2 decrypt", 5).unwrap();
        assert!(!hits.is_empty());
        assert_eq!(hits[0].0, "a");
        // Gibberish matches nothing.
        assert!(s.search("p", "!!!", 5).unwrap().is_empty());
    }

    #[test]
    fn summary_caps_output() {
        let (s, _g) = test_store();
        s.save("p", "a", &"x".repeat(5000)).unwrap();
        let full = s.summary("p", 1_000_000).unwrap();
        assert!(full.contains("# a"));
        let capped = s.summary("p", 100).unwrap();
        assert!(capped.contains("memory_search"));
    }
}
