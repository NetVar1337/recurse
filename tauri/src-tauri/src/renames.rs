//! Analyst function renames, persisted in SQLite (the `function_names` table).
//!
//! Keyed by binary path + function address, so names follow a target across
//! sessions. The host loads them when a binary is opened and installs them into
//! the active engine (via `Engine::set_renames`), so the rename is visible to
//! both the UI and the agent.

use std::collections::HashMap;

use rusqlite::params;

use crate::db;

/// Every rename recorded for `binary_path`, as `address -> name`. Best-effort:
/// a storage failure yields an empty map rather than an error, so a broken DB
/// never blocks opening a binary.
pub fn load(binary_path: &str) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let Ok(conn) = db::connect() else {
        return out;
    };
    let Ok(mut stmt) = conn.prepare("SELECT addr, name FROM function_names WHERE binary_path = ?1")
    else {
        return out;
    };
    let Ok(rows) = stmt.query_map(params![binary_path], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    }) else {
        return out;
    };
    for row in rows.flatten() {
        out.insert(row.0.max(0) as u64, row.1);
    }
    out
}

/// Set the name of one function, or clear it when `name` is `None`/blank.
pub fn set(binary_path: &str, addr: u64, name: Option<&str>) -> Result<(), String> {
    let conn = db::connect()?;
    match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(name) => {
            conn.execute(
                "INSERT INTO function_names (binary_path, addr, name, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (binary_path, addr) DO UPDATE SET name = excluded.name,
                                                               updated_at = excluded.updated_at",
                params![binary_path, addr as i64, name, db::now()],
            )
            .map_err(|e| e.to_string())?;
        }
        None => {
            conn.execute(
                "DELETE FROM function_names WHERE binary_path = ?1 AND addr = ?2",
                params![binary_path, addr as i64],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn set_load_and_clear_roundtrip() {
        crate::testhome::with_test_home(|_| {
            let bin = "/tmp/target";
            assert!(load(bin).is_empty());
            set(bin, 0x401000, Some("decrypt_flag")).unwrap();
            set(bin, 0x401100, Some("check_password")).unwrap();
            let map = load(bin);
            assert_eq!(map.get(&0x401000).map(String::as_str), Some("decrypt_flag"));
            assert_eq!(
                map.get(&0x401100).map(String::as_str),
                Some("check_password")
            );
            // Renaming overwrites; blank clears just that one.
            set(bin, 0x401000, Some("decrypt")).unwrap();
            set(bin, 0x401100, Some("  ")).unwrap();
            let map = load(bin);
            assert_eq!(map.get(&0x401000).map(String::as_str), Some("decrypt"));
            assert!(!map.contains_key(&0x401100));
            // Renames are scoped per binary.
            assert!(load("/tmp/other").is_empty());
        });
    }
}
