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

/// Every variable name recorded for `binary_path`, as `(func, key) -> name`.
///
/// A local variable has no address — it is a frame offset inside a function —
/// so it gets its own table rather than sharing `function_names`. `key` is the
/// frame offset (`-8`) for a local and the register (`rdi`) for an argument,
/// which is the whole identity of the thing being named.
pub fn load_variables(binary_path: &str) -> HashMap<(u64, String), String> {
    let mut out = HashMap::new();
    let Ok(conn) = db::connect() else {
        return out;
    };
    let Ok(mut stmt) =
        conn.prepare("SELECT func_addr, key, name FROM variable_names WHERE binary_path = ?1")
    else {
        return out;
    };
    let Ok(rows) = stmt.query_map(params![binary_path], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    }) else {
        return out;
    };
    for row in rows.flatten() {
        out.insert((row.0.max(0) as u64, row.1), row.2);
    }
    out
}

/// Set the name of one variable, or clear it when `name` is `None`/blank.
pub fn set_variable(
    binary_path: &str,
    func: u64,
    key: &str,
    name: Option<&str>,
) -> Result<(), String> {
    let conn = db::connect()?;
    match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(name) => {
            conn.execute(
                "INSERT INTO variable_names (binary_path, func_addr, key, name, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (binary_path, func_addr, key)
                 DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at",
                params![binary_path, func as i64, key, name, db::now()],
            )
            .map_err(|e| e.to_string())?;
        }
        None => {
            conn.execute(
                "DELETE FROM variable_names
                 WHERE binary_path = ?1 AND func_addr = ?2 AND key = ?3",
                params![binary_path, func as i64, key],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
