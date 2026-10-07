//! Analyst function renames, persisted in SQLite (the `function_names` table).
//!
//! Keyed by binary path + function address, so names follow a target across
//! sessions. The host loads them when a binary is opened and installs them into
//! the active engine (via `Engine::set_renames`), so the rename is visible to
//! both the UI and the agent.

use std::collections::HashMap;

use rusqlite::params;

use crate::db;

/// Every rename recorded for `binary_path`, as `address -> name`.
///
/// Fails, rather than yielding an empty map, when the names cannot be read: a
/// caller that is told "no names" instead will open the binary and show an
/// analyst who has renamed things a view that has forgotten all of it. The
/// callers that must not be blocked by this — opening a binary — degrade
/// deliberately, and say so where they do.
pub fn load(binary_path: &str) -> Result<HashMap<u64, String>, String> {
    let mut out = HashMap::new();
    for (addr, name) in db::rows_for(
        "renames",
        "SELECT addr, name FROM function_names WHERE binary_path = ?1",
        binary_path,
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )? {
        out.insert(addr.max(0) as u64, name);
    }
    Ok(out)
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
            assert!(load(bin).unwrap().is_empty());
            set(bin, 0x401000, Some("decrypt_flag")).unwrap();
            set(bin, 0x401100, Some("check_password")).unwrap();
            let map = load(bin).unwrap();
            assert_eq!(map.get(&0x401000).map(String::as_str), Some("decrypt_flag"));
            assert_eq!(
                map.get(&0x401100).map(String::as_str),
                Some("check_password")
            );
            // Renaming overwrites; blank clears just that one.
            set(bin, 0x401000, Some("decrypt")).unwrap();
            set(bin, 0x401100, Some("  ")).unwrap();
            let map = load(bin).unwrap();
            assert_eq!(map.get(&0x401000).map(String::as_str), Some("decrypt"));
            assert!(!map.contains_key(&0x401100));
            // Renames are scoped per binary.
            assert!(load("/tmp/other").unwrap().is_empty());
        });
    }

    /// A database left behind by an older build must not shadow the schema.
    ///
    /// `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists,
    /// so a database created before `key` existed keeps its old shape: a `slot`
    /// column, and a primary key that does not mention `key`. Every write then
    /// fails on the `ON CONFLICT` clause naming a constraint the table does not
    /// have — and the analyst's names silently do not stick. The schema now
    /// discards this table rather than trying to move rows across a primary key
    /// `ALTER TABLE` cannot change, which is only sound because nothing released
    /// depends on the rows.
    #[test]
    fn a_stale_table_is_rebuilt_rather_than_written_to() {
        crate::testhome::with_test_home(|_| {
            let conn = crate::db::connect().expect("connect");
            conn.execute_batch(
                "DROP TABLE IF EXISTS variable_names;
                 CREATE TABLE variable_names (
                     binary_path TEXT NOT NULL,
                     func_addr INTEGER NOT NULL,
                     slot INTEGER NOT NULL,
                     name TEXT NOT NULL,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY (binary_path, func_addr, slot)
                 );",
            )
            .expect("plant the old shape");
            drop(conn);

            // The first write after the stale shape was planted is the one that
            // used to fail.
            set_variable("/tmp/target", 0x401000, "-4", Some("demo"))
                .expect("write over a stale table");
            let names = load_variables("/tmp/target").unwrap();
            assert_eq!(names.get(&(0x401000, "-4".to_string())).map(String::as_str), Some("demo"));
        });
    }

    /// A table that cannot be read must not read as a table with nothing in it.
    ///
    /// This is the shape of the failure that cost an afternoon: the loaders
    /// returned an empty map for every fault, so a table missing a column
    /// reported the same answer as a binary nobody had named anything in, all
    /// the way out to a view that showed no names. A fault has to stay a fault
    /// for as long as it takes to find it.
    #[test]
    fn an_unreadable_table_is_an_error_rather_than_no_names() {
        crate::testhome::with_test_home(|_| {
            let conn = crate::db::connect().expect("connect");
            // A column of a type the loader does not expect to read back.
            conn.execute_batch("DROP TABLE IF EXISTS variable_names;")
                .expect("drop");
            conn.execute_batch(
                "CREATE TABLE variable_names (
                     binary_path TEXT NOT NULL,
                     func_addr INTEGER NOT NULL,
                     key BLOB NOT NULL,
                     name TEXT NOT NULL,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY (binary_path, func_addr, key)
                 );
                 INSERT INTO variable_names VALUES ('/tmp/target', 2302, X'00', 'demo', 0);",
            )
            .expect("plant an unreadable row");
            drop(conn);

            assert!(
                load_variables("/tmp/target").is_err(),
                "a row that cannot be decoded must not be dropped in favour of a short map"
            );
        });
    }
}

/// Every variable name recorded for `binary_path`, as `(func, key) -> name`.
///
/// A local variable has no address — it is a frame offset inside a function —
/// so it gets its own table rather than sharing `function_names`. `key` is the
/// frame offset (`-8`) for a local and the register (`rdi`) for an argument,
/// which is the whole identity of the thing being named.
///
/// Fails when the names cannot be read, for the same reason [`load`] does: an
/// empty map is a claim that nothing has been named, and a table that cannot be
/// read is not that.
pub fn load_variables(binary_path: &str) -> Result<HashMap<(u64, String), String>, String> {
    let mut out = HashMap::new();
    for (func, key, name) in db::rows_for(
        "variable renames",
        "SELECT func_addr, key, name FROM variable_names WHERE binary_path = ?1",
        binary_path,
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )? {
        out.insert((func.max(0) as u64, key), name);
    }
    Ok(out)
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
