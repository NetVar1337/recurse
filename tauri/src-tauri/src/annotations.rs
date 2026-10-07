//! Analyst type annotations, persisted in SQLite (the `variable_types` table).
//!
//! A name says what a thing is called; a type says what it holds. They are
//! independent edits of the same datum, so they are stored independently: a
//! frame slot can be named `buf` while still having no type, and typed `char[8]`
//! while still being called `var_18`.
//!
//! Keyed by binary path + function address + the same `key` [`crate::renames`]
//! uses, so one row can address any of the three things a function header
//! lists: the return value (`<RETURN>`), an argument (`rdi`) or a frame slot
//! (`-8`). The engine has no view of any of them — it never recovers a stack
//! slot, let alone its type — so nothing here is installed into it; these are
//! the analyst's own conclusions, read back by the views that show them.
//!
//! Not the same thing as a decompiler `DecompileAnnotation`: those are emitted
//! by the engine to colour the pseudocode it produced, and cannot be written.

use std::collections::HashMap;

use rusqlite::params;
use serde_json::Value;
use tauri::State;

use crate::commands::{session_of, with_sess};
use crate::db;
use crate::AppState;

/// The `key` a function's return value is stored under.
///
/// Not a register and not a number, so it cannot be read as an argument or as
/// a frame offset; the listing spells the return's storage `<UNASSIGNED>` and
/// its name `<RETURN>`, and this is that marker, so the key and the label the
/// analyst sees are the same string.
pub const RETURN_KEY: &str = "<RETURN>";

/// Every type recorded for `binary_path`, as `(func, key) -> type`.
///
/// Fails rather than yielding an empty map when the types cannot be read, for
/// the reason [`crate::renames::load`] does: an empty map is a claim that
/// nothing has been typed, and a table that cannot be read is not that.
pub fn load(binary_path: &str) -> Result<HashMap<(u64, String), String>, String> {
    let mut out = HashMap::new();
    for (func, key, type_name) in db::rows_for(
        "variable types",
        "SELECT func_addr, key, type_name FROM variable_types WHERE binary_path = ?1",
        binary_path,
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )? {
        out.insert((func.max(0) as u64, key), type_name);
    }
    Ok(out)
}

/// Set the type of one datum, or clear it when `type_name` is `None`/blank.
///
/// Blank clears rather than storing an empty type, for the same reason a blank
/// rename does: `""` is what "no annotation" means everywhere else, and a row
/// holding it would read back as a type of nothing.
///
/// ```
/// # use recurse_lib::{annotations, testhome};
/// # fn ok<T>(r: Result<T, String>) -> T { r.unwrap_or_else(|e| panic!("{e}")) }
/// testhome::with_test_home(|_| {
///     ok(annotations::set_type("/tmp/target", 0x401000, annotations::RETURN_KEY, Some("int")));
///     assert_eq!(
///         ok(annotations::load("/tmp/target"))
///             .get(&(0x401000, "<RETURN>".to_string()))
///             .map(String::as_str),
///         Some("int"),
///     );
///     ok(annotations::set_type("/tmp/target", 0x401000, annotations::RETURN_KEY, Some("  ")));
///     assert!(ok(annotations::load("/tmp/target")).is_empty());
/// });
/// ```
pub fn set_type(
    binary_path: &str,
    func: u64,
    key: &str,
    type_name: Option<&str>,
) -> Result<(), String> {
    let conn = db::connect()?;
    match type_name.map(str::trim).filter(|t| !t.is_empty()) {
        Some(type_name) => {
            conn.execute(
                "INSERT INTO variable_types (binary_path, func_addr, key, type_name, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (binary_path, func_addr, key)
                 DO UPDATE SET type_name = excluded.type_name,
                               updated_at = excluded.updated_at",
                params![binary_path, func as i64, key, type_name, db::now()],
            )
            .map_err(|e| e.to_string())?;
        }
        None => {
            conn.execute(
                "DELETE FROM variable_types
                 WHERE binary_path = ?1 AND func_addr = ?2 AND key = ?3",
                params![binary_path, func as i64, key],
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Give a datum a type, or clear it when `type_name` is blank.
///
/// The counterpart of `rename_variable`, and keyed the same way: a return
/// value's `key` is [`RETURN_KEY`], an argument's is its register, a local's is
/// its frame offset as a decimal string.
#[tauri::command(async)]
pub fn set_variable_type(
    func: u64,
    key: String,
    type_name: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let guard = session_of(&state)?;
    let engine = with_sess(&guard)?;
    let path = engine.path().to_string_lossy().to_string();
    set_type(&path, func, &key, Some(&type_name))
}

/// The type annotations recorded for the open binary, as `"<func>:<key>" ->
/// type`, in the shape the frontend keeps them under.
#[tauri::command(async)]
pub fn variable_types(state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session_of(&state)?;
    let engine = with_sess(&guard)?;
    let path = engine.path().to_string_lossy().to_string();
    let types: HashMap<String, String> = load(&path)?
        .into_iter()
        .map(|((func, key), type_name)| (format!("{func}:{key}"), type_name))
        .collect();
    serde_json::to_value(types).map_err(|e| e.to_string())
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
            set_type(bin, 0x401000, RETURN_KEY, Some("int")).unwrap();
            set_type(bin, 0x401000, "rdi", Some("char *")).unwrap();
            set_type(bin, 0x401000, "-8", Some("char[8]")).unwrap();
            let types = load(bin).unwrap();
            assert_eq!(
                types
                    .get(&(0x401000, RETURN_KEY.to_string()))
                    .map(String::as_str),
                Some("int")
            );
            assert_eq!(
                types
                    .get(&(0x401000, "rdi".to_string()))
                    .map(String::as_str),
                Some("char *")
            );
            assert_eq!(
                types.get(&(0x401000, "-8".to_string())).map(String::as_str),
                Some("char[8]")
            );

            // Typing over a type replaces it; a blank one clears just that row.
            set_type(bin, 0x401000, RETURN_KEY, Some("long")).unwrap();
            set_type(bin, 0x401000, "-8", Some("  ")).unwrap();
            let types = load(bin).unwrap();
            assert_eq!(
                types
                    .get(&(0x401000, RETURN_KEY.to_string()))
                    .map(String::as_str),
                Some("long")
            );
            assert!(!types.contains_key(&(0x401000, "-8".to_string())));

            // Two functions may both use `-8` for different things.
            set_type(bin, 0x402000, "-8", Some("uint64_t")).unwrap();
            let types = load(bin).unwrap();
            assert_eq!(
                types.get(&(0x402000, "-8".to_string())).map(String::as_str),
                Some("uint64_t")
            );

            // Annotations are scoped per binary, like every other analyst edit.
            assert!(load("/tmp/other").unwrap().is_empty());
        });
    }

    /// A table that cannot be read must not read as a table with nothing in it.
    ///
    /// The same failure `crate::renames` guards against: a loader that returns
    /// an empty map for every fault makes a missing column indistinguishable
    /// from a target nobody has typed, and that reaches the view as "none of my
    /// types are here" rather than as a fault to fix.
    #[test]
    fn an_unreadable_table_is_an_error_rather_than_no_types() {
        crate::testhome::with_test_home(|_| {
            let conn = db::connect().expect("connect");
            // A table whose rows carry a column type the loader cannot decode.
            conn.execute_batch(
                "DROP TABLE variable_types;
                 CREATE TABLE variable_types (
                     binary_path TEXT NOT NULL,
                     func_addr INTEGER NOT NULL,
                     key TEXT NOT NULL,
                     type_name BLOB NOT NULL,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY (binary_path, func_addr, key)
                 );
                 INSERT INTO variable_types VALUES ('/tmp/target', 2304, '<RETURN>', X'00', 0);",
            )
            .expect("plant an unreadable row");
            drop(conn);

            assert!(
                load("/tmp/target").is_err(),
                "a row that cannot be decoded must not be dropped in favour of a short map"
            );
        });
    }
}
