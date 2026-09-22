//! Windows PDB (CodeView) debug info ingestion: public symbol names and
//! RVAs from a `.pdb` file — for a binary shipped without its own debug
//! info (the common release-build case) but with a matching PDB available
//! (from the build itself, or downloaded from a symbol server). Named
//! `winpdb`, not `pdb`, so this module never shadows the `pdb` crate it
//! wraps.
//!
//! # Scope, honestly
//!
//! Public symbols only (`pdb::SymbolData::Public`) — name plus relative
//! virtual address. A PDB's *type* information (real function signatures,
//! local variable names/types — the PDB-side equivalent of what
//! `crate::dwarf` recovers for ELF/Mach-O from `.debug_info`) lives in a
//! much more involved part of the format (the TPI/IPI type-information
//! streams) that this module does not parse. Public-symbol-to-name mapping
//! is nonetheless the single highest-value PDB use case for RE — turning
//! `sub_140001000` into its real name — and the one this module delivers.
//!
//! Not wired into `Engine`/`analyze` yet, same as `crate::types`/`crate::sig`:
//! a standalone library capability first (`Engine::set_renames` already
//! exists as the mechanism a host would feed these names into).

use std::path::Path;

use pdb::FallibleIterator;

/// One public symbol: a name and the relative virtual address (offset from
/// the module's own preferred base, not an absolute address) it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdbSymbol {
    pub name: String,
    pub rva: u32,
}

/// Load every public symbol from the PDB at `path`.
pub fn load_public_symbols(path: &Path) -> Result<Vec<PdbSymbol>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    load_public_symbols_from(file)
}

/// [`load_public_symbols`] over an already-open reader — the file handle
/// PDB itself needs to seek around the MSF container, or any other
/// `Read + Seek + Source<'_>` the caller already has open.
pub fn load_public_symbols_from<'s, S: pdb::Source<'s> + 's>(
    source: S,
) -> Result<Vec<PdbSymbol>, String> {
    let mut pdb_file = pdb::PDB::open(source).map_err(|e| format!("open PDB: {e}"))?;
    let symbol_table = pdb_file
        .global_symbols()
        .map_err(|e| format!("read global symbols: {e}"))?;
    let address_map = pdb_file
        .address_map()
        .map_err(|e| format!("read address map: {e}"))?;

    let mut out = Vec::new();
    let mut symbols = symbol_table.iter();
    while let Some(symbol) = symbols
        .next()
        .map_err(|e| format!("iterate symbols: {e}"))?
    {
        let Ok(pdb::SymbolData::Public(data)) = symbol.parse() else {
            continue;
        };
        if let Some(rva) = data.offset.to_rva(&address_map) {
            out.push(PdbSymbol {
                name: data.name.to_string().into_owned(),
                rva: rva.0,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Cursor;

    /// Not a real PDB: this module must report a clean `Err`, not panic,
    /// on input that fails the MSF container's own header check — the
    /// common "wrong file" / "corrupted download" case.
    #[test]
    fn garbage_input_is_a_clean_error_not_a_panic() {
        let data = vec![0u8; 64];
        let result = load_public_symbols_from(Cursor::new(data));
        assert!(result.is_err());
    }

    #[test]
    fn empty_input_is_a_clean_error_not_a_panic() {
        let result = load_public_symbols_from(Cursor::new(Vec::<u8>::new()));
        assert!(result.is_err());
    }

    /// A real happy-path test, against a real PDB: an MSVC debug build
    /// (the default on this target) always writes the test binary's own
    /// `.pdb` right next to it. Skips (does not fail) when that sibling
    /// file is absent — a release build, or a non-Windows-MSVC target,
    /// legitimately has none.
    #[test]
    fn real_pdb_alongside_the_test_binary_when_present() {
        let exe = std::env::current_exe().expect("test exe");
        let pdb_path = exe.with_extension("pdb");
        if !pdb_path.exists() {
            eprintln!(
                "no sibling .pdb for {}; skipping (expected off Windows/MSVC)",
                exe.display()
            );
            return;
        }
        let symbols = load_public_symbols(&pdb_path).expect("parse sibling pdb");
        assert!(
            !symbols.is_empty(),
            "a debug build's own PDB should have public symbols"
        );
        assert!(
            symbols.iter().any(|s| s.name.contains("recurse_static")),
            "expected a recurse_static symbol among {} public symbols",
            symbols.len()
        );
    }
}
