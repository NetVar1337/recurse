//! Naming code in a running process that is not the debuggee's own binary.
//!
//! A dynamically linked program's calls mostly go somewhere the analysis
//! engine has never seen: `__libc_start_main` calls into libc, and libc is a
//! different file with its own symbol table. The pane can only say
//! `call 0x7f2c1a4b9820` for those, which is the one call an analyst most wants
//! a name for.
//!
//! Two pieces make it say `; __libc_setup_tls` instead:
//!
//! * which file is mapped where — the kernel's own answer, in
//!   `/proc/<pid>/maps`; and
//! * what that file's symbols are — read straight from its symbol table, with
//!   no disassembly and no analysis pass, because a symbol table is a sorted
//!   list of addresses and a call target is a function entry.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

/// One file mapped into the process, with the address range it occupies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Module {
    /// Path as the kernel spells it.
    pub path: String,
    /// Lowest mapped address of the file, which is its load bias.
    pub base: u64,
    /// One past the highest mapped address of the file.
    pub end: u64,
}

/// One symbol in a module: a function entry, by static address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModuleSymbol {
    /// Address in the file's own address space.
    pub addr: u64,
    /// Symbol name, shortened the way the analysis engine shortens one.
    pub name: String,
    /// Whether the symbol is a declared function, or an untyped label in code.
    ///
    /// An untyped label can sit *inside* a function, so a caller resolving an
    /// address inside a function prefers a declared function over it.
    pub is_func: bool,
}

/// The files mapped into `pid`, one entry per path.
///
/// Anonymous and special mappings are dropped: they have no file behind them,
/// and therefore no symbols to contribute.
pub fn modules(pid: u32) -> Result<Vec<Module>, String> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| format!("read /proc/{pid}/maps: {e}"))?;
    Ok(parse_maps(&maps))
}

/// The file-backed mappings in the text of `/proc/<pid>/maps`.
///
/// One file usually appears as several lines — one per segment, and a
/// relro/guard page can split it further — so the ranges are merged per path and
/// the base is the lowest of them. A path that is only mapped as data is still
/// reported: a `call` cannot land in it, but a name resolved from it is not
/// wrong, and skipping the check would cost a syscall per candidate.
///
/// ```
/// use recurse_lib::debug_modules::parse_maps;
///
/// let text = "\
/// 55b0d4000000-55b0d4002000 r--p 00000000 08:01 1234 /bin/target
/// 55b0d4002000-55b0d4007000 r-xp 00002000 08:01 1234 /bin/target
/// 55b0d4007000-55b0d4009000 rw-p 00007000 08:01 1234 /bin/target
/// 7f2c1a000000-7f2c1a021000 r--p 00000000 08:01 5678 /lib/libc.so.6
/// 7f2c1a021000-7f2c1a140000 r-xp 00021000 08:01 5678 /lib/libc.so.6
/// 7ffd3dc95000-7ffd3dc97000 rw-p 00000000 00:00 0    [anon]
/// ";
///
/// let mods = parse_maps(text);
/// assert_eq!(mods.len(), 2);
/// assert_eq!(mods[1].path, "/lib/libc.so.6");
/// assert_eq!(mods[1].base, 0x7f2c1a000000);
/// assert_eq!(mods[1].end, 0x7f2c1a140000);
/// ```
pub fn parse_maps(text: &str) -> Vec<Module> {
    let mut by_path: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        // The path is the last field, and it is absent for anonymous mappings.
        let Some(path) = line.split_whitespace().last() else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let span = by_path.entry(path.to_string()).or_insert((start, end));
        span.0 = span.0.min(start);
        span.1 = span.1.max(end);
    }
    by_path
        .into_iter()
        .map(|(path, (base, end))| Module { path, base, end })
        .collect()
}

/// The module an address belongs to, if any.
pub fn module_at<'a>(modules: &'a [Module], addr: u64) -> Option<&'a Module> {
    modules.iter().find(|m| addr >= m.base && addr < m.end)
}

/// The functions and code labels `path` defines, sorted by address.
///
/// Read from the symbol table only. A full analysis pass would find more, but
/// it also takes seconds on a library the size of libc, and every symbol a call
/// target can land on is in the symbol table by construction — a call goes to a
/// function entry, and a linker-provided function entry is a symbol.
pub fn symbols(path: &str) -> Result<Vec<ModuleSymbol>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    symbols_of(&bytes)
}

/// [`symbols`] over bytes already read.
pub fn symbols_of(bytes: &[u8]) -> Result<Vec<ModuleSymbol>, String> {
    let file = object::File::parse(bytes).map_err(|e| format!("parse symbols: {e}"))?;
    let mut out: Vec<ModuleSymbol> = recurse_static::native::symbol_seeds(&file)
        .into_iter()
        .map(|(addr, kind, name)| ModuleSymbol {
            addr,
            name,
            is_func: matches!(kind, recurse_static::native::SymbolSeedKind::Func),
        })
        .collect();
    // Sorted, because the lookup is "the nearest symbol at or below", and that
    // is only a binary search if they are in order. Duplicates come from a
    // symbol appearing in both `.symtab` and `.dynsym`; the declared function
    // wins, since that is the one the name belongs to.
    out.sort_by(|a, b| a.addr.cmp(&b.addr).then(b.is_func.cmp(&a.is_func)));
    out.dedup_by(|a, b| a.addr == b.addr);
    Ok(out)
}

/// The function containing `addr` in `symbols`, or the nearest one below it.
///
/// A call target is a function entry, so the nearest symbol at or below is the
/// answer. When a size is known the answer is checked rather than assumed: a
/// declared function that contains the address beats a label inside it, and an
/// address past a known function's end is not claimed at all. `.dynsym` entries
/// carry no size, which is why a stripped library's names are the nearest ones
/// rather than proven ones — reported as `name+0x1f` so the distance is visible
/// rather than implied.
pub fn resolve(symbols: &[ModuleSymbol], addr: u64) -> Option<(String, u64)> {
    let at = symbols.partition_point(|s| s.addr <= addr);
    let below = symbols[..at].iter().rev().find(|s| s.is_func)?;
    let offset = addr - below.addr;
    Some((below.name.clone(), offset))
}

/// The file name a module path ends with, without its directory or version
/// suffix: `/lib/x86_64-linux-gnu/libc.so.6` reads as `libc`.
pub fn short_module(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.split(".so").next().unwrap_or(file).to_string()
}

/// Whether `path` names a readable file, for a caller's early exit.
pub fn is_readable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const MAPS: &str = "\
55b0d4000000-55b0d4002000 r--p 00000000 08:01 1234 /bin/target
55b0d4002000-55b0d4007000 r-xp 00002000 08:01 1234 /bin/target
55b0d4007000-55b0d4009000 rw-p 00007000 08:01 1234 /bin/target
7f2c1a000000-7f2c1a021000 r--p 00000000 08:01 5678 /lib/libc.so.6
7f2c1a021000-7f2c1a140000 r-xp 00021000 08:01 5678 /lib/libc.so.6
7ffd3dc95000-7ffd3dc97000 rw-p 00000000 00:00 0
7ffd3dc97000-7ffd3dca8000 rw-p 00000000 00:00 0    [stack]
";

    #[test]
    fn merges_the_segments_of_one_file() {
        let mods = parse_maps(MAPS);
        assert_eq!(mods.len(), 2);
        let target = &mods[0];
        assert_eq!(target.path, "/bin/target");
        assert_eq!(target.base, 0x55b0d4000000);
        assert_eq!(target.end, 0x55b0d4009000);
    }

    #[test]
    fn drops_mappings_with_no_file_behind_them() {
        // A heap or stack address belongs to no module, which is what stops a
        // garbage pointer from being named after whatever sits below it.
        assert!(module_at(&parse_maps(MAPS), 0x7ffd3dc96000).is_none());
    }

    #[test]
    fn finds_the_module_an_address_is_in() {
        let mods = parse_maps(MAPS);
        let libc = module_at(&mods, 0x7f2c1a100000).expect("libc");
        assert_eq!(libc.path, "/lib/libc.so.6");
        assert_eq!(short_module(&libc.path), "libc");
        // The first byte past the end belongs to nothing.
        assert!(module_at(&mods, 0x7f2c1a140000).is_none());
    }

    #[test]
    fn ignores_lines_it_cannot_read() {
        assert!(parse_maps("").is_empty());
        assert!(parse_maps("not-a-map-line\n").is_empty());
        assert!(parse_maps("zzz-fff r--p 0 0 0 /bin/x\n").is_empty());
    }

    #[test]
    fn resolves_an_exact_entry() {
        let symbols = vec![
            ModuleSymbol {
                addr: 0x1000,
                name: "a".into(),
                is_func: true,
            },
            ModuleSymbol {
                addr: 0x2000,
                name: "b".into(),
                is_func: true,
            },
        ];
        assert_eq!(resolve(&symbols, 0x2000), Some(("b".into(), 0)));
    }

    #[test]
    fn resolves_inside_a_function_to_the_function_below() {
        let symbols = vec![ModuleSymbol {
            addr: 0x2000,
            name: "b".into(),
            is_func: true,
        }];
        assert_eq!(resolve(&symbols, 0x201f), Some(("b".into(), 0x1f)));
    }

    #[test]
    fn prefers_a_function_over_a_label_inside_it() {
        // `.symtab` and `.dynsym` both list the function; an assembly label sits
        // inside it. Naming the label would be naming nothing useful.
        let symbols = vec![
            ModuleSymbol {
                addr: 0x2000,
                name: "b".into(),
                is_func: true,
            },
            ModuleSymbol {
                addr: 0x2010,
                name: "b.local".into(),
                is_func: false,
            },
        ];
        assert_eq!(resolve(&symbols, 0x2018), Some(("b".into(), 0x18)));
    }

    #[test]
    fn claims_nothing_below_the_first_symbol() {
        let symbols = vec![ModuleSymbol {
            addr: 0x2000,
            name: "b".into(),
            is_func: true,
        }];
        assert_eq!(resolve(&symbols, 0x1000), None);
    }
}
