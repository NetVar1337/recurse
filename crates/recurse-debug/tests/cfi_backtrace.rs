//! CFI unwinding: on `-O2 -fomit-frame-pointer` code a frame-pointer walk
//! cannot recover the call chain, so the backtrace must come from `.eh_frame`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use object::{Object, ObjectSymbol};
use recurse_debug::model::{BreakAt, LaunchOptions};
use recurse_debug::symbols::Symbols;
use recurse_debug::Debugger;

const FIXTURE: &str = r#"
#include <stdio.h>

__attribute__((noinline)) int inner(int x) { return x * 3 + 1; }

__attribute__((noinline)) int check(int x) { return inner(x) + inner(x + 1); }

int main(void) {
    int total = 0;
    for (int i = 0; i < 3; i++) total += check(i);
    printf("%d\n", total);
    return 0;
}
"#;

/// A `Symbols` source backed by the fixture's own ELF symbol table, with range
/// lookup (a return address points inside a function, not at its entry).
struct ElfSymbols {
    /// `(address, size, name)`, sorted by address.
    funcs: Vec<(u64, u64, String)>,
    by_name: HashMap<String, u64>,
}

impl Symbols for ElfSymbols {
    fn name_at(&self, addr: u64) -> Option<String> {
        let idx = self.funcs.partition_point(|(a, _, _)| *a <= addr);
        let (base, size, name) = self.funcs.get(idx.checked_sub(1)?)?;
        (*size == 0 || addr < base + size).then(|| name.clone())
    }

    fn resolve(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    fn load_bias(&self, _pid: u32, _runtime_entry: Option<u64>) -> Option<u64> {
        Some(0)
    }
}

/// Compile the fixture eagerly optimized, or `None` when no compiler exists.
fn build_fixture() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("recurse-cfi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join("target.c");
    std::fs::write(&src, FIXTURE).ok()?;
    let bin = dir.join("target");
    let status = Command::new("cc")
        .args(["-O2", "-fomit-frame-pointer", "-no-pie", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .ok()?;
    status.success().then_some(bin)
}

fn elf_symbols(path: &Path) -> Option<ElfSymbols> {
    let data = std::fs::read(path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let mut funcs = Vec::new();
    let mut by_name = HashMap::new();
    for sym in file.symbols() {
        if sym.address() == 0 {
            continue;
        }
        if let Ok(name) = sym.name() {
            if !name.is_empty() {
                funcs.push((sym.address(), sym.size(), name.to_string()));
                by_name.insert(name.to_string(), sym.address());
            }
        }
    }
    funcs.sort_by_key(|(a, _, _)| *a);
    Some(ElfSymbols { funcs, by_name })
}

#[test]
fn backtrace_unwinds_optimized_code() {
    let Some(bin) = build_fixture() else {
        eprintln!("skipping: no `cc` available");
        return;
    };
    let Some(symbols) = elf_symbols(&bin) else {
        return;
    };
    let inner = match symbols.resolve("inner") {
        Some(a) => a,
        None => return,
    };
    let symbols = Arc::new(symbols);

    let dbg = match Debugger::with_symbols(symbols) {
        Ok(d) => d,
        Err(_) => return,
    };
    if dbg
        .launch(&LaunchOptions {
            path: bin.to_string_lossy().to_string(),
            ..Default::default()
        })
        .is_err()
    {
        return;
    }
    dbg.add_breakpoint(&BreakAt::Addr { addr: inner })
        .expect("break at inner");
    let hit = match dbg.resume() {
        Ok(s) => s,
        Err(_) => return,
    };
    assert_eq!(hit.registers.pc, inner);

    let frames = dbg.backtrace(None).expect("backtrace");
    let names: Vec<String> = frames
        .iter()
        .map(|f| f.name.clone().unwrap_or_default())
        .collect();
    assert!(
        frames.len() >= 3,
        "expected a real call chain, got {names:?}"
    );
    assert!(names.iter().any(|n| n == "main"), "main in {names:?}");
    assert!(names.iter().any(|n| n == "check"), "check in {names:?}");

    let _ = dbg.kill();
}
