//! End-to-end test of the Linux backend: compile a fixture, launch it under
//! the debugger, break on a symbol, inspect registers, step, and detach.
//!
//! Skips (never fails) when there is no C compiler or no ptrace support.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use recurse_debug::model::{BreakAt, LaunchOptions, StepKind, StopReason};
use recurse_debug::symbols::Symbols;
use recurse_debug::Debugger;

use object::{Object, ObjectSymbol};

const FIXTURE: &str = r#"
#include <stdio.h>

__attribute__((noinline)) int check(int x) {
    return x * 2 + 1;
}

int main(void) {
    int total = 0;
    for (int i = 0; i < 3; i++) total += check(i);
    printf("%d\n", total);
    return 0;
}
"#;

/// A `Symbols` source backed by the fixture's own ELF symbol table.
struct ElfSymbols {
    by_addr: HashMap<u64, String>,
    by_name: HashMap<String, u64>,
}

impl Symbols for ElfSymbols {
    fn name_at(&self, addr: u64) -> Option<String> {
        self.by_addr.get(&addr).cloned()
    }

    fn resolve(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    fn load_bias(&self, _pid: u32) -> Option<u64> {
        // The fixture is linked `-no-pie`, so static == runtime.
        Some(0)
    }
}

/// Compile the fixture into a temp dir and return its path, or `None` when no
/// compiler is available.
fn build_fixture() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("recurse-debug-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join("target.c");
    std::fs::write(&src, FIXTURE).ok()?;
    let bin = dir.join("target");
    let status = Command::new("cc")
        .args(["-O0", "-g", "-no-pie", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .ok()?;
    status.success().then_some(bin)
}

/// Parse the fixture's symbols for the debugger.
fn elf_symbols(path: &Path) -> Option<ElfSymbols> {
    let data = std::fs::read(path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let mut by_addr = HashMap::new();
    let mut by_name = HashMap::new();
    for sym in file.symbols() {
        if sym.address() == 0 {
            continue;
        }
        if let Ok(name) = sym.name() {
            if !name.is_empty() {
                by_addr.insert(sym.address(), name.to_string());
                by_name.insert(name.to_string(), sym.address());
            }
        }
    }
    Some(ElfSymbols { by_addr, by_name })
}

#[test]
fn launch_break_step_detach() {
    let Some(bin) = build_fixture() else {
        eprintln!("skipping: no `cc` available");
        return;
    };
    let symbols = match elf_symbols(&bin) {
        Some(s) => Arc::new(s),
        None => {
            eprintln!("skipping: could not parse fixture symbols");
            return;
        }
    };
    let check_addr = symbols.resolve("check").expect("check symbol");

    let dbg = Debugger::with_symbols(symbols).expect("debugger");
    let stop = match dbg.launch(&LaunchOptions {
        path: bin.to_string_lossy().to_string(),
        ..Default::default()
    }) {
        Ok(stop) => stop,
        Err(e) => {
            eprintln!("skipping: launch failed ({e})");
            return;
        }
    };
    assert!(matches!(stop.reason, StopReason::Started));

    // Break on `check` and run to it.
    let bp = dbg
        .add_breakpoint(&BreakAt::Symbol {
            name: "check".to_string(),
        })
        .expect("break on check");
    assert_eq!(bp.addr, check_addr);

    let hit = dbg.resume().expect("resume to breakpoint");
    match hit.reason {
        StopReason::Breakpoint { addr, .. } => assert_eq!(addr, check_addr),
        other => panic!("expected breakpoint hit, got {other:?}"),
    }
    assert_eq!(hit.registers.pc, check_addr, "pc is at the breakpoint");
    assert_ne!(hit.registers.sp, 0, "stack pointer is set");

    // The breakpoint byte is installed; memory at the address reads as int3.
    let bytes = dbg.read_memory(check_addr, 1).expect("read memory");
    assert_eq!(bytes[0], 0xcc, "trap byte present");

    // Step one instruction.
    let stepped = dbg.step(StepKind::Into).expect("step");
    assert!(matches!(stepped.reason, StopReason::Step));
    assert_ne!(
        stepped.registers.pc, check_addr,
        "pc advanced past the break"
    );

    // Remove the breakpoint (the loop calls `check` again) and run to exit.
    dbg.remove_breakpoint(bp.id).expect("remove breakpoint");
    let end = dbg.resume().expect("resume to exit");
    assert!(
        matches!(
            end.reason,
            StopReason::Exited { .. } | StopReason::Killed { .. }
        ),
        "unexpected end: {:?}",
        end.reason
    );

    dbg.detach().expect("detach");
}
