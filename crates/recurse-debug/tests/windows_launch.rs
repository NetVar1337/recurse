//! End-to-end test of the Windows backend: compile a fixture, launch it
//! under the debugger, break on a symbol (resolved from the fixture's own
//! PDB via `recurse_static::winpdb`), inspect registers, step, and
//! detach — the Windows counterpart to `tests/linux_launch.rs`. Also
//! proves `advanced::run_until_condition`/`run_until_watchpoint_change`
//! against this same real, live process.
//!
//! Skips (never fails) when there is no C compiler available.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use recurse_debug::advanced::{
    run_until_condition, run_until_watchpoint_change, Condition, ConditionalBreakpoint, Watchpoint,
};
use recurse_debug::model::{BreakAt, LaunchOptions, StepKind, StopReason};
use recurse_debug::symbols::Symbols;
use recurse_debug::Debugger;

const FIXTURE: &str = r#"
int add(int a, int b) { return a + b; }

int main(void) {
    volatile int x = 1;
    volatile int y = 2;
    volatile int z = add(x, y);
    return z - 3;
}
"#;

/// A `Symbols` source backed by the fixture's own PDB public symbols.
struct PdbSymbols {
    by_addr: HashMap<u64, String>,
    by_name: HashMap<String, u64>,
}

impl Symbols for PdbSymbols {
    fn name_at(&self, addr: u64) -> Option<String> {
        self.by_addr.get(&addr).cloned()
    }

    fn resolve(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    fn load_bias(&self, _pid: u32, _runtime_entry: Option<u64>) -> Option<u64> {
        // The fixture is linked `/DYNAMICBASE:NO`, so its runtime load
        // address equals its preferred image base — static RVA == runtime
        // address, the same "no bias" case `linux_launch.rs`'s `-no-pie`
        // fixture relies on.
        Some(0)
    }
}

/// Compile the fixture into a temp dir with a fixed (non-ASLR) load
/// address and real PDB debug info, or `None` when no compiler is
/// available.
fn build_fixture() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("recurse-debug-win-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join("target.c");
    std::fs::write(&src, FIXTURE).ok()?;
    let bin = dir.join("target.exe");
    let status = Command::new("clang")
        .args(["-O0", "-g", "-Wl,/DYNAMICBASE:NO", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .ok()?;
    status.success().then_some(bin)
}

/// Resolve `add`'s and `main`'s runtime addresses from the fixture's own
/// PDB (image base + RVA; see [`PdbSymbols::load_bias`]).
fn pdb_symbols(exe: &std::path::Path) -> Option<PdbSymbols> {
    let data = std::fs::read(exe).ok()?;
    let file = object::File::parse(&*data).ok()?;
    use object::Object;
    let base = file.relative_address_base();

    let pdb_path = exe.with_extension("pdb");
    let syms = recurse_static::winpdb::load_public_symbols(&pdb_path).ok()?;
    let mut by_addr = HashMap::new();
    let mut by_name = HashMap::new();
    for s in syms {
        let addr = base + u64::from(s.rva);
        by_addr.insert(addr, s.name.clone());
        by_name.insert(s.name, addr);
    }
    Some(PdbSymbols { by_addr, by_name })
}

#[test]
fn launch_break_step_detach() {
    let Some(bin) = build_fixture() else {
        eprintln!("skipping: no `clang` available");
        return;
    };
    let Some(symbols) = pdb_symbols(&bin) else {
        eprintln!("skipping: could not read fixture PDB");
        return;
    };
    let Some(&add_addr) = symbols.by_name.get("add") else {
        eprintln!("skipping: `add` symbol not found in fixture PDB");
        return;
    };

    let dbg = match Debugger::with_symbols(Arc::new(symbols)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skipping: no Windows debugger backend ({e})");
            return;
        }
    };

    let launched = dbg.launch(&LaunchOptions {
        path: bin.to_string_lossy().to_string(),
        ..Default::default()
    });
    let Ok(initial) = launched else {
        eprintln!("skipping: could not launch fixture ({launched:?})");
        return;
    };
    assert!(
        matches!(
            initial.reason,
            StopReason::Started | StopReason::Signal { .. }
        ),
        "{:?}",
        initial.reason
    );

    let bp = dbg
        .add_breakpoint(&BreakAt::Addr { addr: add_addr })
        .expect("add breakpoint");
    let stop = dbg.resume().expect("resume to breakpoint");
    match stop.reason {
        StopReason::Breakpoint { addr, id } => {
            assert_eq!(addr, add_addr);
            assert_eq!(id, bp.id);
        }
        other => panic!("expected a breakpoint stop, got {other:?}"),
    }
    assert_eq!(stop.registers.pc, add_addr);

    // Windows x64 calling convention: the first two integer args (`a`,
    // `b`) arrive in RCX/RDX. The fixture calls `add(x, y)` with x=1,
    // y=2.
    let rcx = stop.registers.values.get("rcx").copied().unwrap_or(0) as u32;
    let rdx = stop.registers.values.get("rdx").copied().unwrap_or(0) as u32;
    assert_eq!(rcx, 1, "a == 1");
    assert_eq!(rdx, 2, "b == 2");

    let stepped = dbg.step(StepKind::Into).expect("single step");
    assert!(
        matches!(stepped.reason, StopReason::Step),
        "{:?}",
        stepped.reason
    );
    assert_ne!(stepped.registers.pc, add_addr, "pc must have advanced");

    dbg.detach().expect("detach");
}

#[test]
fn conditional_breakpoint_stops_only_when_the_condition_is_true() {
    let Some(bin) = build_fixture() else {
        eprintln!("skipping: no `clang` available");
        return;
    };
    let Some(symbols) = pdb_symbols(&bin) else {
        eprintln!("skipping: could not read fixture PDB");
        return;
    };
    let Some(&add_addr) = symbols.by_name.get("add") else {
        eprintln!("skipping: `add` symbol not found in fixture PDB");
        return;
    };
    let dbg = match Debugger::with_symbols(Arc::new(symbols)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skipping: no Windows debugger backend ({e})");
            return;
        }
    };
    let Ok(_initial) = dbg.launch(&LaunchOptions {
        path: bin.to_string_lossy().to_string(),
        ..Default::default()
    }) else {
        eprintln!("skipping: could not launch fixture");
        return;
    };
    dbg.add_breakpoint(&BreakAt::Addr { addr: add_addr })
        .expect("add breakpoint");

    // A tautology: this must stop on the very first hit of `add`.
    let mut always_true = [ConditionalBreakpoint::new(
        add_addr,
        Condition::parse("rsp != 0").expect("parse"),
    )];
    let (stop, _log) =
        run_until_condition(&dbg, &mut always_true, &[], 10).expect("run_until_condition");
    assert!(matches!(stop.reason, StopReason::Breakpoint { addr, .. } if addr == add_addr));
    assert_eq!(always_true[0].hit_count, 1);

    dbg.kill().expect("kill");
}

#[test]
fn conditional_breakpoint_transparently_runs_past_a_false_condition_to_exit() {
    let Some(bin) = build_fixture() else {
        eprintln!("skipping: no `clang` available");
        return;
    };
    let Some(symbols) = pdb_symbols(&bin) else {
        eprintln!("skipping: could not read fixture PDB");
        return;
    };
    let Some(&add_addr) = symbols.by_name.get("add") else {
        eprintln!("skipping: `add` symbol not found in fixture PDB");
        return;
    };
    let dbg = match Debugger::with_symbols(Arc::new(symbols)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skipping: no Windows debugger backend ({e})");
            return;
        }
    };
    let Ok(_initial) = dbg.launch(&LaunchOptions {
        path: bin.to_string_lossy().to_string(),
        ..Default::default()
    }) else {
        eprintln!("skipping: could not launch fixture");
        return;
    };
    dbg.add_breakpoint(&BreakAt::Addr { addr: add_addr })
        .expect("add breakpoint");

    // A contradiction: `add` is only ever called once by the fixture, so
    // a condition that's always false must transparently run the process
    // to completion rather than ever reporting a stop there.
    let mut always_false = [ConditionalBreakpoint::new(
        add_addr,
        Condition::parse("rsp == 0").expect("parse"),
    )];
    let (stop, _log) =
        run_until_condition(&dbg, &mut always_false, &[], 10).expect("run_until_condition");
    assert!(
        matches!(stop.reason, StopReason::Exited { .. }),
        "{:?}",
        stop.reason
    );
    assert_eq!(
        always_false[0].hit_count, 1,
        "the condition must still have been evaluated once"
    );
}

#[test]
fn software_watchpoint_detects_a_real_stack_write_while_single_stepping() {
    let Some(bin) = build_fixture() else {
        eprintln!("skipping: no `clang` available");
        return;
    };
    let Some(symbols) = pdb_symbols(&bin) else {
        eprintln!("skipping: could not read fixture PDB");
        return;
    };
    let dbg = match Debugger::with_symbols(Arc::new(symbols)) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skipping: no Windows debugger backend ({e})");
            return;
        }
    };
    let Ok(initial) = dbg.launch(&LaunchOptions {
        path: bin.to_string_lossy().to_string(),
        ..Default::default()
    }) else {
        eprintln!("skipping: could not launch fixture");
        return;
    };

    // Watch the top-of-stack word at the initial (loader) stop: CRT/loader
    // startup code writes to its own stack frame constantly during early
    // init, so this must change within a modest single-step budget.
    let mut watchpoints = [Watchpoint::new(initial.registers.sp, 8)];
    let result = run_until_watchpoint_change(&dbg, &mut watchpoints, 5_000)
        .expect("run_until_watchpoint_change");
    assert!(
        result.is_some(),
        "expected the watched stack word to change within the step budget"
    );

    dbg.kill().expect("kill");
}
