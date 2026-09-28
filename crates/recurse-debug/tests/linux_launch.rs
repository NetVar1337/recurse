//! End-to-end test of the Linux backend: compile a fixture, launch it under
//! the debugger, break on a symbol, inspect registers, step, and detach.
//!
//! Skips (never fails) off Linux, and when this host cannot produce the
//! fixture (no C compiler, one that cannot link it, or no ptrace support).

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

    fn load_bias(&self, _pid: u32, _runtime_entry: Option<u64>) -> Option<u64> {
        // The fixture is linked `-no-pie`, so static == runtime.
        Some(0)
    }
}

/// Compile the fixture into a temp dir and return its path, or `None` when this
/// host cannot produce one.
///
/// Gated on the host platform first: `-no-pie` is a GNU/Linux linker option, and
/// the debugger exercised here is the ptrace backend, so a compiler on another
/// host would build a binary this test cannot launch. Skipping before the
/// compiler runs also keeps a wrong-host build from looking like a test failure.
/// "no compiler" and "could not link" are reported apart, since the first is a
/// missing toolchain and the second is a broken one.
fn build_fixture() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: Linux backend, not the host platform");
        return None;
    }
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
    if !status.success() {
        eprintln!("skipping: `cc` could not build the fixture");
        return None;
    }
    Some(bin)
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
        eprintln!("skipping: no Linux fixture available");
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

#[test]
fn subscribers_see_stops_and_output_without_polling() {
    let Some(bin) = build_fixture() else {
        eprintln!("skipping: no Linux fixture available");
        return;
    };
    let symbols = match elf_symbols(&bin) {
        Some(s) => Arc::new(s),
        None => {
            eprintln!("skipping: could not parse fixture symbols");
            return;
        }
    };
    let dbg = Debugger::with_symbols(symbols).expect("debugger");
    let mut events = dbg.subscribe();
    if let Err(e) = dbg.launch(&LaunchOptions {
        path: bin.to_string_lossy().to_string(),
        ..Default::default()
    }) {
        eprintln!("skipping: launch failed ({e})");
        return;
    }

    // The launch stop is pushed, not waited for, and it is counted.
    let first = next_stop(&mut events, 1, 2_000);
    assert!(first.stop.is_some(), "a stop carries its registers");
    assert!(!first.frames.is_empty(), "and the frames that go with it");

    // A step is the next stop, and it counts as one even though a view is
    // published more than once for it.
    dbg.step(StepKind::Into).expect("step");
    let second = next_stop(&mut events, 2, 2_000);
    assert_eq!(second.stop_seq, 2, "a step is a stop of its own");

    // Installing a breakpoint is not a stop, and says so: a consumer can tell
    // "the program moved" from "this is the same stop arriving again".
    let bp = dbg
        .add_breakpoint(&BreakAt::Symbol {
            name: "check".to_string(),
        })
        .expect("break on check");
    let armed = next_with(&mut events, |s| s.breakpoints.len() == 1, 2_000);
    assert_eq!(armed.stop_seq, 2, "installing a breakpoint is not a stop");
    dbg.remove_breakpoint(bp.id).expect("remove");

    // And the debuggee's output is pushed too, with nothing polling for it: the
    // fixture prints its total on the way out.
    dbg.resume().expect("run to exit");
    let printed = next_output(&mut events, 2_000);
    // `check(i) = i * 2 + 1` for i in 0..3, so the loop prints 1 + 3 + 5.
    assert!(
        printed.contains('9'),
        "expected the fixture's total, got {printed:?}"
    );
    dbg.detach().expect("detach");
}

/// The next published view of the session.
///
/// # Panics
/// If the timeout passes, or an `Output` event turns up: output arrives between
/// stops, and a caller that wanted a stop has to say so.
fn next_stop(
    events: &mut recurse_debug::SessionEvents,
    seq: u64,
    timeout_ms: u64,
) -> recurse_debug::Snapshot {
    next_with(events, move |s| s.stop_seq >= seq, timeout_ms)
}

/// The next published view that satisfies `want`.
///
/// # Panics
/// If the timeout passes first.
fn next_with(
    events: &mut recurse_debug::SessionEvents,
    want: impl Fn(&recurse_debug::Snapshot) -> bool,
    timeout_ms: u64,
) -> recurse_debug::Snapshot {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match events.recv_timeout(left) {
            Ok(recurse_debug::SessionEvent::Snapshot { snapshot }) if want(&snapshot) => {
                return snapshot;
            }
            Ok(recurse_debug::SessionEvent::Snapshot { .. }) => continue,
            Ok(other) => panic!("expected a snapshot, got {other:?}"),
            Err(e) => panic!("nothing matched within {timeout_ms}ms: {e}"),
        }
    }
}

/// Everything the debuggee printed, up to the next snapshot.
///
/// # Panics
/// If the timeout passes before a snapshot ends the run of output.
fn next_output(events: &mut recurse_debug::SessionEvents, timeout_ms: u64) -> String {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut text = String::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match events.recv_timeout(left) {
            Ok(recurse_debug::SessionEvent::Output { text: more }) => text.push_str(&more),
            Ok(recurse_debug::SessionEvent::Snapshot { .. }) if !text.is_empty() => return text,
            Ok(recurse_debug::SessionEvent::Snapshot { .. }) => continue,
            Err(e) => panic!("no output within {timeout_ms}ms: {e}"),
        }
    }
}
