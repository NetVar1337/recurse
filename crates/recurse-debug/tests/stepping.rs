//! Stepping: `Into`, `Over` and `Out` have to stop where the program actually
//! goes next, on straight-line code, inside a loop, and in a frame that says
//! nothing about where it returns to.
//!
//! The interesting cases are the ones a naive step gets wrong. `Over` at a call
//! resumes at the *next instruction*, not at the return address the call pushed
//! — those are only the same address at a function's entry. `Out` resumes where
//! the frame returns, which is the top of the stack only at a function's entry
//! too: one instruction in, the top of the stack is a saved register, and a
//! step out built on it runs away and stops at the next call of the same
//! function.
//!
//! Skips (never fails) off Linux, and when this host cannot produce the
//! fixtures.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use object::{Object, ObjectSymbol};
use recurse_debug::model::{BreakAt, LaunchOptions, StepKind};
use recurse_debug::symbols::Symbols;
use recurse_debug::Debugger;

const FIXTURE: &str = r#"
#include <stdio.h>

__attribute__((noinline)) int inner(int x) {
    return x * 2 + 1;
}

__attribute__((noinline)) int outer(int x) {
    int a = inner(x);
    int b = inner(x + 1);
    return a + b;
}

int main(void) {
    int total = 0;
    for (int i = 0; i < 2; i++) total += outer(i);
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
        // Both fixtures are linked `-no-pie`, so static == runtime.
        Some(0)
    }
}

/// Compile the fixture, or `None` when this host cannot produce one.
///
/// `unwind` asks for the build a normal compiler makes, with `.eh_frame` and
/// frame pointers; the negative case asks for one with neither, which is what a
/// hand-written or stripped routine looks like to a debugger.
///
/// Gated on the host platform first: `-no-pie` is a GNU/Linux linker option and
/// the stepping under test is the ptrace backend, so a compiler on another host
/// would build binaries this test cannot launch.
fn build_fixture(unwind: bool) -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: Linux backend, not the host platform");
        return None;
    }
    let tag = if unwind { "unwind" } else { "nouwind" };
    let dir = std::env::temp_dir().join(format!("recurse-step-{}-{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join("target.c");
    std::fs::write(&src, FIXTURE).ok()?;
    let bin = dir.join("target");
    let mut cc = Command::new("cc");
    cc.args(["-O0", "-g", "-no-pie"]);
    if unwind {
        cc.arg("-fno-omit-frame-pointer");
    } else {
        // No unwind tables and no frame pointers: nothing says where this frame
        // returns to except the stack moving.
        cc.args(["-fomit-frame-pointer", "-fno-asynchronous-unwind-tables"]);
    }
    let status = cc.arg("-o").arg(&bin).arg(&src).status().ok()?;
    if !status.success() {
        eprintln!("skipping: `cc` could not build the {tag} fixture");
        return None;
    }
    Some(bin)
}

/// Parse the fixture's symbols for the debugger.
fn elf_symbols(path: &Path) -> Option<ElfSymbols> {
    let data = std::fs::read(path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let mut funcs: Vec<(u64, u64, String)> = Vec::new();
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
    funcs.sort_by_key(|(addr, _, _)| *addr);
    Some(ElfSymbols { funcs, by_name })
}

/// Launch the fixture and hand back the session and its symbols.
fn launch(unwind: bool) -> Option<(Debugger, Arc<ElfSymbols>, PathBuf)> {
    let bin = build_fixture(unwind)?;
    let symbols = Arc::new(elf_symbols(&bin)?);
    let dbg = Debugger::with_symbols(symbols.clone()).ok()?;
    let stop = dbg
        .launch(&LaunchOptions {
            path: bin.to_string_lossy().to_string(),
            ..Default::default()
        })
        .ok()?;
    if !matches!(stop.reason, recurse_debug::model::StopReason::Started) {
        return None;
    }
    Some((dbg, symbols, bin))
}

/// The address of `name` in the fixture.
fn addr_of(symbols: &ElfSymbols, name: &str) -> u64 {
    symbols
        .resolve(name)
        .unwrap_or_else(|| panic!("fixture has no `{name}`"))
}

/// The first `call` in `func` as `(address, length in bytes)`, found by decoding
/// rather than by a hardcoded offset.
///
/// Both halves have to come from this decode, before any breakpoint is
/// installed: a call with a trap byte in front of it decodes as `int3`, and a
/// test that measured the length afterwards would be measuring its own
/// breakpoint.
fn first_call(dbg: &Debugger, func: u64) -> (u64, u64) {
    let insns = dbg.disasm(func, 16).expect("disassemble");
    let call = insns
        .iter()
        .find(|i| i.text.starts_with("call"))
        .unwrap_or_else(|| panic!("no call in the function at {func:#x}"));
    (call.addr, call.bytes.len() as u64 / 2)
}

#[test]
fn step_over_a_call_resumes_after_it() {
    let Some((dbg, symbols, _)) = launch(true) else {
        eprintln!("skipping: no launchable fixture");
        return;
    };
    // The `call inner` in `outer`.
    let (call_site, call_len) = first_call(&dbg, addr_of(&symbols, "outer"));
    dbg.add_breakpoint(&BreakAt::Addr { addr: call_site })
        .expect("break on the call");
    dbg.resume().expect("run to the call");

    let stop = dbg.step(StepKind::Over).expect("over the call");
    // The instruction after the call, not the return address the call pushed:
    // `inner` has to have run, and `outer` has to be back on its own track.
    assert_eq!(stop.registers.pc, call_site + call_len);
    dbg.kill().ok();
}

#[test]
fn step_out_of_a_function_entry() {
    let Some((dbg, symbols, _)) = launch(true) else {
        eprintln!("skipping: no launchable fixture");
        return;
    };
    let inner = addr_of(&symbols, "inner");
    let outer = addr_of(&symbols, "outer");
    dbg.add_breakpoint(&BreakAt::Addr { addr: inner })
        .expect("break on inner");
    dbg.resume().expect("run to inner");

    // At `inner`'s entry the frame pointer is still `outer`'s, so a frame-pointer
    // walk reports the caller of the *caller*. Only unwind data gets this right.
    let stop = dbg.step(StepKind::Out).expect("out of inner");
    assert!(
        stop.registers.pc > outer && stop.registers.pc < addr_of(&symbols, "main"),
        "expected to land back in `outer`, got {:#x}",
        stop.registers.pc
    );
    dbg.kill().ok();
}

#[test]
fn step_out_from_inside_a_function() {
    let Some((dbg, symbols, _)) = launch(true) else {
        eprintln!("skipping: no launchable fixture");
        return;
    };
    let inner = addr_of(&symbols, "inner");
    let outer = addr_of(&symbols, "outer");
    dbg.add_breakpoint(&BreakAt::Addr { addr: inner })
        .expect("break on inner");
    dbg.resume().expect("run to inner");

    // Past the prologue, where the top of the stack is a saved register rather
    // than a return address. This is the case that used to run away: the step out
    // planted its breakpoint on the saved register and came back round to the
    // *next* call of `inner` instead of returning.
    for _ in 0..3 {
        dbg.step(StepKind::Into).expect("into");
    }
    let stop = dbg.step(StepKind::Out).expect("out of inner");
    assert!(
        stop.registers.pc > outer && stop.registers.pc < addr_of(&symbols, "main"),
        "expected to land back in `outer`, got {:#x}",
        stop.registers.pc
    );
    dbg.kill().ok();
}

#[test]
fn step_out_without_unwind_data_follows_the_stack() {
    // A frame with no `.eh_frame` and no frame pointer says nothing about where
    // it returns to. The stack does: it comes back up when the frame is gone.
    let Some((dbg, symbols, _)) = launch(false) else {
        eprintln!("skipping: no launchable fixture");
        return;
    };
    let inner = addr_of(&symbols, "inner");
    let outer = addr_of(&symbols, "outer");
    let bp = dbg
        .add_breakpoint(&BreakAt::Addr { addr: inner })
        .expect("break on inner");
    dbg.resume().expect("run to inner");
    for _ in 0..2 {
        dbg.step(StepKind::Into).expect("into");
    }
    // Off it, so what stops the step out is the return and not the next call
    // coming back round to the breakpoint.
    dbg.remove_breakpoint(bp.id).expect("remove the breakpoint");

    let stop = dbg.step(StepKind::Out).expect("out of inner");
    assert!(
        stop.registers.pc > outer && stop.registers.pc < addr_of(&symbols, "main"),
        "expected to land back in `outer`, got {:#x}",
        stop.registers.pc
    );
    dbg.kill().ok();
}

#[test]
fn step_out_of_the_outermost_frame_is_a_step() {
    let Some((dbg, _, _)) = launch(true) else {
        eprintln!("skipping: no launchable fixture");
        return;
    };
    // Stopped at `_start`, where the top of the stack is `argc` and there is no
    // frame to return to. Reading that as a return address is how a step out
    // used to put a `0xCC` through the environment block.
    let before = dbg.registers(None).expect("registers").sp;
    let stop = dbg.step(StepKind::Out).expect("out at _start");
    assert_ne!(stop.registers.pc, 0);
    let after = dbg.registers(None).expect("registers").sp;
    assert!(
        after.abs_diff(before) < 64,
        "a step at the outermost frame should not run, sp {before:#x} -> {after:#x}"
    );
    dbg.kill().ok();
}

#[test]
fn removing_the_breakpoint_we_are_stopped_on_rewinds_the_pc() {
    let Some((dbg, symbols, _)) = launch(true) else {
        eprintln!("skipping: no launchable fixture");
        return;
    };
    let inner = addr_of(&symbols, "inner");
    let bp = dbg
        .add_breakpoint(&BreakAt::Addr { addr: inner })
        .expect("break on inner");
    dbg.resume().expect("run to inner");

    // Deleting the breakpoint puts the original instruction back, but the pc is
    // on the byte after the trap that replaced it — so the next resume runs from
    // the middle of an instruction.
    dbg.remove_breakpoint(bp.id).expect("remove the breakpoint");
    let pc = dbg.registers(None).expect("registers").pc;
    assert_eq!(pc, inner, "the pc belongs back on the restored instruction");

    let stop = dbg.step(StepKind::Into).expect("step off it");
    assert!(
        stop.registers.pc > inner,
        "stepping should execute the restored instruction, got {:#x}",
        stop.registers.pc
    );
    dbg.kill().ok();
}
