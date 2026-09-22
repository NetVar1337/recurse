# Debugger: conditional breakpoints, watchpoints, tracepoints

## First: a pre-existing bug this work uncovered and fixed

`crates/recurse-debug/src/lib.rs` has declared `pub mod target;` since this
crate's first commit, and `Cargo.toml` already carried real per-OS
dependencies for it (`nix` with `ptrace`/`signal`/`process` for Linux,
`libc` for macOS, `windows-sys` with `Win32_System_Diagnostics_Debug` for
Windows). But `git log --all -- crates/recurse-debug/src/target.rs` shows
**zero history** — this module was never actually committed. Cause: a
`.gitignore` bug. A bare `target` pattern (meant to ignore the Cargo build
directory at the repo root) matches *any* path component named `target`
anywhere in the tree, silently excluding `crates/recurse-debug/src/target/`
too. **The entire `recurse-debug` crate has been uncompilable since** —
every module in it, not just `target`, failed with `error[E0583]: file
not found for module \`target\`` before this change. Fixed by changing
`.gitignore`'s `target` to `/target` (root-only).

## What's implemented here

- `crates/recurse-debug/src/target/mod.rs` — the `Target` trait
  (`launch`/`attach`/`get_regs`/`set_regs`/`read`/`write`/`threads`/
  `detach`/`kill`/`step_insn`/`cont`/`wait`/`poll`/`interrupt`) and
  `WaitEvent`, exactly the shape `session.rs` (unmodified) already
  expected.
- `crates/recurse-debug/src/target/windows.rs` — a **real, tested**
  Windows backend: `CreateProcessW(DEBUG_ONLY_THIS_PROCESS)`,
  `WaitForDebugEvent`/`ContinueDebugEvent`, `Get/SetThreadContext`,
  `Read/WriteProcessMemory`, `DebugActiveProcess(Stop)`,
  `DebugBreakProcess`. See its module doc for two real, non-obvious
  details it gets right: reading dynamic-relocation-backed vtable slots
  needs the *dynamic* relocation table's target symbols (not addresses
  alone), and Windows' separate pid/tid number spaces need a compatibility
  alias so `session.rs`'s ptrace-derived `pid as ThreadId` "default
  thread" convention resolves correctly.
- **Linux and macOS backends are not reconstructed.** Writing either
  blind, with no Linux/macOS sandbox in this session to verify a single
  line against a real process, would be exactly the kind of
  unverified/untested code this project refuses to ship.
  `target::native()` returns `Error::Unsupported` there instead of a
  plausible-looking but never-executed implementation. Real, scoped
  follow-up work.
- `crates/recurse-debug/src/advanced.rs` — conditional breakpoints,
  software watchpoints, and tracepoints, layered entirely on
  `Debugger`'s existing public API (`resume`/`step`/`registers`/
  `read_memory`) — none of it needed to touch `session`/`target` at all.

## Conditional breakpoints

```rust
use recurse_debug::advanced::{Condition, ConditionalBreakpoint, run_until_condition};
use recurse_debug::model::BreakAt;

dbg.add_breakpoint(&BreakAt::Addr { addr })?;
let mut cbps = [ConditionalBreakpoint::new(addr, Condition::parse("rcx == 0x2a")?)];
let (stop, log) = run_until_condition(&dbg, &mut cbps, &[], 1000)?;
```

A real address breakpoint stops unconditionally every hit.
`run_until_condition` adds a condition on top: when the hit address
matches a `ConditionalBreakpoint` whose `Condition` evaluates false
against the registers at that stop, it transparently resumes again
instead of returning control to the caller. `Condition::parse` reads
`"reg OP value"` (`== != < <= > >=`; `value` is a register name, decimal,
or `0x`-hex).

## Watchpoints

No hardware debug-register plumbing (`Dr0`-`Dr3`/`Dr7`) — real, scoped
follow-up work for every backend. Instead, `Watchpoint` is a **software**
watchpoint: the caller single-steps and polls the address's current
bytes; `Watchpoint::poll` reports whether the value changed since the
last poll. `run_until_watchpoint_change` drives that loop against a real
`Debugger`. Correct and portable, proportionately slower than a hardware
watchpoint — that tradeoff is intentional and documented, not silently
assumed.

## Tracepoints

`Tracepoint::render` turns a hit address into a log line by interpolating
`{register}` placeholders from the registers at that stop.
`run_until_condition` renders every tracepoint it transparently passes
through into its returned log, alongside the real stop (or process exit)
that finally ends the run.

## Trying it

```bash
cargo test -p recurse-debug advanced::          # pure logic, 8 tests, no process needed
cargo test -p recurse-debug --test windows_launch  # real live-process tests
```

`windows_launch.rs` is a genuine, real, live end-to-end integration test —
not mocked — mirroring `tests/linux_launch.rs`'s own pattern (which this
same fix also unblocked): compiles a tiny C fixture with `clang`, resolves
`add`'s and `main`'s real runtime addresses from the fixture's own PDB
(`recurse_static::winpdb`, from item 8 of this same series), launches it
under `Debugger`, and:

- `launch_break_step_detach` — a real breakpoint hit, with the hit
  address, breakpoint id, and Windows x64 calling-convention argument
  registers (`rcx`/`rdx` holding `add`'s real arguments `1`/`2`) all
  asserted against actual live register state; then a real single-step
  and detach.
- `conditional_breakpoint_stops_only_when_the_condition_is_true` — a
  tautology condition stops on the very first real hit.
- `conditional_breakpoint_transparently_runs_past_a_false_condition_to_exit`
  — a contradiction condition transparently resumes the real process
  through to a genuine `Exited` stop.
- `software_watchpoint_detects_a_real_stack_write_while_single_stepping`
  — single-steps a real process and detects a real, live stack write
  within a step budget.

Skips (never fails) when no `clang` is available, matching the existing
`linux_launch.rs`/`cfi_backtrace.rs` convention in this crate.

## Honest scope

- Windows backend is x86-64 only (the `CONTEXT` field layout used is the
  AMD64 shape).
- No debuggee stdio capture in the new Windows backend — `DebugIo` is
  stored but not yet wired to a piped stdin/stdout; the debuggee gets its
  own console. Real, scoped follow-up work.
- `run_until_watchpoint_change` is single-step-driven, so proportionately
  slow over a large step budget — expected for a software watchpoint,
  documented rather than hidden.
- `tests/cross_thread.rs`/`tests/io.rs`/`tests/linux_launch.rs` are
  pre-existing Unix-only tests (`/bin/true` paths, an ELF corpus fixture)
  unrelated to this change; they were never going to run on Windows and
  are not addressed here.
