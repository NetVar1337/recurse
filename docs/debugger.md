# Debugger — design and plan

A from-scratch, cross-platform debugger in Rust, in its **own crate**, exposed
to the agent as a tool and wired into the UI. `librecurse` stays what it is — the
agent framework (LLM loop, tool runtime, SQLite memory). All low-level systems
work (ptrace, Mach, the Win32 debug API, register/memory access, unwinding)
lives here.

## Why a separate crate

- **Separation of concerns.** `librecurse` is the agent. The analysis seam
  (`librecurse::engine`) and the debugger are *systems* code; neither belongs in
  the agent crate's dependency graph. A consumer that only wants the agent must
  not pull in `ptrace`/`windows-sys`/`mach2`.
- **Platform code is `unsafe`-heavy.** Isolating it keeps the unsafe surface in
  one audited crate with a small, safe public API (the same posture as
  `librecurse::signals`, but larger).
- **Independent testing.** The debugger is testable against fixture binaries
  without an LLM, an API key, or the UI.

New crate: `crates/recurse-debug/` (package `recurse-debug`, lib
`recurse_debug`). Added to the workspace members; the host (`tauri/src-tauri`)
depends on it. `librecurse` does **not**.

## Goals

- Launch, attach, stop, step, breakpoint, inspect registers/memory/stack, read a
  backtrace, and detach/kill — on Linux, macOS, and Windows.
- Drive it entirely from structured ops (JSON in, JSON out) so the agent tool and
  the UI share one implementation.
- Resolve symbols/addresses through the analysis engine, without depending on it.

## Non-goals (for now)

- No DWARF/source-level stepping (line numbers, variables). We debug at the
  instruction/register level; the analysis engine already gives us function
  names. Source-level is a later layer on top of the same primitives.
- No kernel-mode debugging, no core-dump replay (a separate, smaller feature).
- No reverse-execution, no time-travel.

## Crate layout

```
crates/recurse-debug/
  Cargo.toml
  src/
    lib.rs            public API: Debugger, Session, ops, tool schema
    error.rs          Error type (no panics; Result everywhere)
    model.rs          platform-neutral types: Registers, ThreadId, StopReason,
                      Breakpoint, BreakId, Frame, MemoryRange, ProcessState
    session.rs        the state machine: launch/attach/continue/step/break/…
    event.rs          async event stream (Stop, Exited, Output)
    symbols.rs        `Symbols` trait (host supplies engine-backed impl)
    target/           per-OS backends behind one `Target` trait
      mod.rs          `trait Target` + `fn target() -> Box<dyn Target>`
      linux.rs        ptrace + /proc
      macos.rs        Mach task/thread APIs
      windows.rs      Win32 Debug API
    arch.rs           register sets + breakpoint encodings per arch
    tool.rs           agent tool schema + `execute_tool(&Debugger, op, args)`
  tests/
    fixtures/         a tiny C program + build script (printed in CI)
    launch_break_step.rs
```

## Public API (safe surface)

```rust
/// One debuggee: process + threads + breakpoints. Owns a platform `Target`.
pub struct Debugger { /* … */ }

impl Debugger {
    pub fn new(symbols: Arc<dyn Symbols>) -> Self;
    pub fn launch(&self, opts: LaunchOptions) -> Result<u32>;   // pid
    pub fn attach(&self, pid: u32) -> Result<()>;
    pub fn resume(&self) -> Result<Stop>;
    pub fn step(&self, kind: StepKind) -> Result<Stop>;          // Into/Over/Out
    pub fn pause(&self) -> Result<Stop>;
    pub fn breakpoints(&self) -> Result<Vec<Breakpoint>>;
    pub fn add_breakpoint(&self, at: BreakAt) -> Result<BreakId>; // Addr | Symbol
    pub fn remove_breakpoint(&self, id: BreakId) -> Result<()>;
    pub fn registers(&self, thread: Option<ThreadId>) -> Result<Registers>;
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>>;
    pub fn write_memory(&self, addr: u64, bytes: &[u8]) -> Result<()>;
    pub fn threads(&self) -> Result<Vec<ThreadId>>;
    pub fn backtrace(&self, thread: Option<ThreadId>) -> Result<Vec<Frame>>;
    pub fn status(&self) -> Result<Status>;
    pub fn detach(&self) -> Result<()>;
    pub fn kill(&self) -> Result<()>;
    pub fn subscribe(&self) -> Receiver<Event>;
}
```

`Symbols` keeps the debugger independent of the analysis engine; the host
implements it over `librecurse::engine::Engine`:

```rust
pub trait Symbols: Send + Sync {
    /// Static name for a static (link-time) address.
    fn name_at(&self, addr: u64) -> Option<String>;
    /// Resolve a symbol name to a static address.
    fn resolve(&self, name: &str) -> Option<u64>;
    /// Load bias: runtime_addr - static_addr (ASLR/PIE). 0 if non-PIE.
    fn load_bias(&self, pid: u32) -> Option<u64>;
}
```

## Platform backends

One `trait Target` implemented per OS. The session/state machine is
platform-neutral and talks only to this trait.

```rust
trait Target: Send {
    fn launch(&mut self, opts: &LaunchOptions) -> Result<u32>;
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn wait(&mut self) -> Result<Stop>;             // blocks until a stop
    fn cont(&mut self, thread: ThreadId, how: Continue) -> Result<()>;
    fn get_regs(&self, t: ThreadId) -> Result<Registers>;
    fn set_regs(&mut self, t: ThreadId, r: &Registers) -> Result<()>;
    fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>>;
    fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<()>;
    fn peek_byte(&self, addr: u64) -> Result<u8>;   // for breakpoint insertion
    fn threads(&self) -> Result<Vec<ThreadId>>;
    fn detach(&mut self) -> Result<()>;
    fn kill(&mut self) -> Result<()>;
}
```

| | Linux | macOS | Windows |
|---|---|---|---|
| launch | `fork` + `PTRACE_TRACEME` + `execve` (via `std::process::Command` with `pre_exec`) | `posix_spawn` + `ptrace(PT_ATTACHEXC)` or `task_for_pid` | `CreateProcessW` with `DEBUG_ONLY_THIS_PROCESS` |
| attach | `PTRACE_SEIZE` (fallback `PTRACE_ATTACH`) + `waitpid` | `task_for_pid` + `thread_suspend` | `DebugActiveProcess` |
| wait | `waitpid(WNOHANG\|__WALL)` | `mach_msg` on exception port | `WaitForDebugEvent` |
| continue | `PTRACE_CONT` / `PTRACE_SINGLESTEP` | `thread_resume` / `thread_step` | `ContinueDebugEvent` / trap flag |
| registers | `PTRACE_GETREGSET`/`SETREGSET` (`NT_PRSTATUS`) | `thread_get_state`/`set_state` | `GetThreadContext`/`SetThreadContext` |
| memory | `PTRACE_PEEKDATA`/`POKEDATA`, `process_vm_readv`/`writev` | `mach_vm_read_overwrite`/`mach_vm_write` | `ReadProcessMemory`/`WriteProcessMemory` |
| threads | `/proc/<pid>/task` | `task_threads` | `Thread32First/Next` |
| sw breakpoint | write `0xCC`, remember original | same | same |
| hw breakpoint | `DR0..DR3` + `DR7` | x86 debug registers via `thread_set_state` | `Dr0..Dr3` in `CONTEXT` |

Crates (all permissive): `libc`/`nix` (Unix), `mach2` (macOS), `windows-sys`
(Windows). No copyleft. Everything behind `#[cfg(target_os = …)]`.

### Breakpoints

- **Software**: replace the byte at `addr` with the trap instruction for the arch
  (`0xCC` on x86/x86-64; `BRK #0`/`0xD4200000` on AArch64), remember the original
  byte. On stop, if `pc-1 == bp.addr`, step over the original instruction and
  re-arm the trap before continuing. Software breakpoints need writable memory;
  use **hardware** breakpoints when the page is read-only (common with `r-x`
  code) or when we cannot write.
- **Hardware**: x86 has 4 debug registers (`DR0..DR3`) with `DR7` control. ARM
  has limited (often 2–6) hardware slots. Expose both; report the slot limit.
- **Watchpoints**: `DR7` read/write/execute on x86; `mprotect`-based single-step
  fallback elsewhere (later milestone).

### Stepping

- **Into**: single-step the current thread.
- **Over**: if the current instruction is a `call`, read the return address
  (top of stack / `LR`), set a temporary breakpoint there, continue; otherwise
  single-step.
- **Out**: unwind one frame, temporary breakpoint at the return address,
  continue.

### ASLR / PIE

The analysis engine works in *static* addresses; a running process has a load
bias. The host's `Symbols::load_bias` computes it (Linux: parse
`/proc/<pid>/maps` for the executable's mapping; Windows: module base from
`EnumProcessModules`; macOS: `_dyld_get_image_vmaddr_slide`). The session maps
static→runtime when arming a symbol breakpoint and runtime→static when naming a
frame.

## Agent tool

Mirrors the existing `analyze` tool: one tool, an `op` vocabulary, compact JSON
results, capped output. Defined in `recurse-debug::tool` and appended to the
agent schema **by the host** (exactly how `librecurse::memory` tools are
appended), so `librecurse` never depends on the debugger.

Tool name: `debug`.

| op | args | returns |
|---|---|---|
| `launch` | `path`, `args[]`, `cwd`, `env{}` | `{pid}` |
| `attach` | `pid` | `{pid}` |
| `continue` | — | stop reason |
| `pause` | — | stop reason |
| `step` | `kind` (`into`/`over`/`out`) | stop reason |
| `break` | `addr` (number/hex/symbol), `kind` (`sw`/`hw`), `len`? | `{id, addr}` |
| `unbreak` | `id` | `{}` |
| `breakpoints` | — | list |
| `regs` | `thread`? | named registers + `pc`/`sp`/`fp` |
| `read` | `addr`, `len`, `format`? (`hex`/`u64`/`ascii`) | bytes |
| `write` | `addr`, `bytes` (hex) | `{}` |
| `stack` | `count`? | words from `sp` with symbol hints |
| `backtrace` | `thread`? | frames (addr + function name) |
| `threads` | — | ids + current |
| `status` | — | state, pid, stop reason, breakpoints |
| `detach` | — | `{}` |
| `kill` | — | `{}` |

Capabilities gate what the running platform allows (e.g. `attach: false` when
`ptrace_scope` forbids it, or when lacking the macOS `task_for_pid`
entitlement); the host filters the schema so the model never sees an op it
cannot run — the same pattern as `Engine::capabilities()`.

**System prompt**: add a short paragraph telling the agent it can run the target
under the debugger to confirm behaviour (e.g. "set a breakpoint at the address
that checks the password, then read the register it compares"). This pairs with
the existing "verify, don't guess" framing.

## Host wiring (`tauri/src-tauri`)

- New `AppState` field: `pub debug: Mutex<Option<Arc<Debugger>>>`, built on
  launch/attach and cleared on detach/kill. Mirrors `session`.
- New module `tauri/src-tauri/src/debug.rs`:
  - `SymbolsEngine` — implements `recurse_debug::Symbols` over the live
    `Box<dyn Engine>` (name_at/resolve from `functions()`/`resolve()`,
    `load_bias` from `/proc`/module APIs).
  - Build/teardown helpers.
- Commands (registered in `lib.rs`): `debug_launch`, `debug_attach`,
  `debug_continue`, `debug_pause`, `debug_step`, `debug_break`,
  `debug_unbreak`, `debug_breakpoints`, `debug_regs`, `debug_read`,
  `debug_write`, `debug_stack`, `debug_backtrace`, `debug_threads`,
  `debug_status`, `debug_detach`, `debug_kill`.
- **Event stream**: a Tauri `Channel` (`debug_events`) pushes `Stop`/`Exited`/
  `Output` events, so the UI updates when the debuggee stops even if the stop
  wasn't caused by a UI command. The `Debugger`'s `subscribe()` receiver is
  forwarded to the channel by a small task.
- Agent dispatch (in the `agent_chat` worker's `exec` closure): add
  `name if recurse_debug::is_op(name) => debug.execute_tool(name, &args)` next
  to the existing `is_op`/memory arms. Append `recurse_debug::tool_schema(caps)`
  to `tools` before the run.

## UI wiring (`tauri/src`)

- `types.ts`: `CenterTab` gains `"debug"`; add `DebugStatus`, `DebugRegisters`,
  `DebugFrame`, `DebugBreakpoint`, `DebugEvent`.
- `api.ts`: the `debug_*` invokers + `onDebugEvent` (Channel).
- `store/debugStore.ts`: session state, breakpoints, registers, backtrace,
  threads, a log/console buffer, and actions per command; subscribes to the
  event channel on launch.
- `components/DebugPanel.tsx`: a new **Debug** tab with:
  - a toolbar (Launch…, Attach…, Continue, Pause, Step ▸/↘/↗, Detach, Kill),
  - a status strip (pid, state, stop reason),
  - a registers grid, a stack view, and a backtrace (click a frame → jump to the
    function in the disassembly),
  - a debug console/log.
- `components/CenterPanel.tsx`: register the tab; show it only when the debugger
  capability is present.
- **Breakpoints in the disassembly**: a gutter affordance on each instruction
  row to toggle a breakpoint; the store keeps the set; the row shows a red dot.
  Clicking a backtrace frame selects the function and highlights the line.
- `FunctionList` / disasm: optionally annotate functions with a breakpoint count.

## Milestones

1. **M1 — Linux core (x86-64).** `crates/recurse-debug` scaffold; `Target` trait
   + Linux `ptrace` backend; launch, software breakpoints, `continue`, `step
   into/over/out`, `regs`, `read_mem`. Integration test against a fixture binary.
2. **M2 — Agent tool.** `recurse-debug::tool` schema + `execute_tool`; host
   `SymbolsEngine`, `AppState.debug`, commands, agent dispatch; system-prompt
   note. Headless end-to-end test: launch fixture, break on a symbol, read a
   register, assert.
3. **M3 — UI.** `debugStore` + `DebugPanel` + event channel; registers, stack,
   backtrace, log; breakpoint gutter in the disassembly.
4. **M4 — Depth.** Memory write, threads, hardware breakpoints, ASLR/PIE mapping,
   signal handling, watchpoints.
5. **M5 — macOS + Windows backends.** Mach and Win32 `Target` impls; CI matrix.

## Testing

- **Fixtures**: a tiny C program (`tests/fixtures/target.c`) compiled in the test
  build (a build script invoking `cc`, skipped when no compiler). It has a known
  function (`check_password`) we can break on and inspect.
- **Unit**: arch breakpoint encoding, register get/set round-trip, step-over
  return-address logic (pure functions, no process).
- **Integration** (`#[ignore]` on CI where ptrace is restricted): launch fixture,
  break at a symbol, assert `pc` matches, step, read memory, detach.
- **`ptrace_scope`**: tests detect `kernel.yama.ptrace_scope` and skip attach
  when it forbids it, reporting the reason (never a flaky failure).

## Security & safety

- Debugging runs the target **locally with the user's privileges** — no
  elevation. Document the malware caveat: run untrusted samples in a VM/container.
- Linux: respect `ptrace_scope`; surface a clear error and remediation
  (`sudo sysctl kernel.yama.ptrace_scope=0`) rather than failing obscurely.
- macOS: `task_for_pid` needs the `com.apple.security.get-task-allow`
  entitlement (dev-signed builds have it); report when it is missing.
- The debugger never writes outside the debuggee's address space, and every
  `unsafe` block is confined to `target/` with a `// SAFETY:` note.

## Risks / open questions

- **macOS attach** is the hardest (entitlements, SIP, `task_for_pid`). If it
  proves impractical, ship launch-only on macOS and document it.
- **Hardware breakpoint limits** (4 on x86, fewer on ARM) — need a policy for
  running out (refuse and explain, vs. silently downgrade).
- **Async model**: one blocking wait thread per session with a command channel
  (simple, correct) vs. an event-loop future. Start with the thread.
- **Symbol timing**: symbols come from the engine, which may still be indexing;
  breakpoints by symbol should fall back to "address not resolved yet" cleanly.

## Definition of done (M1–M3)

- `recurse-debug` builds and tests on Linux without the UI or an LLM.
- The agent can, in one session: launch a target, break on `check_password`,
  continue to the hit, read `rdi`/`rax`, step, read the stack, backtrace, and
  detach — through the `debug` tool, with compact JSON.
- The UI has a Debug tab doing the same interactively, with breakpoints shown in
  the disassembly and a backtrace that navigates to functions.
