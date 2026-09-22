//! The platform boundary: one [`Target`] trait, one implementation per OS.
//!
//! [`crate::session`] is entirely platform-neutral; every OS-specific
//! syscall (ptrace, the Mach task API, the Win32 debug API) lives behind
//! this trait, so `session.rs` never has a `#[cfg(target_os = ...)]` in it.
//!
//! # A note on how this file came to exist
//!
//! `crates/recurse-debug/src/lib.rs` has declared `pub mod target;` since
//! this crate's very first commit, and `crates/recurse-debug/Cargo.toml`
//! already carried per-OS dependencies for exactly this job (`nix` with
//! `ptrace`/`signal`/`process` features for Linux, `libc` for macOS,
//! `windows-sys` with `Win32_System_Diagnostics_Debug` for Windows) — but
//! `git log --all -- crates/recurse-debug/src/target.rs` shows **zero
//! history**: this module was never actually committed. The cause was a
//! `.gitignore` bug, fixed in the same change that adds this file: a bare
//! `target` pattern (intended to ignore the Cargo build directory at the
//! repo root) matches *any* path component named `target` anywhere in the
//! tree, silently excluding `crates/recurse-debug/src/target/` too. The
//! whole crate has been uncompilable since — every module here, including
//! this one, failed with `error[E0583]: file not found for module
//! \`target\`` before this change.
//!
//! # What's implemented here, and what isn't
//!
//! The **Windows backend** ([`windows`]) is real and tested end-to-end in
//! this repository's own sandbox (launch, breakpoint, single-step,
//! register read/write, memory read/write, detach — see
//! `tests/windows_launch.rs`).
//!
//! The **Linux and macOS backends are not reconstructed here.** Their
//! dependencies are still declared in `Cargo.toml` (this change does not
//! touch that), and `ptrace`/ the Mach task API are well-documented, but
//! writing either one blind — with no Linux/macOS sandbox in this session
//! to verify a single line of it against a real process — would be
//! exactly the kind of unverified/untested code this project's own
//! convention refuses to ship. [`native`] returns
//! [`crate::Error::Unsupported`] there instead of a plausible-looking but
//! never-executed implementation. Reconstructing them for real, against a
//! real Linux/macOS target, is separate, scoped follow-up work.

use std::sync::Arc;

use crate::model::{LaunchOptions, Registers, ThreadId};
use crate::session::DebugIo;
use crate::Result;

#[cfg(target_os = "windows")]
mod windows;

/// Why [`Target::wait`]/[`Target::poll`] returned.
#[derive(Clone, Copy, Debug)]
pub enum WaitEvent {
    /// A thread stopped — a breakpoint trap, a completed single-step, a
    /// debugger-requested pause, or any other synchronous stop. `signal`
    /// follows the POSIX convention `crate::session` already classifies
    /// against (`0`/`SIGSTOP` = our own pause, `SIGTRAP` = trap/step,
    /// anything else = a real signal/exception reported as-is) even on a
    /// backend, like Windows, with no real POSIX signals — the backend's
    /// job is to translate its own native stop reason into this same
    /// numbering so `session.rs` stays platform-neutral.
    Stopped { thread: ThreadId, signal: i32 },
    /// The debuggee exited normally.
    Exited { code: i32 },
    /// The debuggee was terminated by a signal (POSIX backends only —
    /// Windows has no equivalent and never emits this).
    Signaled { signal: i32 },
    /// An event the session doesn't need to act on beyond acknowledging
    /// it (e.g. a module load) — should not normally reach a caller of
    /// [`Target::wait`]/[`Target::poll`]; backends resolve these
    /// internally and keep waiting.
    Other,
}

/// One OS's debuggee: launch/attach, registers, memory, and the
/// stop/continue event loop. Implementations own whatever native handles
/// they need (a pid, thread handles, …); [`crate::session::Inner`] only
/// ever sees this trait.
pub trait Target: Send {
    /// Launch `opts` under the debugger. Blocks until the initial stop
    /// (the loader's own breakpoint) and returns the new process id.
    fn launch(&mut self, opts: &LaunchOptions) -> Result<u32>;
    /// Attach to a running `pid`. Blocks until the initial stop.
    fn attach(&mut self, pid: u32) -> Result<()>;
    fn get_regs(&mut self, thread: ThreadId) -> Result<Registers>;
    fn set_regs(&mut self, thread: ThreadId, regs: &Registers) -> Result<()>;
    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>>;
    fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<()>;
    fn threads(&mut self) -> Result<Vec<ThreadId>>;
    fn detach(&mut self) -> Result<()>;
    fn kill(&mut self) -> Result<()>;
    /// Resume `thread` for exactly one instruction, then acknowledge
    /// whatever stop is currently pending. Does not itself wait for the
    /// resulting trap — the caller follows with [`Target::wait`].
    fn step_insn(&mut self, thread: ThreadId, signal: i32) -> Result<()>;
    /// Resume `thread` (and, on backends where continuation is
    /// process-wide rather than per-thread, every other thread) freely,
    /// acknowledging whatever stop is currently pending.
    fn cont(&mut self, thread: ThreadId, signal: i32) -> Result<()>;
    /// Block for the next stop.
    fn wait(&mut self) -> Result<WaitEvent>;
    /// Check for a stop without blocking.
    fn poll(&mut self) -> Result<Option<WaitEvent>>;
    /// Asynchronously request that a running debuggee pause.
    fn interrupt(&mut self) -> Result<()>;
}

/// This platform's `Target` implementation.
///
/// # Errors
/// [`crate::Error::Unsupported`] on a platform with no backend (see the
/// module docs above — currently every OS except Windows).
pub fn native(io: Arc<DebugIo>) -> Result<Box<dyn Target>> {
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsTarget::new(io)))
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = io;
        Err(crate::Error::Unsupported(
            "no target backend for this OS in this build (see crates/recurse-debug/src/target/mod.rs module docs)"
                .to_string(),
        ))
    }
}
