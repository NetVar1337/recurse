//! The platform boundary: one [`Target`] trait, one implementation per OS.
//!
//! [`crate::session`] is entirely platform-neutral; every OS-specific
//! syscall (ptrace, the Mach task API, the Win32 debug API) lives behind
//! this trait, so `session.rs` never has a `#[cfg(target_os = ...)]` in it.
//!
//! # Backends
//!
//! * **Linux** ([`linux`]) — `ptrace` + `waitpid` + `/proc`.
//! * **Windows** ([`windows`]) — the Win32 debug API.
//! * **macOS** — not implemented yet; [`native`] returns
//!   [`crate::Error::Unsupported`] there rather than shipping an unverified
//!   Mach backend.

use std::sync::Arc;

use crate::model::{LaunchOptions, Registers, ThreadId};
use crate::session::DebugIo;
use crate::Result;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;

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
/// [`crate::Error::Unsupported`] on a platform with no backend (Linux and
/// Windows have one; macOS does not yet).
pub fn native(io: Arc<DebugIo>) -> Result<Box<dyn Target>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxTarget::new(io)))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::WindowsTarget::new(io)))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = io;
        Err(crate::Error::Unsupported(
            "no target backend for this OS in this build (see crates/recurse-debug/src/target/mod.rs module docs)"
                .to_string(),
        ))
    }
}
