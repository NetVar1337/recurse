//! The debug session: a platform-neutral state machine over a [`Target`].
//!
//! Owns the debuggee, its breakpoints, and the stop state. All software
//! breakpoint bookkeeping (trap bytes, step-over, temporary breakpoints for
//! step-over/out) lives here, so the OS backends stay thin.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::arch;
use crate::error::{Error, Result};
use crate::model::{
    BreakAt, Breakpoint, Frame, LaunchOptions, ProcessState, Registers, Status, StepKind, Stop,
    StopReason, ThreadId,
};
use crate::symbols::{NoSymbols, Symbols};
use crate::target::{self, Target, WaitEvent};

/// `SIGTRAP` — the stop signal for traps (breakpoints and single-steps).
const SIGTRAP: i32 = 5;

/// Maximum frames walked by [`Debugger::backtrace`].
const MAX_FRAMES: usize = 64;

/// A debug session: one debuggee, its breakpoints, and its state.
///
/// Methods take `&self` and serialise on an internal mutex, mirroring the
/// analysis [`Engine`](https://docs.rs/librecurse) so the agent tool and the UI
/// share one handle.
pub struct Debugger {
    inner: Mutex<Inner>,
    symbols: Arc<dyn Symbols>,
}

struct Inner {
    target: Box<dyn Target>,
    pid: Option<u32>,
    state: ProcessState,
    last_stop: Option<StopReason>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    next_id: u64,
    /// `runtime - static` address (ASLR/PIE load bias).
    bias: u64,
    /// Set while a single-step is outstanding, so a `SIGTRAP` reads as a step.
    stepping: bool,
    /// Address of a breakpoint we are stopped on (pc already past the trap).
    stopped_at_bp: Option<u64>,
}

impl Debugger {
    /// A debugger with no symbol source.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] on a platform with no backend.
    pub fn new() -> Result<Self> {
        Self::with_symbols(Arc::new(NoSymbols))
    }

    /// A debugger that resolves names/addresses through `symbols`.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] on a platform with no backend.
    pub fn with_symbols(symbols: Arc<dyn Symbols>) -> Result<Self> {
        Ok(Self {
            inner: Mutex::new(Inner {
                target: target::native()?,
                pid: None,
                state: ProcessState::Idle,
                last_stop: None,
                breakpoints: BTreeMap::new(),
                next_id: 1,
                bias: 0,
                stepping: false,
                stopped_at_bp: None,
            }),
            symbols,
        })
    }

    /// The load bias of the current debuggee (0 when unknown).
    pub fn load_bias(&self) -> Result<u64> {
        Ok(self.lock()?.bias)
    }

    /// Launch `opts` under the debugger; returns the initial (exec) stop.
    ///
    /// # Errors
    /// Returns the OS error when the process cannot be spawned or traced.
    pub fn launch(&self, opts: &LaunchOptions) -> Result<Stop> {
        let mut inner = self.lock()?;
        let pid = inner.target.launch(opts)?;
        inner.pid = Some(pid);
        inner.bias = self.symbols.load_bias(pid).unwrap_or(0);
        inner.state = ProcessState::Stopped;
        inner.last_stop = Some(StopReason::Started);
        let thread = pid as ThreadId;
        let registers = inner.target.get_regs(thread)?;
        Ok(Stop {
            pid,
            thread,
            reason: StopReason::Started,
            registers,
        })
    }

    /// Attach to a running `pid`; returns the initial stop.
    ///
    /// # Errors
    /// Returns the OS error when the process cannot be attached (e.g. a
    /// restrictive `ptrace_scope`).
    pub fn attach(&self, pid: u32) -> Result<Stop> {
        let mut inner = self.lock()?;
        inner.target.attach(pid)?;
        inner.pid = Some(pid);
        inner.bias = self.symbols.load_bias(pid).unwrap_or(0);
        inner.state = ProcessState::Stopped;
        inner.last_stop = Some(StopReason::Started);
        let thread = pid as ThreadId;
        let registers = inner.target.get_regs(thread)?;
        Ok(Stop {
            pid,
            thread,
            reason: StopReason::Started,
            registers,
        })
    }

    /// Install a breakpoint. Symbol targets are resolved through
    /// [`Symbols`] and biased by the load address.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error when the trap
    /// byte cannot be written (e.g. a read-only page).
    pub fn add_breakpoint(&self, at: &BreakAt) -> Result<Breakpoint> {
        let mut inner = self.lock()?;
        inner.pid()?;
        let addr = inner.resolve(self.symbols.as_ref(), at)?;
        let trap = arch::breakpoint_bytes();
        let original = inner.target.read(addr, trap.len())?;
        inner.target.write(addr, trap)?;
        let id = inner.next_id;
        inner.next_id += 1;
        let bp = Breakpoint {
            id,
            addr,
            enabled: true,
            original,
        };
        inner.breakpoints.insert(id, bp.clone());
        Ok(bp)
    }

    /// Remove a breakpoint by id, restoring the original bytes.
    ///
    /// # Errors
    /// [`Error::NoSuchBreakpoint`] when `id` is unknown.
    pub fn remove_breakpoint(&self, id: u64) -> Result<()> {
        let mut inner = self.lock()?;
        let bp = inner
            .breakpoints
            .remove(&id)
            .ok_or(Error::NoSuchBreakpoint(id))?;
        if bp.enabled {
            inner.target.write(bp.addr, &bp.original)?;
        }
        if inner.stopped_at_bp == Some(bp.addr) {
            inner.stopped_at_bp = None;
        }
        Ok(())
    }

    /// All installed breakpoints.
    pub fn breakpoints(&self) -> Result<Vec<Breakpoint>> {
        Ok(self.lock()?.breakpoints.values().cloned().collect())
    }

    /// Resume until the next breakpoint, signal, or exit.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error from resuming.
    pub fn resume(&self) -> Result<Stop> {
        let mut inner = self.lock()?;
        let thread = inner.thread()?;
        let lifted = inner.lift_breakpoint(thread)?;
        if lifted.is_some() {
            // Run the breakpointed instruction, then re-arm the trap.
            inner.stepping = true;
            inner.target.step_insn(thread, 0)?;
            inner.wait_stop()?;
            inner.rearm(&lifted)?;
        }
        inner.state = ProcessState::Running;
        inner.target.cont(thread, 0)?;
        inner.wait_stop()
    }

    /// Step one instruction (into), over a call, or out of the function.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error from stepping.
    pub fn step(&self, kind: StepKind) -> Result<Stop> {
        let mut inner = self.lock()?;
        let thread = inner.thread()?;
        let lifted = inner.lift_breakpoint(thread)?;
        let result = match kind {
            StepKind::Into => inner.single_step(thread),
            StepKind::Over | StepKind::Out => {
                let regs = inner.target.get_regs(thread)?;
                let bytes = inner.target.read(regs.pc, 16).unwrap_or_default();
                // A call is run to completion; anything else is a plain step.
                // `Out` always runs to the return address.
                if kind == StepKind::Out || arch::is_call(&bytes) {
                    let ret = inner.read_word(regs.sp)?;
                    inner.run_to(thread, ret)
                } else {
                    inner.single_step(thread)
                }
            }
        };
        inner.rearm(&lifted)?;
        result
    }

    /// Registers of `thread`, or of the main thread when `None`.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error.
    pub fn registers(&self, thread: Option<ThreadId>) -> Result<Registers> {
        let mut inner = self.lock()?;
        let t = thread.unwrap_or(inner.thread()?);
        inner.target.get_regs(t)
    }

    /// Read `len` bytes of the debuggee's memory at `addr`.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error when the range
    /// is unmapped.
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut inner = self.lock()?;
        inner.pid()?;
        inner.target.read(addr, len)
    }

    /// Write `bytes` into the debuggee's memory at `addr`.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error when the range
    /// is not writable.
    pub fn write_memory(&self, addr: u64, bytes: &[u8]) -> Result<()> {
        let mut inner = self.lock()?;
        inner.pid()?;
        inner.target.write(addr, bytes)
    }

    /// The debuggee's threads.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee.
    pub fn threads(&self) -> Result<Vec<ThreadId>> {
        let mut inner = self.lock()?;
        inner.pid()?;
        inner.target.threads()
    }

    /// Walk the frame-pointer chain into a backtrace.
    ///
    /// Best effort: without unwind tables this follows `rbp`/`fp` links, which
    /// is correct for frame-pointer builds and stops cleanly otherwise.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee.
    pub fn backtrace(&self, thread: Option<ThreadId>) -> Result<Vec<Frame>> {
        let mut inner = self.lock()?;
        let t = thread.unwrap_or(inner.thread()?);
        let regs = inner.target.get_regs(t)?;
        let bias = inner.bias;
        let name = |addr: u64| self.symbols.name_at(addr.wrapping_sub(bias));
        let mut frames = vec![Frame {
            addr: regs.pc,
            name: name(regs.pc),
        }];
        let mut fp = regs.fp;
        for _ in 0..MAX_FRAMES {
            if fp == 0 {
                break;
            }
            let ret = inner.read_word(fp.wrapping_add(8))?;
            let next = inner.read_word(fp)?;
            if ret == 0 {
                break;
            }
            frames.push(Frame {
                addr: ret,
                name: name(ret),
            });
            if next <= fp {
                break;
            }
            fp = next;
        }
        Ok(frames)
    }

    /// A snapshot of the session.
    ///
    /// # Errors
    /// Only if the internal lock is poisoned.
    pub fn status(&self) -> Result<Status> {
        let inner = self.lock()?;
        Ok(Status {
            pid: inner.pid,
            state: inner.state,
            stop: inner.last_stop.clone(),
            breakpoints: inner.breakpoints.values().cloned().collect(),
        })
    }

    /// Detach, leaving the process running.
    ///
    /// # Errors
    /// The OS error from detaching.
    pub fn detach(&self) -> Result<()> {
        let mut inner = self.lock()?;
        if inner.pid.is_some() {
            inner.target.detach()?;
        }
        inner.pid = None;
        inner.state = ProcessState::Exited;
        inner.breakpoints.clear();
        inner.stopped_at_bp = None;
        Ok(())
    }

    /// Kill the process.
    ///
    /// # Errors
    /// The OS error from killing.
    pub fn kill(&self) -> Result<()> {
        let mut inner = self.lock()?;
        if inner.pid.is_some() {
            inner.target.kill()?;
        }
        inner.pid = None;
        inner.state = ProcessState::Exited;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|e| Error::msg(format!("debugger lock poisoned: {e}")))
    }
}

impl Inner {
    /// The debuggee pid, or [`Error::NotRunning`].
    fn pid(&self) -> Result<u32> {
        self.pid.ok_or(Error::NotRunning)
    }

    /// The main thread id (the pid on Linux).
    fn thread(&self) -> Result<ThreadId> {
        Ok(self.pid()? as ThreadId)
    }

    /// Resolve a [`BreakAt`] to a runtime address.
    fn resolve(&self, symbols: &dyn Symbols, at: &BreakAt) -> Result<u64> {
        match at {
            BreakAt::Addr { addr } => Ok(*addr),
            BreakAt::Symbol { name } => symbols
                .resolve(name)
                .map(|static_addr| static_addr.wrapping_add(self.bias))
                .ok_or_else(|| Error::msg(format!("unknown symbol `{name}`"))),
        }
    }

    /// Block for the next stop and shape it into a [`Stop`].
    fn wait_stop(&mut self) -> Result<Stop> {
        match self.target.wait()? {
            WaitEvent::Stopped { thread, signal } => {
                let mut registers = self.target.get_regs(thread)?;
                let reason = self.classify(signal, &registers);
                // Report the breakpoint address, not the byte past the trap,
                // the way a debugger shows the current line.
                if let StopReason::Breakpoint { addr, .. } = &reason {
                    registers.pc = *addr;
                }
                self.state = ProcessState::Stopped;
                self.last_stop = Some(reason.clone());
                Ok(Stop {
                    pid: self.pid.unwrap_or(0),
                    thread,
                    reason,
                    registers,
                })
            }
            WaitEvent::Exited { code } => {
                self.pid = None;
                self.state = ProcessState::Exited;
                let reason = StopReason::Exited { code };
                self.last_stop = Some(reason.clone());
                Ok(terminal_stop(reason))
            }
            WaitEvent::Signaled { signal } => {
                self.pid = None;
                self.state = ProcessState::Exited;
                let reason = StopReason::Killed { signal };
                self.last_stop = Some(reason.clone());
                Ok(terminal_stop(reason))
            }
            WaitEvent::Other => {
                let reason = StopReason::Signal {
                    signal: 0,
                    name: "event".to_string(),
                };
                self.last_stop = Some(reason.clone());
                Ok(Stop {
                    pid: self.pid.unwrap_or(0),
                    thread: 0,
                    reason,
                    registers: Registers::default(),
                })
            }
        }
    }

    /// Turn a stop signal + registers into a [`StopReason`], tracking a hit
    /// breakpoint or an outstanding single-step.
    fn classify(&mut self, signal: i32, regs: &Registers) -> StopReason {
        if signal == SIGTRAP {
            let hit = arch::breakpoint_hit_addr(regs.pc);
            if let Some(bp) = self
                .breakpoints
                .values()
                .find(|b| b.enabled && b.addr == hit)
                .cloned()
            {
                self.stopped_at_bp = Some(bp.addr);
                self.stepping = false;
                return StopReason::Breakpoint {
                    addr: bp.addr,
                    id: bp.id,
                };
            }
            if self.stepping {
                self.stepping = false;
                self.stopped_at_bp = None;
                return StopReason::Step;
            }
        }
        self.stopped_at_bp = None;
        self.stepping = false;
        StopReason::Signal {
            signal,
            name: signal_name(signal),
        }
    }

    /// Single-step `thread` and wait, marking the trap as a step.
    fn single_step(&mut self, thread: ThreadId) -> Result<Stop> {
        self.stepping = true;
        self.state = ProcessState::Running;
        self.target.step_insn(thread, 0)?;
        self.wait_stop()
    }

    /// Run until `addr` by way of a temporary breakpoint, then remove it and
    /// rewind the pc so the instruction there executes next.
    fn run_to(&mut self, thread: ThreadId, addr: u64) -> Result<Stop> {
        let trap = arch::breakpoint_bytes();
        let original = self.target.read(addr, trap.len())?;
        self.target.write(addr, trap)?;
        self.stepping = true;
        self.state = ProcessState::Running;
        self.target.cont(thread, 0)?;
        let stop = self.wait_stop()?;
        // The temp trap may have been removed by an exit; only restore if we
        // are still stopped at it.
        if self.pid.is_some() {
            self.target.write(addr, &original)?;
            let mut regs = self.target.get_regs(thread)?;
            if arch::breakpoint_hit_addr(regs.pc) == addr {
                regs.pc = addr;
                self.target.set_regs(thread, &regs)?;
            }
        }
        Ok(stop)
    }

    /// If stopped on a breakpoint, disable it, restore its original bytes, and
    /// rewind the pc so the breakpointed instruction is next. Returns
    /// `(id, address, original bytes)` so the caller can re-arm it.
    ///
    /// The breakpoint is marked disabled while lifted, so the single-step that
    /// runs its instruction is not mistaken for a fresh hit.
    fn lift_breakpoint(&mut self, thread: ThreadId) -> Result<Option<(u64, u64, Vec<u8>)>> {
        let Some(addr) = self.stopped_at_bp.take() else {
            return Ok(None);
        };
        let Some(id) = self
            .breakpoints
            .values()
            .find(|b| b.addr == addr)
            .map(|b| b.id)
        else {
            return Ok(None);
        };
        let Some(original) = self.breakpoints.get(&id).map(|b| b.original.clone()) else {
            return Ok(None);
        };
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.enabled = false;
        }
        self.target.write(addr, &original)?;
        let mut regs = self.target.get_regs(thread)?;
        regs.pc = addr;
        self.target.set_regs(thread, &regs)?;
        Ok(Some((id, addr, original)))
    }

    /// Re-enable a lifted breakpoint and re-install its trap byte.
    fn rearm(&mut self, lifted: &Option<(u64, u64, Vec<u8>)>) -> Result<()> {
        if let Some((id, addr, _)) = lifted {
            if let Some(bp) = self.breakpoints.get_mut(id) {
                bp.enabled = true;
            }
            self.target.write(*addr, arch::breakpoint_bytes())?;
        }
        Ok(())
    }

    /// Read a native-endian word from the debuggee.
    fn read_word(&mut self, addr: u64) -> Result<u64> {
        let bytes = self.target.read(addr, 8)?;
        let arr: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::msg("short memory read"))?;
        Ok(u64::from_ne_bytes(arr))
    }
}

/// A [`Stop`] for a process that has ended (no thread/registers).
fn terminal_stop(reason: StopReason) -> Stop {
    Stop {
        pid: 0,
        thread: 0,
        reason,
        registers: Registers::default(),
    }
}

/// Conventional name for a signal number.
fn signal_name(signal: i32) -> String {
    let name = match signal {
        0 => "none",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        _ => return format!("signal {signal}"),
    };
    name.to_string()
}
