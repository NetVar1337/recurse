//! The debug session: a platform-neutral state machine over a [`Target`].
//!
//! Owns the debuggee, its breakpoints, and the stop state. All software
//! breakpoint bookkeeping (trap bytes, step-over, temporary breakpoints for
//! step-over/out) lives here, so the OS backends stay thin.
//!
//! ## Why a worker thread
//!
//! On Linux (and Windows) the *tracer* is the exact thread that forked or
//! attached the debuggee, not the process — a different thread calling `ptrace`
//! on the same tracee gets `ESRCH`. Since the host runs commands on arbitrary
//! pool threads, the session owns one dedicated thread that performs every
//! target operation. [`Debugger`] is a handle that forwards commands to it, so
//! the UI and the agent can call it from any thread.

use std::collections::BTreeMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde::Serialize;

use crate::arch;
use crate::error::{Error, Result};
use crate::model::{
    BreakAt, Breakpoint, Frame, Insn, LaunchOptions, ProcessState, Registers, Status, StepKind,
    Stop, StopReason, ThreadId,
};
use crate::symbols::{NoSymbols, Symbols};
use crate::target::{self, Target, WaitEvent};
use recurse_static::arch::Arch;

/// `SIGTRAP` — the stop signal for traps (breakpoints and single-steps).
const SIGTRAP: i32 = 5;

/// Maximum frames walked by [`Debugger::backtrace`].
const MAX_FRAMES: usize = 64;

/// A reply channel for one command.
type Reply<T> = Sender<Result<T>>;

/// Cap on captured output, so a chatty debuggee cannot grow the buffer without
/// bound. Older bytes are dropped first.
const MAX_OUTPUT: usize = 1 << 20;

/// Shared debuggee stdio.
///
/// This is deliberately *outside* the worker thread: the analyst must be able
/// to type at the debuggee's prompts while a `continue` is blocked waiting for
/// a stop, so writing stdin and draining output never queue behind it.
pub struct DebugIo {
    stdin: Mutex<Option<Box<dyn std::io::Write + Send>>>,
    output: Mutex<Vec<u8>>,
}

impl DebugIo {
    /// An empty io pair.
    pub fn new() -> Self {
        Self {
            stdin: Mutex::new(None),
            output: Mutex::new(Vec::new()),
        }
    }

    /// Install the stdin sink. Called by the backend at launch.
    pub fn set_stdin(&self, sink: Box<dyn std::io::Write + Send>) {
        if let Ok(mut s) = self.stdin.lock() {
            *s = Some(sink);
        }
    }

    /// Append captured stdout/stderr. Called by the backend's reader threads.
    pub fn push_output(&self, bytes: &[u8]) {
        if let Ok(mut v) = self.output.lock() {
            v.extend_from_slice(bytes);
            if v.len() > MAX_OUTPUT {
                let drop = v.len() - MAX_OUTPUT;
                v.drain(..drop);
            }
        }
    }

    /// Write `bytes` to the debuggee's stdin.
    ///
    /// # Errors
    /// A message when stdin is not piped (e.g. after an attach).
    pub fn write_stdin(&self, bytes: &[u8]) -> Result<()> {
        let mut guard = self
            .stdin
            .lock()
            .map_err(|_| Error::msg("stdin lock poisoned"))?;
        let sink = guard
            .as_mut()
            .ok_or_else(|| Error::msg("stdin is not piped (was the target attached?)"))?;
        sink.write_all(bytes)?;
        sink.flush()?;
        Ok(())
    }

    /// Drain captured output since the last call.
    pub fn take_output(&self) -> Vec<u8> {
        self.output
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    }
}

impl Default for DebugIo {
    fn default() -> Self {
        Self::new()
    }
}

/// A live, lock-cheap view of the session.
///
/// Written by the worker thread after each operation and read directly by the
/// UI (never through the worker), so the UI can *follow along* — even while a
/// `continue` is still blocked waiting for a stop. This is what makes an
/// agent-driven debug session visible in real time.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    /// Debuggee pid, if any.
    pub pid: Option<u32>,
    /// Lifecycle state.
    pub state: ProcessState,
    /// The last stop (with registers), if any.
    pub stop: Option<Stop>,
    /// Installed breakpoints.
    pub breakpoints: Vec<Breakpoint>,
    /// Backtrace at the last stop.
    pub frames: Vec<Frame>,
    /// `runtime - static` address (ASLR/PIE load bias), so the UI can map a
    /// runtime PC to a disassembly (static) address and back.
    pub bias: u64,
}

/// A debug session handle. Cheap to clone-share behind an `Arc`.
pub struct Debugger {
    tx: Option<Sender<Command>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    io: Arc<DebugIo>,
    snapshot: Arc<Mutex<Snapshot>>,
}

/// One operation for the worker thread.
enum Command {
    /// Launch a new debuggee.
    Launch(LaunchOptions, Reply<Stop>),
    /// Attach to a running process.
    Attach(u32, Reply<Stop>),
    /// Resume.
    Resume(Reply<Stop>),
    /// Step.
    Step(StepKind, Reply<Stop>),
    /// Install a breakpoint.
    AddBreakpoint(BreakAt, Reply<Breakpoint>),
    /// Remove a breakpoint.
    RemoveBreakpoint(u64, Reply<()>),
    /// List breakpoints.
    Breakpoints(Reply<Vec<Breakpoint>>),
    /// Read registers.
    Registers(Option<ThreadId>, Reply<Registers>),
    /// Write one register.
    SetRegister(String, u64, Reply<Registers>),
    /// Read memory.
    ReadMemory(u64, usize, Reply<Vec<u8>>),
    /// Write memory.
    WriteMemory(u64, Vec<u8>, Reply<()>),
    /// List threads.
    Threads(Reply<Vec<ThreadId>>),
    /// Walk the backtrace.
    Backtrace(Option<ThreadId>, Reply<Vec<Frame>>),
    /// Disassemble live memory.
    Disasm(u64, usize, Reply<Vec<Insn>>),
    /// Snapshot the session.
    Status(Reply<Status>),
    /// Load bias.
    LoadBias(Reply<u64>),
    /// Detach.
    Detach(Reply<()>),
    /// Kill.
    Kill(Reply<()>),
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
        let io = Arc::new(DebugIo::new());
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let inner = Inner::new(symbols, io.clone(), snapshot.clone())?;
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("recurse-debug".to_string())
            .spawn(move || run_worker(inner, rx))
            .map_err(Error::Io)?;
        Ok(Self {
            tx: Some(tx),
            worker: Mutex::new(Some(worker)),
            io,
            snapshot,
        })
    }

    /// A live snapshot of the session, read without touching the worker thread.
    ///
    /// Safe to call while a `continue` is blocked, so a UI can follow an
    /// agent-driven session in real time.
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// The load bias of the current debuggee (0 when unknown).
    ///
    /// # Errors
    /// A message when the worker thread is gone.
    pub fn load_bias(&self) -> Result<u64> {
        self.call(Command::LoadBias)
    }

    /// Launch `opts` under the debugger; returns the initial (exec) stop.
    ///
    /// # Errors
    /// The OS error when the process cannot be spawned or traced.
    pub fn launch(&self, opts: &LaunchOptions) -> Result<Stop> {
        let opts = opts.clone();
        self.call(move |tx| Command::Launch(opts, tx))
    }

    /// Attach to a running `pid`; returns the initial stop.
    ///
    /// # Errors
    /// The OS error when the process cannot be attached (e.g. a restrictive
    /// `ptrace_scope`).
    pub fn attach(&self, pid: u32) -> Result<Stop> {
        self.call(move |tx| Command::Attach(pid, tx))
    }

    /// Install a breakpoint.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error when the trap
    /// byte cannot be written.
    pub fn add_breakpoint(&self, at: &BreakAt) -> Result<Breakpoint> {
        let at = at.clone();
        self.call(move |tx| Command::AddBreakpoint(at, tx))
    }

    /// Remove a breakpoint by id.
    ///
    /// # Errors
    /// [`Error::NoSuchBreakpoint`] when `id` is unknown.
    pub fn remove_breakpoint(&self, id: u64) -> Result<()> {
        self.call(move |tx| Command::RemoveBreakpoint(id, tx))
    }

    /// All installed breakpoints.
    ///
    /// # Errors
    /// A message when the worker thread is gone.
    pub fn breakpoints(&self) -> Result<Vec<Breakpoint>> {
        self.call(Command::Breakpoints)
    }

    /// Resume until the next breakpoint, signal, or exit.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee.
    pub fn resume(&self) -> Result<Stop> {
        self.call(Command::Resume)
    }

    /// Step one instruction (into), over a call, or out of the function.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee.
    pub fn step(&self, kind: StepKind) -> Result<Stop> {
        self.call(move |tx| Command::Step(kind, tx))
    }

    /// Registers of `thread`, or of the main thread when `None`.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee.
    pub fn registers(&self, thread: Option<ThreadId>) -> Result<Registers> {
        self.call(move |tx| Command::Registers(thread, tx))
    }

    /// Set register `name` to `value`, returning the updated registers.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error.
    pub fn set_register(&self, name: &str, value: u64) -> Result<Registers> {
        let name = name.to_string();
        self.call(move |tx| Command::SetRegister(name, value, tx))
    }

    /// Read `len` bytes of the debuggee's memory at `addr`.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error when the range
    /// is unmapped.
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        self.call(move |tx| Command::ReadMemory(addr, len, tx))
    }

    /// Write `bytes` into the debuggee's memory at `addr`.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or the OS error when the range
    /// is not writable.
    pub fn write_memory(&self, addr: u64, bytes: &[u8]) -> Result<()> {
        let bytes = bytes.to_vec();
        self.call(move |tx| Command::WriteMemory(addr, bytes, tx))
    }

    /// The debuggee's threads.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee.
    pub fn threads(&self) -> Result<Vec<ThreadId>> {
        self.call(Command::Threads)
    }

    /// Walk the frame-pointer chain into a backtrace.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee.
    pub fn backtrace(&self, thread: Option<ThreadId>) -> Result<Vec<Frame>> {
        self.call(move |tx| Command::Backtrace(thread, tx))
    }

    /// A snapshot of the session.
    ///
    /// # Errors
    /// A message when the worker thread is gone.
    pub fn status(&self) -> Result<Status> {
        self.call(Command::Status)
    }

    /// Detach, leaving the process running.
    ///
    /// # Errors
    /// The OS error from detaching.
    pub fn detach(&self) -> Result<()> {
        self.call(Command::Detach)
    }

    /// Kill the process.
    ///
    /// # Errors
    /// The OS error from killing.
    pub fn kill(&self) -> Result<()> {
        self.call(Command::Kill)
    }

    /// Write `bytes` to the debuggee's stdin. Works even while the debuggee is
    /// running (it does not go through the worker thread).
    ///
    /// # Errors
    /// A message when stdin is not piped.
    pub fn write_stdin(&self, bytes: &[u8]) -> Result<()> {
        self.io.write_stdin(bytes)
    }

    /// Drain the debuggee's captured stdout/stderr.
    pub fn output(&self) -> Vec<u8> {
        self.io.take_output()
    }

    /// Disassemble `count` instructions at runtime address `addr`, reading the
    /// bytes from the debuggee's live memory. Works at any address — the
    /// loader, a JIT page, or the main binary — because it decodes what is
    /// actually mapped.
    ///
    /// # Errors
    /// [`Error::NotRunning`] with no debuggee, or when the architecture is
    /// unknown.
    pub fn disasm(&self, addr: u64, count: usize) -> Result<Vec<Insn>> {
        self.call(move |tx| Command::Disasm(addr, count, tx))
    }

    /// Send one command and block for its reply.
    fn call<T>(&self, build: impl FnOnce(Reply<T>) -> Command) -> Result<T> {
        let (tx, rx) = mpsc::channel();
        let sender = self
            .tx
            .as_ref()
            .ok_or_else(|| Error::msg("debugger thread is gone"))?;
        sender
            .send(build(tx))
            .map_err(|_| Error::msg("debugger thread is gone"))?;
        rx.recv()
            .map_err(|_| Error::msg("debugger thread is gone"))?
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        // Drop the sender first: the worker's `recv` only returns once every
        // sender is gone, so joining before this would deadlock. The worker
        // then exits, and `PTRACE_O_EXITKILL` reaps any running debuggee.
        self.tx.take();
        let worker = self.worker.lock().ok().and_then(|mut w| w.take());
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }
}

/// The worker loop: owns the target and executes commands serially.
fn run_worker(mut inner: Inner, rx: Receiver<Command>) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Command::Launch(opts, tx) => {
                let _ = tx.send(inner.launch(&opts));
            }
            Command::Attach(pid, tx) => {
                let _ = tx.send(inner.attach(pid));
            }
            Command::Resume(tx) => {
                let _ = tx.send(inner.resume());
            }
            Command::Step(kind, tx) => {
                let _ = tx.send(inner.step(kind));
            }
            Command::AddBreakpoint(at, tx) => {
                let _ = tx.send(inner.add_breakpoint(&at));
            }
            Command::RemoveBreakpoint(id, tx) => {
                let _ = tx.send(inner.remove_breakpoint(id));
            }
            Command::Breakpoints(tx) => {
                let _ = tx.send(Ok(inner.breakpoints()));
            }
            Command::Registers(thread, tx) => {
                let _ = tx.send(inner.registers(thread));
            }
            Command::SetRegister(name, value, tx) => {
                let _ = tx.send(inner.set_register(&name, value));
            }
            Command::ReadMemory(addr, len, tx) => {
                let _ = tx.send(inner.read_memory(addr, len));
            }
            Command::WriteMemory(addr, bytes, tx) => {
                let _ = tx.send(inner.write_memory(addr, &bytes));
            }
            Command::Threads(tx) => {
                let _ = tx.send(inner.threads());
            }
            Command::Backtrace(thread, tx) => {
                let _ = tx.send(inner.backtrace(thread));
            }
            Command::Disasm(addr, count, tx) => {
                let _ = tx.send(inner.disasm(addr, count));
            }
            Command::Status(tx) => {
                let _ = tx.send(Ok(inner.status()));
            }
            Command::LoadBias(tx) => {
                let _ = tx.send(Ok(inner.bias));
            }
            Command::Detach(tx) => {
                let _ = tx.send(inner.detach());
            }
            Command::Kill(tx) => {
                let _ = tx.send(inner.kill());
            }
        }
        // Publish the new state so a UI following along updates live.
        inner.publish();
    }
}

/// The mutable session state, owned by the worker thread.
struct Inner {
    target: Box<dyn Target>,
    symbols: Arc<dyn Symbols>,
    pid: Option<u32>,
    state: ProcessState,
    last_stop: Option<StopReason>,
    /// The last full stop (registers included), for the published snapshot.
    last_full: Option<Stop>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    next_id: u64,
    /// `runtime - static` address (ASLR/PIE load bias).
    bias: u64,
    /// Set while a single-step is outstanding, so a `SIGTRAP` reads as a step.
    stepping: bool,
    /// Address of a breakpoint we are stopped on (pc already past the trap).
    stopped_at_bp: Option<u64>,
    /// Shared live view, published after each operation.
    snapshot: Arc<Mutex<Snapshot>>,
    /// The debuggee's architecture, for disassembling its memory.
    arch: Option<Arch>,
}

impl Inner {
    /// Build the target and initial state on the worker thread.
    fn new(
        symbols: Arc<dyn Symbols>,
        io: Arc<DebugIo>,
        snapshot: Arc<Mutex<Snapshot>>,
    ) -> Result<Self> {
        Ok(Self {
            target: target::native(io)?,
            symbols,
            pid: None,
            state: ProcessState::Idle,
            last_stop: None,
            last_full: None,
            breakpoints: BTreeMap::new(),
            next_id: 1,
            bias: 0,
            stepping: false,
            stopped_at_bp: None,
            snapshot,
            arch: None,
        })
    }

    /// Publish the current session state for the UI to read directly.
    fn publish(&mut self) {
        let frames = if matches!(self.state, ProcessState::Stopped) {
            self.backtrace(None).unwrap_or_default()
        } else {
            Vec::new()
        };
        let snap = Snapshot {
            pid: self.pid,
            state: self.state,
            stop: self.last_full.clone(),
            breakpoints: self.breakpoints(),
            frames,
            bias: self.bias,
        };
        if let Ok(mut s) = self.snapshot.lock() {
            *s = snap;
        }
    }

    /// The debuggee pid, or [`Error::NotRunning`].
    fn pid(&self) -> Result<u32> {
        self.pid.ok_or(Error::NotRunning)
    }

    /// The main thread id (the pid on Linux).
    fn thread(&self) -> Result<ThreadId> {
        Ok(self.pid()? as ThreadId)
    }

    /// Resolve a [`BreakAt`] to a runtime address.
    fn resolve(&self, at: &BreakAt) -> Result<u64> {
        match at {
            BreakAt::Addr { addr } => Ok(*addr),
            BreakAt::Symbol { name } => self
                .symbols
                .resolve(name)
                .map(|static_addr| static_addr.wrapping_add(self.bias))
                .ok_or_else(|| Error::msg(format!("unknown symbol `{name}`"))),
        }
    }

    /// Launch a debuggee.
    fn launch(&mut self, opts: &LaunchOptions) -> Result<Stop> {
        let pid = self.target.launch(opts)?;
        self.arch = Arch::detect(std::path::Path::new(&opts.path));
        self.pid = Some(pid);
        let thread = pid as ThreadId;
        let registers = self.target.get_regs(thread)?;
        // The initial stop is at the entry point as loaded, which gives the
        // PIE/ASLR bias against the static entry the host knows.
        self.bias = self.symbols.load_bias(pid, Some(registers.pc)).unwrap_or(0);
        self.state = ProcessState::Stopped;
        self.last_stop = Some(StopReason::Started);
        let stop = Stop {
            pid,
            thread,
            reason: StopReason::Started,
            registers,
        };
        self.last_full = Some(stop.clone());
        self.publish();
        Ok(stop)
    }

    /// Attach to a running process.
    fn attach(&mut self, pid: u32) -> Result<Stop> {
        self.target.attach(pid)?;
        self.arch = Arch::detect(std::path::Path::new(&format!("/proc/{pid}/exe")));
        self.pid = Some(pid);
        self.bias = self.symbols.load_bias(pid, None).unwrap_or(0);
        self.state = ProcessState::Stopped;
        self.last_stop = Some(StopReason::Started);
        let thread = pid as ThreadId;
        let registers = self.target.get_regs(thread)?;
        let stop = Stop {
            pid,
            thread,
            reason: StopReason::Started,
            registers,
        };
        self.last_full = Some(stop.clone());
        self.publish();
        Ok(stop)
    }

    /// Install a breakpoint.
    fn add_breakpoint(&mut self, at: &BreakAt) -> Result<Breakpoint> {
        self.pid()?;
        let addr = self.resolve(at)?;
        let trap = arch::breakpoint_bytes();
        let original = self.target.read(addr, trap.len())?;
        self.target.write(addr, trap)?;
        let id = self.next_id;
        self.next_id += 1;
        let bp = Breakpoint {
            id,
            addr,
            enabled: true,
            original,
        };
        self.breakpoints.insert(id, bp.clone());
        Ok(bp)
    }

    /// Remove a breakpoint by id.
    fn remove_breakpoint(&mut self, id: u64) -> Result<()> {
        let bp = self
            .breakpoints
            .remove(&id)
            .ok_or(Error::NoSuchBreakpoint(id))?;
        if bp.enabled {
            self.target.write(bp.addr, &bp.original)?;
        }
        if self.stopped_at_bp == Some(bp.addr) {
            self.stopped_at_bp = None;
        }
        Ok(())
    }

    /// The installed breakpoints.
    fn breakpoints(&self) -> Vec<Breakpoint> {
        self.breakpoints.values().cloned().collect()
    }

    /// Resume.
    fn resume(&mut self) -> Result<Stop> {
        let thread = self.thread()?;
        let lifted = self.lift_breakpoint(thread)?;
        if lifted.is_some() {
            // Run the breakpointed instruction, then re-arm the trap.
            self.stepping = true;
            self.target.step_insn(thread, 0)?;
            self.wait_stop()?;
            self.rearm(&lifted)?;
        }
        self.state = ProcessState::Running;
        // Publish before blocking, so a follower sees the target is running.
        self.publish();
        self.target.cont(thread, 0)?;
        self.wait_stop()
    }

    /// Step.
    fn step(&mut self, kind: StepKind) -> Result<Stop> {
        let thread = self.thread()?;
        let lifted = self.lift_breakpoint(thread)?;
        let result = match kind {
            StepKind::Into => self.single_step(thread),
            StepKind::Over | StepKind::Out => {
                let regs = self.target.get_regs(thread)?;
                let bytes = self.target.read(regs.pc, 16).unwrap_or_default();
                // A call is run to completion; anything else is a plain step.
                // `Out` always runs to the return address. The "return address"
                // is only trustworthy when it is actually readable: at `_start`
                // the top of the stack is `argc`, not a return address.
                let wants_run = kind == StepKind::Out || arch::is_call(&bytes);
                let ret = if wants_run {
                    self.read_word(regs.sp)
                        .ok()
                        .filter(|ret| self.readable(*ret))
                } else {
                    None
                };
                match ret {
                    Some(ret) => self.run_to(thread, ret),
                    None => self.single_step(thread),
                }
            }
        };
        self.rearm(&lifted)?;
        result
    }

    /// Read registers.
    fn registers(&mut self, thread: Option<ThreadId>) -> Result<Registers> {
        let t = thread.unwrap_or(self.thread()?);
        self.target.get_regs(t)
    }

    /// Set one register, keeping the pc/sp/fp shortcuts in sync.
    fn set_register(&mut self, name: &str, value: u64) -> Result<Registers> {
        let thread = self.thread()?;
        let mut regs = self.target.get_regs(thread)?;
        match name {
            "pc" | "rip" => {
                regs.pc = value;
                regs.values.insert("rip".to_string(), value);
            }
            "sp" | "rsp" => {
                regs.sp = value;
                regs.values.insert("rsp".to_string(), value);
            }
            "fp" | "rbp" => {
                regs.fp = value;
                regs.values.insert("rbp".to_string(), value);
            }
            other => {
                regs.values.insert(other.to_string(), value);
            }
        }
        self.target.set_regs(thread, &regs)?;
        Ok(regs)
    }

    /// Read memory.
    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        self.pid()?;
        self.target.read(addr, len)
    }

    /// Write memory.
    fn write_memory(&mut self, addr: u64, bytes: &[u8]) -> Result<()> {
        self.pid()?;
        self.target.write(addr, bytes)
    }

    /// List threads.
    fn threads(&mut self) -> Result<Vec<ThreadId>> {
        self.pid()?;
        self.target.threads()
    }

    /// Disassemble live memory at `addr`.
    fn disasm(&mut self, addr: u64, count: usize) -> Result<Vec<Insn>> {
        self.pid()?;
        let arch = self
            .arch
            .ok_or_else(|| Error::msg("architecture unknown; cannot disassemble"))?;
        // x86 instructions are at most 16 bytes, so this always covers `count`.
        let want = count.max(1).saturating_mul(16);
        // Shrink the read until it fits mapped memory: the pc can sit near the
        // end of a page or region.
        let mut bytes = Vec::new();
        let mut len = want;
        while len > 0 {
            match self.target.read(addr, len) {
                Ok(b) => {
                    bytes = b;
                    break;
                }
                Err(_) => len /= 2,
            }
        }
        let raw = recurse_static::arch::disasm(arch, &bytes, addr, count).map_err(Error::msg)?;
        Ok(raw
            .into_iter()
            .map(|i| Insn {
                addr: i.addr,
                bytes: i.bytes.iter().map(|b| format!("{b:02x}")).collect(),
                text: i.text,
            })
            .collect())
    }

    /// Walk the frame-pointer chain.
    fn backtrace(&mut self, thread: Option<ThreadId>) -> Result<Vec<Frame>> {
        let t = thread.unwrap_or(self.thread()?);
        let regs = self.target.get_regs(t)?;
        let bias = self.bias;
        let symbols = self.symbols.clone();
        let name = |addr: u64| symbols.name_at(addr.wrapping_sub(bias));
        let mut frames = vec![Frame {
            addr: regs.pc,
            name: name(regs.pc),
        }];
        let mut fp = regs.fp;
        for _ in 0..MAX_FRAMES {
            if fp == 0 {
                break;
            }
            let ret = self.read_word(fp.wrapping_add(8))?;
            let next = self.read_word(fp)?;
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

    /// Snapshot.
    fn status(&self) -> Status {
        Status {
            pid: self.pid,
            state: self.state,
            stop: self.last_stop.clone(),
            breakpoints: self.breakpoints(),
        }
    }

    /// Detach.
    fn detach(&mut self) -> Result<()> {
        if self.pid.is_some() {
            self.target.detach()?;
        }
        self.pid = None;
        self.state = ProcessState::Exited;
        self.breakpoints.clear();
        self.stopped_at_bp = None;
        Ok(())
    }

    /// Kill.
    fn kill(&mut self) -> Result<()> {
        if self.pid.is_some() {
            self.target.kill()?;
        }
        self.pid = None;
        self.state = ProcessState::Exited;
        Ok(())
    }

    /// Block for the next stop and shape it into a [`Stop`].
    fn wait_stop(&mut self) -> Result<Stop> {
        let stop = match self.target.wait()? {
            WaitEvent::Stopped { thread, signal } => {
                let mut registers = self.target.get_regs(thread)?;
                let reason = self.classify(signal, &registers);
                // Report the breakpoint address, not the byte past the trap.
                if let StopReason::Breakpoint { addr, .. } = &reason {
                    registers.pc = *addr;
                }
                self.state = ProcessState::Stopped;
                self.last_stop = Some(reason.clone());
                Stop {
                    pid: self.pid.unwrap_or(0),
                    thread,
                    reason,
                    registers,
                }
            }
            WaitEvent::Exited { code } => {
                self.pid = None;
                self.state = ProcessState::Exited;
                let reason = StopReason::Exited { code };
                self.last_stop = Some(reason.clone());
                terminal_stop(reason)
            }
            WaitEvent::Signaled { signal } => {
                self.pid = None;
                self.state = ProcessState::Exited;
                let reason = StopReason::Killed { signal };
                self.last_stop = Some(reason.clone());
                terminal_stop(reason)
            }
            WaitEvent::Other => {
                let reason = StopReason::Signal {
                    signal: 0,
                    name: "event".to_string(),
                };
                self.last_stop = Some(reason.clone());
                Stop {
                    pid: self.pid.unwrap_or(0),
                    thread: 0,
                    reason,
                    registers: Registers::default(),
                }
            }
        };
        self.last_full = Some(stop.clone());
        self.publish();
        Ok(stop)
    }

    /// Turn a stop signal + registers into a [`StopReason`].
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

    /// Single-step and wait, marking the trap as a step.
    fn single_step(&mut self, thread: ThreadId) -> Result<Stop> {
        self.stepping = true;
        self.state = ProcessState::Running;
        self.publish();
        self.target.step_insn(thread, 0)?;
        self.wait_stop()
    }

    /// Run until `addr` via a temporary breakpoint, then remove it and rewind
    /// the pc so the instruction there executes next.
    fn run_to(&mut self, thread: ThreadId, addr: u64) -> Result<Stop> {
        let trap = arch::breakpoint_bytes();
        // If the address is not readable we cannot place a temporary
        // breakpoint; fall back to a plain single-step.
        let Ok(original) = self.target.read(addr, trap.len()) else {
            return self.single_step(thread);
        };
        self.target.write(addr, trap)?;
        self.stepping = true;
        self.state = ProcessState::Running;
        self.publish();
        self.target.cont(thread, 0)?;
        let stop = self.wait_stop()?;
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
    /// rewind the pc. Returns `(id, address, original bytes)` to re-arm later.
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

    /// True when `addr` can be read (a breakpoint byte fits there).
    fn readable(&mut self, addr: u64) -> bool {
        self.target
            .read(addr, arch::breakpoint_bytes().len())
            .is_ok()
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
