//! Windows `Target`: the Win32 debug API
//! (`CreateProcessW(DEBUG_ONLY_THIS_PROCESS)`, `WaitForDebugEvent`,
//! `ContinueDebugEvent`, `Get/SetThreadContext`,
//! `Read/WriteProcessMemory`).
//!
//! # The event-acknowledgement contract
//!
//! Every `WaitForDebugEvent` the OS delivers must eventually be answered
//! with exactly one `ContinueDebugEvent`, or the debuggee's thread stays
//! frozen forever. This struct tracks the single outstanding event as
//! [`WindowsTarget::pending`] and resolves it inside [`Target::cont`]/
//! [`Target::step_insn`] — the same "acknowledge on resume, not on
//! receipt" shape `session.rs` already expects from a ptrace backend
//! (where `PTRACE_CONT`/`PTRACE_SINGLESTEP` themselves both resume *and*
//! acknowledge in one call).
//!
//! # `EXCEPTION_BREAKPOINT` is overloaded
//!
//! A software breakpoint (`int3`), the very first stop after launch (the
//! loader's own breakpoint), and [`DebugBreakProcess`] (this backend's
//! [`Target::interrupt`]) all raise the *same* exception code. This
//! backend distinguishes "this stop is our own async pause request" by
//! tracking [`WindowsTarget::interrupt_requested`] and reporting signal
//! `0` for exactly the next `EXCEPTION_BREAKPOINT` after `interrupt()` is
//! called — matching `session.rs`'s own `classify()`, which already
//! treats signal `0` as "the stop is ours, not the program's" (see its
//! doc comment).
//!
//! # Honest scope
//!
//! - x86-64 only (`CONTEXT` field names below are the AMD64 layout).
//! - No debuggee stdio capture: [`DebugIo`] is stored but never wired to
//!   a piped stdin/stdout — the debuggee gets its own console instead.
//!   Real, scoped follow-up work (`CreatePipe` + `STARTUPINFOW`'s
//!   `hStd*`/`STARTF_USESTDHANDLES` + a reader thread).
//! - `LaunchOptions::env`, when non-empty, replaces rather than merges
//!   with the debugger's own environment (Win32's own
//!   `CREATE_UNICODE_ENVIRONMENT` block convention has no separate
//!   "inherit but override" mode either).

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, HANDLE,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugBreakProcess,
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WaitForDebugEvent, WriteProcessMemory, CONTEXT, CONTEXT_ALL_AMD64, CREATE_PROCESS_DEBUG_EVENT,
    CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
    UNLOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, TerminateProcess, CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS,
    INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::error::{Error, Result};
use crate::model::{LaunchOptions, Registers, ThreadId};
use crate::session::DebugIo;
use crate::target::{Target, WaitEvent};

/// `SIGTRAP`/`SIGSTOP`, matching `session.rs`'s own constants — this
/// backend reports its native stops using these POSIX-style numbers so
/// `session.rs` never needs to know it's talking to a non-POSIX OS.
const SIGTRAP: i32 = 5;

/// The event `WaitForDebugEvent` most recently delivered, not yet
/// acknowledged with `ContinueDebugEvent`.
struct PendingEvent {
    pid: u32,
    tid: u32,
}

pub(crate) struct WindowsTarget {
    #[allow(dead_code)]
    // stored for parity with other backends; see module docs (stdio not yet wired)
    io: Arc<DebugIo>,
    process: HANDLE,
    pid: u32,
    /// `dwThreadId -> handle`, **plus** a standing `pid -> handle` alias
    /// (see the `CREATE_PROCESS_DEBUG_EVENT`/`EXCEPTION_DEBUG_EVENT` arms
    /// of `pump`) so `session.rs`'s `pid as ThreadId` "default thread"
    /// convention resolves. [`WindowsTarget::real_thread_ids`] is the
    /// authoritative set of *actual* thread ids, for
    /// [`Target::threads`] to report — this map's keys alone would
    /// wrongly include the `pid` alias as if it were a real thread.
    threads: HashMap<u32, HANDLE>,
    real_thread_ids: std::collections::HashSet<u32>,
    pending: Option<PendingEvent>,
    interrupt_requested: bool,
}

// SAFETY: `HANDLE` (a raw `isize`) and every field here are plain data;
// this backend's methods are only ever called from the one dedicated
// worker thread `crate::session` already serializes all target access
// through (see that module's own "why a worker thread" doc), the same
// precondition the Win32 debug API itself imposes (only the thread that
// called `CreateProcessW`/`DebugActiveProcess` may call
// `WaitForDebugEvent`/`ContinueDebugEvent` for that debuggee).
unsafe impl Send for WindowsTarget {}

impl WindowsTarget {
    pub(crate) fn new(io: Arc<DebugIo>) -> Self {
        Self {
            io,
            process: std::ptr::null_mut(),
            pid: 0,
            threads: HashMap::new(),
            real_thread_ids: std::collections::HashSet::new(),
            pending: None,
            interrupt_requested: false,
        }
    }

    fn thread_handle(&self, thread: ThreadId) -> Result<HANDLE> {
        self.threads
            .get(&(thread as u32))
            .copied()
            .ok_or(Error::NotRunning)
    }

    /// Resolve whatever event is currently pending with `ContinueDebugEvent`.
    /// A no-op (not an error) when nothing is pending, so `cont`/`step_insn`
    /// stay simple to call right after `launch`/`attach`'s own initial stop.
    fn continue_pending(&mut self, handled: bool) -> Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        let status = if handled {
            DBG_CONTINUE
        } else {
            DBG_EXCEPTION_NOT_HANDLED
        };
        // SAFETY: `pending.{pid,tid}` are exactly the identifiers the most
        // recent `WaitForDebugEvent` reported; the Win32 contract requires
        // passing them back unchanged.
        let ok = unsafe { ContinueDebugEvent(pending.pid, pending.tid, status) };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Block for the next debug event, auto-continuing everything except a
    /// real stop (an exception) or process exit — the shared core of
    /// `launch`'s/`attach`'s initial pump and the steady-state `wait`.
    fn pump(&mut self, timeout_ms: u32) -> Result<Option<WaitEvent>> {
        loop {
            let mut event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
            // SAFETY: `event` is a valid, writable, correctly-sized
            // out-parameter for the duration of this call.
            let ok = unsafe { WaitForDebugEvent(&raw mut event, timeout_ms) };
            if ok == 0 {
                // Only a real timeout is expected here (poll()'s 0ms case);
                // anything else is a genuine OS error.
                return Ok(None);
            }

            let pid = event.dwProcessId;
            let tid = event.dwThreadId;
            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    // SAFETY: `dwDebugEventCode` guarantees this union arm.
                    let info = unsafe { event.u.CreateProcessInfo };
                    self.process = info.hProcess;
                    self.pid = pid;
                    self.threads.insert(tid, info.hThread);
                    self.real_thread_ids.insert(tid);
                    // `crate::session` was written for ptrace, where a
                    // freshly-`TRACEME`'d child's pid and its initial
                    // thread id are the same number; it uses `pid as
                    // ThreadId` as its "default thread" handle
                    // throughout (see `Inner::thread`). Windows has
                    // separate pid/tid number spaces, so this struct
                    // keeps a standing alias `pid -> $the current
                    // thread's handle`, refreshed on every stop (see the
                    // `EXCEPTION_DEBUG_EVENT` arm below) so that
                    // convention resolves to the right thread here too.
                    self.threads.insert(pid, info.hThread);
                    if !info.hFile.is_null() {
                        // SAFETY: a valid handle the OS opened for us; we own it now.
                        unsafe { CloseHandle(info.hFile) };
                    }
                    self.ack(pid, tid);
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    // SAFETY: `dwDebugEventCode` guarantees this union arm.
                    let info = unsafe { event.u.CreateThread };
                    self.threads.insert(tid, info.hThread);
                    self.real_thread_ids.insert(tid);
                    self.ack(pid, tid);
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    if let Some(handle) = self.threads.remove(&tid) {
                        self.real_thread_ids.remove(&tid);
                        // SAFETY: a handle this struct owns exclusively.
                        unsafe { CloseHandle(handle) };
                    }
                    self.ack(pid, tid);
                }
                LOAD_DLL_DEBUG_EVENT => {
                    // SAFETY: `dwDebugEventCode` guarantees this union arm.
                    let info = unsafe { event.u.LoadDll };
                    if !info.hFile.is_null() {
                        // SAFETY: a valid handle the OS opened for us; we own it now.
                        unsafe { CloseHandle(info.hFile) };
                    }
                    self.ack(pid, tid);
                }
                UNLOAD_DLL_DEBUG_EVENT | OUTPUT_DEBUG_STRING_EVENT | RIP_EVENT => {
                    self.ack(pid, tid);
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    // SAFETY: `dwDebugEventCode` guarantees this union arm.
                    let info = unsafe { event.u.ExitProcess };
                    self.pending = None;
                    return Ok(Some(WaitEvent::Exited {
                        code: info.dwExitCode as i32,
                    }));
                }
                EXCEPTION_DEBUG_EVENT => {
                    self.pending = Some(PendingEvent { pid, tid });
                    // Refresh the `pid`-alias (see the
                    // `CREATE_PROCESS_DEBUG_EVENT` arm above) to the
                    // thread that actually just stopped.
                    if let Some(&handle) = self.threads.get(&tid) {
                        self.threads.insert(pid, handle);
                    }
                    // SAFETY: `dwDebugEventCode` guarantees this union arm.
                    let exception = unsafe { event.u.Exception };
                    let code = exception.ExceptionRecord.ExceptionCode;
                    let signal = if code == EXCEPTION_BREAKPOINT {
                        if std::mem::take(&mut self.interrupt_requested) {
                            0
                        } else {
                            SIGTRAP
                        }
                    } else if code == EXCEPTION_SINGLE_STEP {
                        SIGTRAP
                    } else {
                        code
                    };
                    return Ok(Some(WaitEvent::Stopped {
                        thread: tid as ThreadId,
                        signal,
                    }));
                }
                _ => self.ack(pid, tid),
            }
        }
    }

    /// Immediately acknowledge an event this backend handles internally
    /// (never surfaced to `session.rs`) — everything except an exception
    /// or process exit.
    fn ack(&mut self, pid: u32, tid: u32) {
        // SAFETY: `pid`/`tid` are exactly what the event we're acking
        // reported.
        unsafe {
            ContinueDebugEvent(pid, tid, DBG_CONTINUE);
        }
    }

    fn read_context(&self, thread: ThreadId) -> Result<CONTEXT> {
        let handle = self.thread_handle(thread)?;
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.ContextFlags = CONTEXT_ALL_AMD64;
        // SAFETY: `handle` is a live thread handle this struct owns;
        // `ctx` is a correctly-sized, writable out-parameter.
        let ok = unsafe { GetThreadContext(handle, &raw mut ctx) };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(ctx)
    }

    fn write_context(&self, thread: ThreadId, ctx: &CONTEXT) -> Result<()> {
        let handle = self.thread_handle(thread)?;
        // SAFETY: `handle` is a live thread handle this struct owns; `ctx`
        // is a valid, initialized `CONTEXT` (built from a prior
        // `GetThreadContext` call in every caller here).
        let ok = unsafe { SetThreadContext(handle, &raw const *ctx) };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn set_trap_flag(&self, thread: ThreadId, enabled: bool) -> Result<()> {
        let mut ctx = self.read_context(thread)?;
        const TRAP_FLAG: u32 = 0x100;
        if enabled {
            ctx.EFlags |= TRAP_FLAG;
        } else {
            ctx.EFlags &= !TRAP_FLAG;
        }
        self.write_context(thread, &ctx)
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a Win32 `CREATE_UNICODE_ENVIRONMENT` block: `"K=V\0"` pairs, in a
/// single buffer, terminated by an extra `\0`.
fn build_env_block(env: &std::collections::BTreeMap<String, String>) -> Vec<u16> {
    let mut block = Vec::new();
    for (k, v) in env {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

fn context_registers(ctx: &CONTEXT) -> Registers {
    let mut values = std::collections::BTreeMap::new();
    values.insert("rax".to_string(), ctx.Rax);
    values.insert("rbx".to_string(), ctx.Rbx);
    values.insert("rcx".to_string(), ctx.Rcx);
    values.insert("rdx".to_string(), ctx.Rdx);
    values.insert("rsi".to_string(), ctx.Rsi);
    values.insert("rdi".to_string(), ctx.Rdi);
    values.insert("r8".to_string(), ctx.R8);
    values.insert("r9".to_string(), ctx.R9);
    values.insert("r10".to_string(), ctx.R10);
    values.insert("r11".to_string(), ctx.R11);
    values.insert("r12".to_string(), ctx.R12);
    values.insert("r13".to_string(), ctx.R13);
    values.insert("r14".to_string(), ctx.R14);
    values.insert("r15".to_string(), ctx.R15);
    values.insert("rip".to_string(), ctx.Rip);
    values.insert("rsp".to_string(), ctx.Rsp);
    values.insert("rbp".to_string(), ctx.Rbp);
    values.insert("eflags".to_string(), u64::from(ctx.EFlags));
    Registers {
        pc: ctx.Rip,
        sp: ctx.Rsp,
        fp: ctx.Rbp,
        values,
    }
}

impl Target for WindowsTarget {
    fn launch(&mut self, opts: &LaunchOptions) -> Result<u32> {
        let app_name = to_wide(&opts.path);
        let mut cmdline = to_wide(&{
            let mut s = format!("\"{}\"", opts.path);
            for a in &opts.args {
                s.push(' ');
                s.push('"');
                s.push_str(&a.replace('"', "\\\""));
                s.push('"');
            }
            s
        });
        let cwd = opts.cwd.as_deref().map(to_wide);
        let env_block = if opts.env.is_empty() {
            None
        } else {
            Some(build_env_block(&opts.env))
        };

        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let mut flags = DEBUG_ONLY_THIS_PROCESS;
        if env_block.is_some() {
            flags |= CREATE_UNICODE_ENVIRONMENT;
        }

        // SAFETY: every pointer passed is either null or points at a live,
        // correctly-sized buffer (`app_name`/`cmdline` are NUL-terminated
        // `Vec<u16>` kept alive for the whole call; `cwd`/`env_block`
        // likewise or null; `startup`/`process_info` are valid,
        // correctly-sized in/out parameters).
        let ok = unsafe {
            CreateProcessW(
                app_name.as_ptr(),
                cmdline.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                flags,
                env_block
                    .as_ref()
                    .map_or(std::ptr::null(), |b| b.as_ptr().cast::<c_void>()),
                cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
                &raw const startup,
                &raw mut process_info,
            )
        };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        // Both handles are also observed (and, for `hFile`/duplicate
        // bookkeeping, owned) through the CREATE_PROCESS_DEBUG_EVENT the
        // pump below will process; closing the ones `CreateProcessW`
        // itself returned here would double-close the same handle, so
        // they're intentionally left for the pump to take ownership of.
        let _ = process_info;

        loop {
            match self.pump(INFINITE)? {
                Some(WaitEvent::Stopped { .. }) => return Ok(self.pid),
                Some(WaitEvent::Exited { code }) => {
                    return Err(Error::msg(format!(
                        "process exited before the initial stop (code {code})"
                    )));
                }
                _ => {}
            }
        }
    }

    fn attach(&mut self, pid: u32) -> Result<()> {
        // SAFETY: `pid` is a plain value; no aliasing/lifetime concerns.
        let ok = unsafe { DebugActiveProcess(pid) };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        loop {
            match self.pump(INFINITE)? {
                Some(WaitEvent::Stopped { .. }) => return Ok(()),
                Some(WaitEvent::Exited { code }) => {
                    return Err(Error::msg(format!(
                        "process exited before the initial stop (code {code})"
                    )));
                }
                _ => {}
            }
        }
    }

    fn get_regs(&mut self, thread: ThreadId) -> Result<Registers> {
        Ok(context_registers(&self.read_context(thread)?))
    }

    fn set_regs(&mut self, thread: ThreadId, regs: &Registers) -> Result<()> {
        let mut ctx = self.read_context(thread)?;
        ctx.Rip = regs.pc;
        ctx.Rsp = regs.sp;
        ctx.Rbp = regs.fp;
        for (name, value) in &regs.values {
            match name.as_str() {
                "rax" => ctx.Rax = *value,
                "rbx" => ctx.Rbx = *value,
                "rcx" => ctx.Rcx = *value,
                "rdx" => ctx.Rdx = *value,
                "rsi" => ctx.Rsi = *value,
                "rdi" => ctx.Rdi = *value,
                "r8" => ctx.R8 = *value,
                "r9" => ctx.R9 = *value,
                "r10" => ctx.R10 = *value,
                "r11" => ctx.R11 = *value,
                "r12" => ctx.R12 = *value,
                "r13" => ctx.R13 = *value,
                "r14" => ctx.R14 = *value,
                "r15" => ctx.R15 = *value,
                "eflags" => ctx.EFlags = *value as u32,
                _ => {}
            }
        }
        self.write_context(thread, &ctx)
    }

    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut read = 0usize;
        // SAFETY: `self.process` is a live process handle this struct
        // owns; `buf` is a writable buffer of exactly `len` bytes.
        let ok = unsafe {
            ReadProcessMemory(
                self.process,
                addr as *const c_void,
                buf.as_mut_ptr().cast(),
                len,
                &raw mut read,
            )
        };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        buf.truncate(read);
        Ok(buf)
    }

    fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<()> {
        let mut written = 0usize;
        // SAFETY: `self.process` is a live process handle this struct
        // owns; `bytes` is a valid, readable buffer for its own length.
        let ok = unsafe {
            WriteProcessMemory(
                self.process,
                addr as *const c_void,
                bytes.as_ptr().cast(),
                bytes.len(),
                &raw mut written,
            )
        };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        // A breakpoint trap byte just written to code memory must be
        // flushed from the instruction cache, or the CPU may still
        // execute the stale (pre-trap) instruction stream.
        // SAFETY: same handle/address/length just validated above.
        unsafe {
            FlushInstructionCache(self.process, addr as *const c_void, bytes.len());
        }
        Ok(())
    }

    fn threads(&mut self) -> Result<Vec<ThreadId>> {
        Ok(self
            .real_thread_ids
            .iter()
            .map(|&t| t as ThreadId)
            .collect())
    }

    fn detach(&mut self) -> Result<()> {
        self.continue_pending(true)?;
        // SAFETY: `self.pid` is a plain value; no aliasing/lifetime concerns.
        let ok = unsafe { DebugActiveProcessStop(self.pid) };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn kill(&mut self) -> Result<()> {
        let _ = self.continue_pending(true);
        // SAFETY: `self.process` is a live process handle this struct owns.
        let ok = unsafe { TerminateProcess(self.process, 1) };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn step_insn(&mut self, thread: ThreadId, signal: i32) -> Result<()> {
        self.set_trap_flag(thread, true)?;
        self.continue_pending(signal == 0)
    }

    fn cont(&mut self, thread: ThreadId, signal: i32) -> Result<()> {
        self.set_trap_flag(thread, false)?;
        self.continue_pending(signal == 0)
    }

    fn wait(&mut self) -> Result<WaitEvent> {
        loop {
            if let Some(event) = self.pump(INFINITE)? {
                return Ok(event);
            }
        }
    }

    fn poll(&mut self) -> Result<Option<WaitEvent>> {
        self.pump(0)
    }

    fn interrupt(&mut self) -> Result<()> {
        self.interrupt_requested = true;
        // SAFETY: `self.process` is a live process handle this struct owns.
        let ok = unsafe { DebugBreakProcess(self.process) };
        if ok == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

impl Drop for WindowsTarget {
    fn drop(&mut self) {
        for (_, handle) in self.threads.drain() {
            // SAFETY: handles this struct exclusively owns; the target is
            // being torn down, so nothing else can be using them.
            unsafe {
                CloseHandle(handle);
            }
        }
        if !self.process.is_null() {
            // SAFETY: a handle this struct exclusively owns.
            unsafe {
                CloseHandle(self.process);
            }
        }
    }
}
