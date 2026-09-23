//! Linux debug backend: `ptrace` + `waitpid` + `/proc`.
//!
//! All `unsafe` in this crate lives behind this module's small surface.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::unix::io::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use super::{Target, WaitEvent};
use crate::error::{Error, Result};
use crate::model::{LaunchOptions, Registers, ThreadId};

/// `PTRACE_O_*` options every session runs with: kill the debuggee if the
/// debugger dies, so we never leak a traced process.
fn default_options() -> ptrace::Options {
    ptrace::Options::PTRACE_O_EXITKILL
}

/// A ptrace-based debug target.
pub struct LinuxTarget {
    pid: Option<Pid>,
    /// Shared debuggee stdio (stdin sink + captured output).
    io: Arc<crate::session::DebugIo>,
}

impl LinuxTarget {
    /// A target with no process attached yet.
    ///
    /// ```
    /// use recurse_debug::target::linux::LinuxTarget;
    /// use recurse_debug::session::DebugIo;
    /// use std::sync::Arc;
    /// let _ = LinuxTarget::new(Arc::new(DebugIo::new()));
    /// ```
    pub fn new(io: Arc<crate::session::DebugIo>) -> Self {
        Self { pid: None, io }
    }

    /// The attached pid, or [`Error::NotRunning`].
    fn pid(&self) -> Result<Pid> {
        self.pid.ok_or(Error::NotRunning)
    }

    /// Map a nix errno to an [`Error`].
    fn errno(e: Errno) -> Error {
        Error::Io(io::Error::from_raw_os_error(e as i32))
    }
}

impl Default for LinuxTarget {
    fn default() -> Self {
        Self {
            pid: None,
            io: Arc::new(crate::session::DebugIo::new()),
        }
    }
}

impl Target for LinuxTarget {
    fn launch(&mut self, opts: &LaunchOptions) -> Result<u32> {
        if opts.path.is_empty() {
            return Err(Error::msg("launch: empty path"));
        }
        let mut cmd = Command::new(&opts.path);
        cmd.args(&opts.args);
        if let Some(cwd) = &opts.cwd {
            cmd.current_dir(cwd);
        }
        for (k, v) in &opts.env {
            cmd.env(k, v);
        }
        // Allocate a pseudo-terminal for the debuggee. A pipe would make libc
        // fully buffer stdout, so prompts would not appear until the process
        // exits; a tty makes it line-buffered, so the session is interactive.
        let (master, slave) = open_pty()?;
        // SAFETY: `pre_exec` runs in the forked child before `exec`; these are
        // async-signal-safe syscalls, and the closure captures only fds.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::ioctl(slave, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                for fd in 0..=2 {
                    if libc::dup2(slave, fd) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if slave > 2 {
                    libc::close(slave);
                }
                if master > 2 {
                    libc::close(master);
                }
                ptrace::traceme().map_err(|e| io::Error::from_raw_os_error(e as i32))
            });
        }
        let child = cmd.spawn()?;
        let pid = Pid::from_raw(child.id() as i32);
        // The child owns the slave end; the parent talks to the master.
        // SAFETY: `slave` is a valid fd we no longer need in the parent.
        unsafe {
            libc::close(slave);
        }
        // SAFETY: `master` is a valid fd; `File` now owns it.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        if let Ok(write_half) = master.try_clone() {
            self.io.set_stdin(Box::new(write_half));
        }
        spawn_reader(master, self.io.clone());
        // We own the child's lifecycle through ptrace/waitpid, so drop the
        // std handle without killing it.
        std::mem::forget(child);
        self.pid = Some(pid);
        // The child stops at exec with SIGTRAP; reap that stop, then set the
        // options (which can only be set once it is stopped).
        match waitpid(pid, None).map_err(Self::errno)? {
            WaitStatus::Stopped(..) => {}
            _ => return Err(Error::msg("debuggee did not stop at exec")),
        }
        ptrace::setoptions(pid, default_options()).map_err(Self::errno)?;
        Ok(pid.as_raw() as u32)
    }

    fn attach(&mut self, pid: u32) -> Result<()> {
        let p = Pid::from_raw(pid as i32);
        // SEIZE stops without a race and without a SIGSTOP the process would
        // otherwise observe; fall back to ATTACH on older kernels.
        if ptrace::seize(p, default_options()).is_err() {
            ptrace::attach(p).map_err(Self::errno)?;
        }
        self.pid = Some(p);
        match waitpid(p, None).map_err(Self::errno)? {
            WaitStatus::Stopped(..) => {}
            _ => return Err(Error::msg("attach: process did not stop")),
        }
        ptrace::setoptions(p, default_options()).map_err(Self::errno)?;
        Ok(())
    }

    fn wait(&mut self) -> Result<WaitEvent> {
        let pid = self.pid()?;
        loop {
            match waitpid(pid, None).map_err(Self::errno)? {
                // Syscall stops and fork/clone/exec notifications are not
                // modelled; keep waiting for a real stop.
                WaitStatus::PtraceSyscall(_) => continue,
                WaitStatus::PtraceEvent(_, _, event) if event != EVENT_STOP => continue,
                status => return Ok(event_of(status)),
            }
        }
    }

    fn poll(&mut self) -> Result<Option<WaitEvent>> {
        let pid = self.pid()?;
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)).map_err(Self::errno)? {
            WaitStatus::StillAlive => Ok(None),
            WaitStatus::PtraceSyscall(_) => Ok(None),
            WaitStatus::PtraceEvent(_, _, event) if event != EVENT_STOP => Ok(None),
            status => Ok(Some(event_of(status))),
        }
    }

    fn interrupt(&mut self) -> Result<()> {
        let pid = self.pid()?;
        // PTRACE_INTERRUPT only works on a SEIZE'd tracee; a TRACEME child does
        // not support it, so stop it with a signal. The tracer consumes the
        // stop and resuming continues normally.
        nix::sys::signal::kill(pid, Signal::SIGSTOP).map_err(Self::errno)
    }

    fn cont(&mut self, thread: ThreadId, signal: i32) -> Result<()> {
        ptrace::cont(Pid::from_raw(thread as i32), signal_opt(signal)).map_err(Self::errno)
    }

    fn step_insn(&mut self, thread: ThreadId, signal: i32) -> Result<()> {
        ptrace::step(Pid::from_raw(thread as i32), signal_opt(signal)).map_err(Self::errno)
    }

    fn get_regs(&mut self, thread: ThreadId) -> Result<Registers> {
        let regs = ptrace::getregs(Pid::from_raw(thread as i32)).map_err(Self::errno)?;
        Ok(regs_from(&regs))
    }

    fn set_regs(&mut self, thread: ThreadId, regs: &Registers) -> Result<()> {
        let pid = Pid::from_raw(thread as i32);
        let current = ptrace::getregs(pid).map_err(Self::errno)?;
        ptrace::setregs(pid, apply_regs(current, regs)).map_err(Self::errno)
    }

    fn read(&mut self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let pid = self.pid()?;
        let mut out = Vec::with_capacity(len);
        let mut a = addr;
        while out.len() < len {
            let word = ptrace::read(pid, a as ptrace::AddressType).map_err(Self::errno)? as u64;
            let bytes = word.to_ne_bytes();
            let take = (len - out.len()).min(bytes.len());
            out.extend_from_slice(&bytes[..take]);
            a = a.wrapping_add(bytes.len() as u64);
        }
        Ok(out)
    }

    fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<()> {
        let pid = self.pid()?;
        let mut written = 0;
        while written < bytes.len() {
            let a = addr.wrapping_add(written as u64);
            // Read-modify-write the containing word so a partial write keeps
            // the neighbouring bytes intact.
            let word = ptrace::read(pid, a as ptrace::AddressType).map_err(Self::errno)? as u64;
            let mut buf = word.to_ne_bytes();
            let take = (bytes.len() - written).min(buf.len());
            buf[..take].copy_from_slice(&bytes[written..written + take]);
            let new = u64::from_ne_bytes(buf);
            ptrace::write(pid, a as ptrace::AddressType, new as libc::c_long)
                .map_err(Self::errno)?;
            written += take;
        }
        Ok(())
    }

    fn threads(&mut self) -> Result<Vec<ThreadId>> {
        let pid = self.pid()?;
        let dir = format!("/proc/{}/task", pid.as_raw());
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) {
                out.push(tid);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    fn detach(&mut self) -> Result<()> {
        let pid = self.pid()?;
        ptrace::detach(pid, None).map_err(Self::errno)?;
        self.pid = None;
        Ok(())
    }

    fn kill(&mut self) -> Result<()> {
        let pid = self.pid()?;
        let res = ptrace::kill(pid).map_err(Self::errno);
        self.pid = None;
        res
    }
}

/// A `Signal` for a raw signal number, or `None` for 0.
fn signal_opt(signal: i32) -> Option<Signal> {
    if signal == 0 {
        None
    } else {
        Signal::try_from(signal).ok()
    }
}

/// `PTRACE_EVENT_STOP`: the event raised by `PTRACE_INTERRUPT` and group-stops.
const EVENT_STOP: i32 = 128;

/// Map a wait status to a [`WaitEvent`].
fn event_of(status: WaitStatus) -> WaitEvent {
    match status {
        WaitStatus::Stopped(thread, sig) => WaitEvent::Stopped {
            thread: thread.as_raw() as u64,
            signal: sig as i32,
        },
        // `PTRACE_INTERRUPT` reports a stop event with no signal.
        WaitStatus::PtraceEvent(thread, _, _) => WaitEvent::Stopped {
            thread: thread.as_raw() as u64,
            signal: 0,
        },
        WaitStatus::Exited(_, code) => WaitEvent::Exited { code },
        WaitStatus::Signaled(_, sig, _) => WaitEvent::Signaled { signal: sig as i32 },
        _ => WaitEvent::Other,
    }
}

/// Cap on captured output, so a chatty debuggee cannot grow the buffer without
/// bound. Older bytes are dropped first.
/// Open a pseudo-terminal pair: `(master, slave)`.
fn open_pty() -> Result<(libc::c_int, libc::c_int)> {
    // SAFETY: `posix_openpt` returns a new fd or -1; the rest operate on it.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            libc::close(master);
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(master, name.as_mut_ptr(), name.len()) != 0 {
            libc::close(master);
            return Err(Error::Io(io::Error::last_os_error()));
        }
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if slave < 0 {
            libc::close(master);
            return Err(Error::Io(io::Error::last_os_error()));
        }
        // Do not echo typed input back into the output pane; the analyst types
        // in the UI, not at the terminal.
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(slave, &mut term) == 0 {
            term.c_lflag &= !libc::ECHO;
            libc::tcsetattr(slave, libc::TCSANOW, &term);
        }
        Ok((master, slave))
    }
}

/// Read a child pipe into the shared output buffer until EOF.
fn spawn_reader(mut reader: impl Read + Send + 'static, io: Arc<crate::session::DebugIo>) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => io.push_output(&chunk[..n]),
            }
        }
    });
}

/// Build the platform-neutral register set from the OS struct.
#[cfg(target_arch = "x86_64")]
fn regs_from(r: &libc::user_regs_struct) -> Registers {
    let pairs: [(&str, u64); 19] = [
        ("rax", r.rax),
        ("rbx", r.rbx),
        ("rcx", r.rcx),
        ("rdx", r.rdx),
        ("rsi", r.rsi),
        ("rdi", r.rdi),
        ("rbp", r.rbp),
        ("rsp", r.rsp),
        ("r8", r.r8),
        ("r9", r.r9),
        ("r10", r.r10),
        ("r11", r.r11),
        ("r12", r.r12),
        ("r13", r.r13),
        ("r14", r.r14),
        ("r15", r.r15),
        ("rip", r.rip),
        ("eflags", r.eflags),
        ("orig_rax", r.orig_rax),
    ];
    let values = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), *v))
        .collect::<BTreeMap<_, _>>();
    Registers {
        pc: r.rip,
        sp: r.rsp,
        fp: r.rbp,
        values,
    }
}

/// Apply the platform-neutral register set onto the OS struct.
#[cfg(target_arch = "x86_64")]
fn apply_regs(mut r: libc::user_regs_struct, regs: &Registers) -> libc::user_regs_struct {
    for (k, v) in &regs.values {
        match k.as_str() {
            "rax" => r.rax = *v,
            "rbx" => r.rbx = *v,
            "rcx" => r.rcx = *v,
            "rdx" => r.rdx = *v,
            "rsi" => r.rsi = *v,
            "rdi" => r.rdi = *v,
            "rbp" => r.rbp = *v,
            "rsp" => r.rsp = *v,
            "r8" => r.r8 = *v,
            "r9" => r.r9 = *v,
            "r10" => r.r10 = *v,
            "r11" => r.r11 = *v,
            "r12" => r.r12 = *v,
            "r13" => r.r13 = *v,
            "r14" => r.r14 = *v,
            "r15" => r.r15 = *v,
            "rip" => r.rip = *v,
            "eflags" => r.eflags = *v,
            _ => {}
        }
    }
    r.rip = regs.pc;
    r.rsp = regs.sp;
    r.rbp = regs.fp;
    r
}

/// Build the register set from the OS struct (AArch64).
#[cfg(target_arch = "aarch64")]
fn regs_from(r: &libc::user_regs_struct) -> Registers {
    let mut values = BTreeMap::new();
    for (i, v) in r.regs.iter().enumerate() {
        values.insert(format!("x{i}"), *v);
    }
    values.insert("sp".to_string(), r.sp);
    values.insert("pc".to_string(), r.pc);
    values.insert("pstate".to_string(), r.pstate);
    Registers {
        pc: r.pc,
        sp: r.sp,
        fp: r.regs[29],
        values,
    }
}

/// Apply the register set onto the OS struct (AArch64).
#[cfg(target_arch = "aarch64")]
fn apply_regs(mut r: libc::user_regs_struct, regs: &Registers) -> libc::user_regs_struct {
    for (i, slot) in r.regs.iter_mut().enumerate() {
        if let Some(v) = regs.values.get(&format!("x{i}")) {
            *slot = *v;
        }
    }
    r.sp = regs.sp;
    r.pc = regs.pc;
    if let Some(ps) = regs.values.get("pstate") {
        r.pstate = *ps;
    }
    r
}

/// Fallback register mapping for architectures without an explicit one.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn regs_from(_r: &libc::user_regs_struct) -> Registers {
    Registers::default()
}

/// Fallback register application for architectures without an explicit one.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn apply_regs(r: libc::user_regs_struct, _regs: &Registers) -> libc::user_regs_struct {
    r
}
