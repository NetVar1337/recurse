//! Platform-neutral debugger types.
//!
//! These are what the session, the agent tool, and the UI pass around; the
//! per-OS backends translate to and from them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A thread id (a pid on Linux, a thread handle on Windows).
pub type ThreadId = u64;

/// A breakpoint id, unique within a session.
pub type BreakId = u64;

/// How to resume after a stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepKind {
    /// Step one instruction, following calls.
    Into,
    /// Step one instruction, running calls to completion.
    Over,
    /// Run until the current function returns.
    Out,
}

/// Where to place a breakpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum BreakAt {
    /// An absolute runtime address.
    Addr { addr: u64 },
    /// A symbol name, resolved through [`crate::Symbols`].
    Symbol { name: String },
}

/// Launch parameters for a new debuggee.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LaunchOptions {
    /// Path to the executable.
    pub path: String,
    /// Command-line arguments (excluding `argv[0]`).
    #[serde(default)]
    pub args: Vec<String>,
    /// Working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Extra environment variables.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Why the debuggee stopped.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum StopReason {
    /// The initial stop after launch/attach, before anything executed.
    Started,
    /// A breakpoint was hit.
    Breakpoint {
        /// The breakpoint's runtime address.
        addr: u64,
        /// The breakpoint id.
        id: BreakId,
    },
    /// A single-step completed.
    Step,
    /// A signal was delivered.
    Signal {
        /// Signal number.
        signal: i32,
        /// Signal name, when known.
        name: String,
    },
    /// The process exited normally.
    Exited {
        /// Exit code.
        code: i32,
    },
    /// The process was killed by a signal.
    Killed {
        /// Signal number.
        signal: i32,
    },
}

/// General-purpose registers plus the key control registers.
///
/// `values` carries every register the architecture exposes, keyed by its
/// conventional name (`rax`, `rip`, `eflags`, …), so callers that need more
/// than pc/sp/fp do not need an architecture-specific type.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Registers {
    /// Program counter / instruction pointer.
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer (best effort; 0 when the arch has none).
    pub fp: u64,
    /// All registers, by name.
    pub values: BTreeMap<String, u64>,
}

/// One stop: where, why, and the registers at that point.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stop {
    /// Process id.
    pub pid: u32,
    /// Thread that stopped.
    pub thread: ThreadId,
    /// Why it stopped.
    pub reason: StopReason,
    /// Registers of the stopping thread.
    pub registers: Registers,
}

/// A breakpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Breakpoint {
    /// Session-unique id.
    pub id: BreakId,
    /// Runtime address.
    pub addr: u64,
    /// Whether the trap byte is currently installed.
    pub enabled: bool,
    /// The original instruction bytes replaced by the trap.
    #[serde(skip)]
    pub original: Vec<u8>,
}

/// Session lifecycle state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessState {
    /// No debuggee.
    #[default]
    Idle,
    /// Attached/launched but stopped.
    Stopped,
    /// Running.
    Running,
    /// Exited or detached.
    Exited,
}

/// One stack frame in a backtrace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Frame {
    /// Return address (or the current pc for the innermost frame).
    pub addr: u64,
    /// Function name, when a symbol source is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Snapshot of the session, for `status`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    /// Debuggee pid, if any.
    pub pid: Option<u32>,
    /// Lifecycle state.
    pub state: ProcessState,
    /// Why it last stopped, if stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopReason>,
    /// Installed breakpoints.
    pub breakpoints: Vec<Breakpoint>,
}
