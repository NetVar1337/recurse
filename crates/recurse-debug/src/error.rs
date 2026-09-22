//! Error type for the debugger.
//!
//! Every fallible operation returns [`Result`]. The crate never panics on bad
//! input, a failing target, or an unsupported platform — it reports.

use std::fmt;

/// A debugger error.
#[derive(Debug)]
pub enum Error {
    /// An OS-level failure (spawn, wait, memory access, …).
    Io(std::io::Error),
    /// The operation needs a running debuggee and there is none.
    NotRunning,
    /// The debuggee is running; the target must be stopped first.
    NotStopped,
    /// No breakpoint with the given id.
    NoSuchBreakpoint(u64),
    /// The platform or architecture does not support the operation.
    Unsupported(String),
    /// Anything else, with a human-readable message.
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NotRunning => write!(f, "no debuggee is running"),
            Error::NotStopped => write!(f, "the debuggee is running; stop it first"),
            Error::NoSuchBreakpoint(id) => write!(f, "no breakpoint with id {id}"),
            Error::Unsupported(what) => write!(f, "unsupported: {what}"),
            Error::Message(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl Error {
    /// Build a message error from anything printable.
    ///
    /// ```
    /// use recurse_debug::Error;
    /// assert_eq!(Error::msg("boom").to_string(), "boom");
    /// ```
    pub fn msg(message: impl Into<String>) -> Self {
        Error::Message(message.into())
    }
}

/// Debugger result alias.
pub type Result<T> = std::result::Result<T, Error>;
