//! Best-effort process signals for interrupting a wedged analysis backend.
//!
//! Only the external engine needs this (the native engine is in-process). On
//! non-Unix targets the functions report failure instead of pretending to act.

#[cfg(unix)]
use nix::sys::signal::{kill, killpg, Signal};
#[cfg(unix)]
use nix::unistd::Pid;

/// Send `SIGINT` to `pid`, mirroring Ctrl-C: a blocked external command
/// unwinds and
/// the pipe produces its response. Returns false when `pid` is 0 or the
/// signal could not be delivered.
///
/// ```no_run
/// use librecurse::signals::interrupt;
/// assert!(!interrupt(0));
/// ```
#[cfg(unix)]
pub fn interrupt(pid: u32) -> bool {
    signal(pid, Signal::SIGINT)
}

/// Send `SIGINT`; always false off Unix.
///
/// ```
/// # #[cfg(not(unix))]
/// # {
/// use librecurse::signals::interrupt;
/// assert!(!interrupt(1234));
/// # }
/// ```
#[cfg(not(unix))]
pub fn interrupt(_pid: u32) -> bool {
    false
}

/// Send `SIGKILL` to `pid`, the last-resort teardown for a backend that
/// ignored [`interrupt`]. Returns false when `pid` is 0 or delivery failed.
///
/// ```no_run
/// use librecurse::signals::terminate;
/// assert!(!terminate(0));
/// ```
#[cfg(unix)]
pub fn terminate(pid: u32) -> bool {
    signal(pid, Signal::SIGKILL)
}

/// Send `SIGKILL`; always false off Unix.
///
/// ```
/// # #[cfg(not(unix))]
/// # {
/// use librecurse::signals::terminate;
/// assert!(!terminate(1234));
/// # }
/// ```
#[cfg(not(unix))]
pub fn terminate(_pid: u32) -> bool {
    false
}

/// Shared Unix delivery path, implemented with `nix` so no `unsafe` is needed
/// in this crate. A pid of 0 is "no known child", never signal it. The signal
/// goes to the process *group* first (the session sets one at spawn) so the
/// engine's
/// own children are covered; if that fails the single pid is signalled
/// instead.
#[cfg(unix)]
fn signal(pid: u32, sig: Signal) -> bool {
    if pid == 0 {
        return false;
    }
    let group = Pid::from_raw(pid as i32);
    killpg(group, sig).is_ok() || kill(group, sig).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn zero_pid_is_never_signalled() {
        assert!(!interrupt(0));
        assert!(!terminate(0));
    }
}
