//! Best-effort process signals for interrupting a wedged analysis backend.
//!
//! Only the r2 backend needs this (the native backend is in-process). On
//! non-Unix targets the functions report failure instead of pretending to act.

/// Send `SIGINT` to `pid`, mirroring Ctrl-C: a blocked r2 command unwinds and
/// the pipe produces its response. Returns false when `pid` is 0 or the
/// signal could not be delivered.
///
/// ```no_run
/// use librecurse::signals::interrupt;
/// assert!(!interrupt(0));
/// ```
#[cfg(unix)]
pub fn interrupt(pid: u32) -> bool {
    signal(pid, libc::SIGINT)
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
    signal(pid, libc::SIGKILL)
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

/// Shared Unix delivery path. A pid of 0 is "no known child", never signal
/// it. The signal goes to the process *group* first (the session sets one at
/// spawn) so r2's own children are covered; if that fails the single pid is
/// signalled instead.
#[cfg(unix)]
fn signal(pid: u32, sig: libc::c_int) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: `kill` with a pid/group we spawned; the return value is checked
    // and no pointers are involved.
    unsafe {
        let g = pid as libc::pid_t;
        if libc::kill(-g, sig) == 0 {
            return true;
        }
        libc::kill(g, sig) == 0
    }
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
