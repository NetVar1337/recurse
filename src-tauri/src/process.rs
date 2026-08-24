use std::process::Command;

/// Configure a Command to run in its own process group / job so
/// interrupt / teardown can signal the whole tree (r2 + debuggee +
/// sandbox wrapper) without touching unrelated processes.
pub fn configure_command(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP (0x200) lets us send CTRL_BREAK_EVENT
        // to the group; CREATE_NO_WINDOW (0x08000000) avoids a console popup.
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

/// Try to interrupt the process group (SIGINT on Unix, CTRL_BREAK / taskkill
/// on Windows). Returns true if a signal was delivered.
pub fn interrupt_process(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        let g = pid as libc::pid_t;
        unsafe {
            if libc::kill(-g, libc::SIGINT) == 0 {
                return true;
            }
            libc::kill(g, libc::SIGINT) == 0
        }
    }
    #[cfg(windows)]
    {
        // Best-effort: ask Windows to terminate the process. `taskkill /T`
        // kills the whole tree, mirroring `kill(-pgid, SIGINT)` on Unix.
        // We use `taskkill` to avoid pulling in `windows-sys`.
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T"])
            .output();
        // Fallback: try direct kill via `taskkill /F` if graceful failed.
        // Return true optimistically — caller will poll `debug_busy`.
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Force-kill the process group (SIGKILL on Unix, taskkill /F on Windows).
pub fn terminate_process(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        let g = pid as libc::pid_t;
        unsafe {
            if libc::kill(-g, libc::SIGKILL) == 0 {
                return true;
            }
            libc::kill(g, libc::SIGKILL) == 0
        }
    }
    #[cfg(windows)]
    {
        let out = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}
