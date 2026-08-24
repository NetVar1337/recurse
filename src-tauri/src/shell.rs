use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde::Serialize;
use tauri::{AppHandle, Emitter};

#[derive(Clone, Serialize)]
pub struct ShellOutput {
    pub id: u32,
    pub data: String,
}

#[derive(Clone, Serialize)]
pub struct ShellExit {
    pub id: u32,
}

#[derive(Clone, Serialize)]
pub struct SpawnedShell {
    pub id: u32,
    pub name: String,
}

struct Shell {
    master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

/// Manages the set of live PTY-backed shell sessions. Each shell owns a
/// reader thread that streams output to the frontend over Tauri events.
pub struct ShellManager {
    shells: Mutex<HashMap<u32, Shell>>,
    next_id: Mutex<u32>,
}

impl Default for ShellManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellManager {
    pub fn new() -> Self {
        Self {
            shells: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    fn alloc_id(&self) -> u32 {
        // Poison-tolerant: id allocation is order-independent, so a poisoned
        // lock (a panicked writer elsewhere) must not take the app down.
        let mut n = self.next_id.lock().unwrap_or_else(PoisonError::into_inner);
        let id = *n;
        *n += 1;
        id
    }

    fn default_shell() -> String {
        #[cfg(unix)]
        {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string())
        }
        #[cfg(windows)]
        {
            std::env::var("COMSPEC")
                .or_else(|_| std::env::var("SHELL"))
                .unwrap_or_else(|_| "cmd.exe".to_string())
        }
        #[cfg(not(any(unix, windows)))]
        {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
        }
    }

    pub fn spawn(&self, app: AppHandle) -> Result<SpawnedShell, String> {
        let id = self.alloc_id();

        let sys = native_pty_system();
        let pair = sys
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;

        let shell = Self::default_shell();
        let mut cmd = CommandBuilder::new(&shell);
        #[cfg(unix)]
        cmd.args(["-l"]);
        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;

        // Stream stdout/stderr to the frontend until the shell exits.
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                        let _ = app.emit("shell-output", ShellOutput { id, data });
                    }
                }
            }
            let _ = app.emit("shell-exit", ShellExit { id });
        });

        let name = Path::new(&shell)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("shell")
            .to_string();

        let mut shells = self.shells.lock().unwrap_or_else(PoisonError::into_inner);
        shells.insert(
            id,
            Shell {
                master: pair.master,
                writer,
                child,
            },
        );
        Ok(SpawnedShell { id, name })
    }

    pub fn write(&self, id: u32, data: &str) -> Result<(), String> {
        let mut shells = self.shells.lock().unwrap_or_else(PoisonError::into_inner);
        let s = shells
            .get_mut(&id)
            .ok_or_else(|| "no such shell".to_string())?;
        s.writer
            .write_all(data.as_bytes())
            .map_err(|e| e.to_string())?;
        s.writer.flush().map_err(|e| e.to_string())
    }

    pub fn resize(&self, id: u32, rows: u16, cols: u16) -> Result<(), String> {
        let shells = self.shells.lock().unwrap_or_else(PoisonError::into_inner);
        let s = shells.get(&id).ok_or_else(|| "no such shell".to_string())?;
        s.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())
    }

    pub fn kill(&self, id: u32) -> Result<(), String> {
        // Remove under the lock, then kill+wait outside it: reaping can take
        // a while and must not stall writes/resizes on other shells.
        let mut s = {
            let mut shells = self.shells.lock().unwrap_or_else(PoisonError::into_inner);
            shells.remove(&id)
        };
        if let Some(s) = s.as_mut() {
            let _ = s.child.kill();
            let _ = s.child.wait();
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<u32> {
        self.shells
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn ids_increase_and_missing_shell_ops_fail_soft() {
        let m = ShellManager::new();
        let a = m.alloc_id();
        let b = m.alloc_id();
        assert_eq!(b, a + 1);
        assert!(m.write(a, "x").is_err());
        assert!(m.resize(a, 1, 1).is_err());
        assert!(m.kill(a).is_ok()); // idempotent
        assert!(m.list().is_empty());
    }
}
