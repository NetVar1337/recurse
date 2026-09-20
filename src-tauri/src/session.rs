use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

use serde_json::Value;

/// Requests sent from the app thread to the r2 worker thread.
enum Cmd {
    Run {
        cmd: String,
        resp: Sender<Result<Value, String>>,
    },
    Quit,
}

type StartupResult = Result<(), String>;

/// Minimal owned r2pipe transport: spawns `r2 -q0 [args] <path>` and speaks
/// the null-terminated command protocol over the child's stdio.
///
/// We deliberately do not use the `r2pipe` crate here: it hides the child
/// handle, so there is no way to get r2's PID — which the debugger needs to
/// interrupt a blocked command (`dc` waiting on the debuggee) or tear down a
/// wedged session. Owning the [`Child`] gives us the PID and reaping duties.
struct R2PipeProc {
    write: std::process::ChildStdin,
    read: BufReader<std::process::ChildStdout>,
    child: Child,
}

impl R2PipeProc {
    fn spawn(program: &str, args: &[String]) -> Result<Self, String> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        crate::process::configure_command(&mut cmd);
        let mut child = cmd
            // Own process group: lets interrupt/teardown signal the entire
            // tree (r2 + its debuggee + any sandbox wrapper like bwrap)
            // without touching unrelated processes. The group id equals the
            // child's pid on Unix.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn radare2: {e}"))?;

        let stdin = child.stdin.take().ok_or("r2 stdin unavailable")?;
        let mut stdout = child.stdout.take().ok_or("r2 stdout unavailable")?;

        // The protocol opens with a single NUL byte once r2 is ready.
        let mut nul = [0u8; 1];
        stdout
            .read_exact(&mut nul)
            .map_err(|e| format!("r2 did not initialize: {e}"))?;

        Ok(R2PipeProc {
            write: stdin,
            read: BufReader::new(stdout),
            child,
        })
    }

    /// Run one command, returning its raw output (without the trailing NUL).
    fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        self.write
            .write_all(format!("{cmd}\n").as_bytes())
            .map_err(|e| format!("r2 write failed: {e}"))?;
        self.write.flush().ok();
        let mut res: Vec<u8> = Vec::new();
        loop {
            let mut chunk = [0u8; 512];
            let n = self
                .read
                .read(&mut chunk)
                .map_err(|e| format!("r2 read failed: {e}"))?;
            if n == 0 {
                return Err("empty response from radare2".into());
            }
            if let Some(pos) = chunk[..n].iter().position(|&b| b == 0) {
                res.extend_from_slice(&chunk[..pos]);
                break;
            }
            res.extend_from_slice(&chunk[..n]);
            if res.len() > 64 * 1024 * 1024 {
                return Err("response exceeded 64MiB".into());
            }
        }
        String::from_utf8(res).map_err(|e| format!("invalid utf-8 from radare2: {e}"))
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for R2PipeProc {
    fn drop(&mut self) {
        let _ = self.cmd("q!");
        let _ = self.child.wait();
    }
}

/// A long-lived radare2 subprocess driven over a dedicated worker thread.
///
/// The pipe itself is `!Send`, so it is owned by the worker and commands are
/// issued over channels. This handle is therefore `Send + Sync` and safe to
/// keep in Tauri managed state.
pub struct R2Session {
    tx: Sender<Cmd>,
    join: Option<std::thread::JoinHandle<()>>,
    pid: std::sync::Arc<AtomicU32>,
    pub path: PathBuf,
    pub info: Value,
}

impl R2Session {
    /// Spawn r2 and load the binary. Analysis is deferred to
    /// [`R2Session::analyze`] so opening never blocks the UI on a long pass.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::open_with_args(path, vec!["-e".into(), "bin.cache=true".into()])
    }

    /// Spawn r2 with extra command-line arguments (e.g. `-d` to start the
    /// native debugger). Reused by both the analysis session and the debug
    /// session.
    pub fn open_with_args(path: impl Into<PathBuf>, args: Vec<String>) -> Result<Self, String> {
        let path = path.into();
        let mut argv = vec!["r2".to_string(), "-q0".to_string()];
        argv.extend(args);
        argv.push(path.to_string_lossy().into_owned());
        Self::open_argv(argv)
    }

    /// Spawn a full pre-built argv (e.g. an `r2` invocation wrapped by the
    /// sandbox backend) speaking the same `-q0` pipe protocol.
    pub fn open_argv(argv: Vec<String>) -> Result<Self, String> {
        if argv.is_empty() {
            return Err("empty spawn argv".into());
        }
        let worker_argv = argv.clone();
        let (tx, rx) = mpsc::channel::<Cmd>();
        let (start_tx, start_rx) = mpsc::channel::<StartupResult>();
        let pid = std::sync::Arc::new(AtomicU32::new(0));

        let join = std::thread::Builder::new()
            .name("r2-worker".into())
            .spawn({
                let pid = pid.clone();
                move || worker(&worker_argv, rx, start_tx, &pid)
            })
            .map_err(|e| format!("failed to spawn r2 worker thread: {e}"))?;

        // DIAGNOSTIC no-thread probe runs before waiting on startup.
        if std::env::var_os("ZZ_NOTHREAD").is_some() {
            drop(join);
            return Err("zz-diagnostic-exit".into());
        }
        start_rx.recv().map_err(|e| e.to_string())??;

        // The last element is conventionally the target path; keep it for
        // display parity with open_with_args.
        let path = PathBuf::from(argv.last().cloned().unwrap_or_default());

        let mut sess = R2Session {
            tx,
            join: Some(join),
            pid,
            path,
            info: Value::Null,
        };

        sess.info = sess.run("ij")?;
        Ok(sess)
    }

    /// Default analysis pass: `aa` (function discovery) + `aac` (call refs).
    ///
    /// Deliberately NOT `aaa`: on large Rust binaries (youki ~8 MiB) `aaa`
    /// walks every jump table / vtable / type-match pass, takes minutes, and
    /// spams `Limiting jump table at 0x... to 512 cases` warnings while the
    /// UI sits on "analyzing…" with no progress. `aa; aac` returns in
    /// seconds with a usable function list; run `aaa` (or `aaaa`) manually
    /// from the r2 console when deep analysis is worth the wait.
    pub fn analyze(&self) -> Result<Value, String> {
        self.run("aa; aac")
    }

    /// Run an r2 command. JSON output is preferred; plain-text output is
    /// wrapped into a JSON string automatically.
    pub fn run(&self, cmd: &str) -> Result<Value, String> {
        let (resp, rx) = mpsc::channel();
        self.tx
            .send(Cmd::Run {
                cmd: cmd.to_string(),
                resp,
            })
            .map_err(|e| format!("r2 worker unavailable: {e}"))?;
        rx.recv().map_err(|e| e.to_string())?
    }

    /// Convenience for plain-text commands.
    pub fn text(&self, cmd: &str) -> Result<String, String> {
        match self.run(cmd)? {
            Value::String(s) => Ok(s),
            other => Ok(other.to_string()),
        }
    }

    /// PID of the spawned r2 child process, or 0 when unknown/exited.
    pub fn pid(&self) -> u32 {
        self.pid.load(Ordering::SeqCst)
    }

    /// Send SIGINT to the r2 child's process group (r2 + debuggee + sandbox
    /// wrapper). r2 handles this like Ctrl-C in an interactive session: a
    /// blocked debugger command (`dc`) unwinds and the pipe produces its
    /// response. Returns false when no live child is known.
    pub fn interrupt(&self) -> bool {
        crate::process::interrupt_process(self.pid())
    }

    /// Send SIGKILL to the r2 child's process group. Last-resort teardown
    /// when SIGINT does not unblock a wedged command; the broken pipe makes
    /// the worker reply with an error to whoever is waiting.
    pub fn force_kill(&self) -> bool {
        crate::process::terminate_process(self.pid())
    }
}

impl Drop for R2Session {
    fn drop(&mut self) {
        let _ = self.tx.send(Cmd::Quit);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn worker(
    argv: &[String],
    rx: Receiver<Cmd>,
    start_tx: Sender<StartupResult>,
    pid_out: &AtomicU32,
) {
    let Some((program, rest)) = argv.split_first() else {
        let _ = start_tx.send(Err("empty spawn argv".into()));
        return;
    };
    let mut pipe = match R2PipeProc::spawn(program, rest) {
        Ok(p) => p,
        Err(e) => {
            let _ = start_tx.send(Err(e));
            return;
        }
    };
    pid_out.store(pipe.pid(), Ordering::SeqCst);
    let _ = start_tx.send(Ok(()));

    while let Ok(msg) = rx.recv() {
        match msg {
            Cmd::Run { cmd, resp } => {
                // Run the command exactly once; JSON output is preferred and
                // non-JSON output degrades to a JSON string wrapper.
                let result: Result<Value, String> = pipe
                    .cmd(&cmd)
                    .map(|text| serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)))
                    .map_err(|e| e.to_string());
                let _ = resp.send(result);
            }
            Cmd::Quit => break,
        }
    }
    pid_out.store(0, Ordering::SeqCst);
    drop(pipe);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r2_available() -> bool {
        std::process::Command::new("r2")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn open_publishes_pid_and_runs_commands() {
        if !r2_available() {
            eprintln!("skipping: radare2 not on PATH");
            return;
        }
        let sess = R2Session::open("/bin/true").expect("open session");
        assert!(sess.pid() > 0, "worker must publish the r2 child pid");
        assert_eq!(sess.path, PathBuf::from("/bin/true"));
        // Plain-text commands come back wrapped as JSON strings.
        let v = sess.run("f").expect("run f");
        assert!(v.is_string() || v.is_object(), "unexpected: {v}");
        // Info was fetched at open time.
        assert!(sess.info.is_object(), "ij should return an object");
    }

    #[test]
    fn drop_reaps_child_and_clears_pid() {
        if !r2_available() {
            eprintln!("skipping: radare2 not on PATH");
            return;
        }
        let sess = R2Session::open("/bin/true").expect("open session");
        let pid = sess.pid();
        assert!(pid > 0);
        drop(sess);
        // After Drop joins the worker the pid is cleared; the child is reaped.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "r2 child {pid} should be gone after drop"
        );
    }

    #[test]
    fn spawn_failure_is_reported_not_panicked() {
        // r2 exits immediately (before the protocol's initial NUL) when asked
        // to open a missing file. The constructor must surface a clean error
        // — never hang or panic.
        if !r2_available() {
            eprintln!("skipping: radare2 not on PATH");
            return;
        }
        let missing = "/tmp/recurse-test-definitely-missing-binary";
        let _ = std::fs::remove_file(missing);
        match R2Session::open(missing) {
            Err(e) => assert!(!e.is_empty(), "error must be descriptive"),
            Ok(sess) => {
                // Some r2 builds defer the failure; commands must still work
                // without hanging.
                let _ = sess.run("f");
            }
        }
    }
}
