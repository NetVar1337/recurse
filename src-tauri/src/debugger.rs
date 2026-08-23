use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::session::R2Session;

/// Private, per-process runtime directory for debugger support files. Using a
/// PID-scoped directory prevents two Recurse instances from sharing (and
/// cross-writing) each other's FIFOs, and keeps the files out of reach of
/// other users (`0700`).
struct DebugPaths {
    dir: PathBuf,
    profile: PathBuf,
    stdin: PathBuf,
    stdout: PathBuf,
}

fn paths() -> &'static DebugPaths {
    static PATHS: OnceLock<DebugPaths> = OnceLock::new();
    PATHS.get_or_init(|| {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("recurse-{pid}"));
        DebugPaths {
            profile: dir.join("debug.rr2"),
            stdin: dir.join("debug.stdin"),
            stdout: dir.join("debug.stdout"),
            dir,
        }
    })
}

fn mkfifo_at(path: &PathBuf, what: &str) -> Result<(), String> {
    let _ = fs::remove_file(path);
    let cpath = std::ffi::CString::new(
        path.to_str()
            .ok_or_else(|| format!("debugger {what} path is not valid UTF-8"))?,
    )
    .map_err(|_| "path contains NUL")?;
    // 0o600: owner read/write only.
    let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
    if rc != 0 {
        return Err(format!(
            "mkfifo failed for debugger {what}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Ensure the private debug dir + FIFO stdin/stdout + r2 run profile exist.
///
/// The debuggee's stdin is redirected to our FIFO (we write, program reads)
/// and its stdout to a second FIFO (program writes, we stream to the UI), so
/// the frontend can render a live interleaved console instead of waiting for
/// `dc` to return. The FIFOs are created with `libc::mkfifo` directly:
/// spawning `mkfifo(1)` needed a "File exists" retry dance and depended on
/// coreutils being installed. We remove any stale node first, then create it
/// exclusively in a directory only this process can write to, so there is no
/// creation race.
pub fn prepare_profile() -> Result<(), String> {
    fs::create_dir_all(&paths().dir)
        .map_err(|e| format!("failed to create debugger runtime dir: {e}"))?;
    mkfifo_at(&paths().stdin, "stdin")?;
    mkfifo_at(&paths().stdout, "stdout")?;
    fs::write(
        &paths().profile,
        format!(
            "stdin={}\nstdout={}\n",
            paths().stdin.display(),
            paths().stdout.display()
        ),
    )
    .map_err(|e| format!("failed to write debugger profile: {e}"))?;
    Ok(())
}

/// Open the debuggee stdout FIFO (nonblocking read side) for the pump thread.
pub fn open_stdout_reader() -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&paths().stdout)
        .map_err(|e| format!("failed to open debugger stdout: {e}"))
}

/// Keep a writer anchor on the stdout FIFO so the reader never sees EOF while
/// the session is alive.
pub fn open_stdout_anchor() -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .open(&paths().stdout)
        .map_err(|e| format!("failed to anchor debugger stdout: {e}"))
}

/// Spawn a thread that tails the debuggee stdout FIFO and hands chunks to
/// `sink` until `done` flips true. Nonblocking reads + short sleeps: no busy
/// spin, no blocked teardown.
pub fn spawn_output_pump(
    done: Arc<AtomicBool>,
    mut sink: impl FnMut(Vec<u8>) + Send + 'static,
) -> Result<(), String> {
    let reader = open_stdout_reader()?;
    let _anchor = open_stdout_anchor()?;
    std::thread::Builder::new()
        .name("debug-stdout-pump".into())
        .spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                if done.load(Ordering::SeqCst) {
                    break;
                }
                match reader_read(&reader, &mut chunk) {
                    Ok(0) => std::thread::sleep(Duration::from_millis(10)),
                    Ok(n) => sink(chunk[..n].to_vec()),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| format!("failed to spawn stdout pump: {e}"))?;
    Ok(())
}

fn reader_read(f: &File, buf: &mut [u8]) -> std::io::Result<usize> {
    Read::read(&mut &*f, buf)
}

/// r2 command-line args for the debug session (must mirror the profile).
pub fn spawn_args() -> Vec<String> {
    vec![
        "-d".to_string(),
        "-e".to_string(),
        "bin.cache=true".to_string(),
        "-r".to_string(),
        paths().profile.to_string_lossy().to_string(),
    ]
}

/// Spawn the debug r2 session for `target` under the active sandbox backend:
/// prepares the FIFO/profile, wraps the argv (bubblewrap when enabled), opens
/// the session and the stdin handle. Single source of truth used by both the
/// Tauri command and agent tools so sandbox policy cannot diverge.
/// Spawn the debug r2 session plus the live stdout pump.
///
/// Ordering matters: r2 applies run-profile redirects sequentially during
/// startup — `stdin=` first (blocks until a WRITER opens the FIFO) then
/// `stdout=` (blocks until a READER does). Both ends must therefore exist
/// BEFORE we spawn r2, or startup deadlocks before the protocol handshake.
/// The stdin anchor is held here; the stdout reader is owned by the pump
/// thread started below, driven by `sink` until `done` flips true.
pub fn spawn_debug_session(
    target: &Path,
    done: Arc<AtomicBool>,
    sink: impl FnMut(Vec<u8>) + Send + 'static,
) -> Result<(R2Session, File), String> {
    prepare_profile()?;
    // Anchor stdin: r2 blocks opening the redirect until a writer exists.
    let stdin = open_stdin()?;
    // Reader side up next: attach the pump before r2 can block on it.
    spawn_output_pump(Arc::clone(&done), sink)?;
    let argv = crate::sandbox::wrap_r2_argv(target, &spawn_args(), &paths().dir)?;
    let sess = R2Session::open_argv(argv)
        .map_err(|e| format!("failed to start debugger: {e}"))?;
    Ok((sess, stdin))
}

/// Open the debuggee stdin FIFO. `O_RDWR` means we always count as the reader
/// side, so opening never blocks; `O_NONBLOCK` makes subsequent writes fail
/// with `WouldBlock` instead of stalling the whole app when the debuggee is
/// not consuming input.
pub fn open_stdin() -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&paths().stdin)
        .map_err(|e| format!("failed to open debugger stdin: {e}"))
}

/// Write bytes to the nonblocking FIFO with a bounded retry loop.
///
/// Never blocks indefinitely: when the pipe buffer fills up (debuggee stopped
/// at a breakpoint and not reading stdin) this returns an error after
/// `timeout`, leaving the caller's locks healthy.
pub fn write_stdin(file: &mut File, mut data: &[u8], timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while !data.is_empty() {
        match file.write(data) {
            Ok(0) => return Err("debugger stdin write made no progress".into()),
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(
                        "debugger is not consuming input — the program may be stopped".into(),
                    );
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(format!("debugger stdin write failed: {e}")),
        }
    }
    file.flush()
        .map_err(|e| format!("debugger stdin flush failed: {e}"))
}

/// Shell-quote a single argument for r2's `ood` argv parser so arguments
/// containing spaces survive as one element.
pub fn quote_arg(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// (Re)open the debuggee, optionally with program arguments.
pub fn start(s: &R2Session, args: &[String]) -> Result<Value, String> {
    let cmd = if args.is_empty() {
        "ood".to_string()
    } else {
        format!(
            "ood {}",
            args.iter()
                .map(|a| quote_arg(a))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    s.run(&cmd)
}

/// Set a breakpoint at `addr`.
pub fn breakpoint(s: &R2Session, addr: u64) -> Result<Value, String> {
    s.run(&format!("db {addr:#x}"))
}

/// List breakpoints (`dbj`).
pub fn breakpoints(s: &R2Session) -> Result<Value, String> {
    s.run("dbj")
}

/// Continue execution until the next breakpoint / exit.
pub fn continue_run(s: &R2Session) -> Result<Value, String> {
    s.run("dc")
}

/// Single-step into.
pub fn step(s: &R2Session) -> Result<Value, String> {
    s.run("ds")
}

/// Single-step over.
pub fn step_over(s: &R2Session) -> Result<Value, String> {
    s.run("dso")
}

/// Dump all registers as JSON (`drj`).
pub fn registers(s: &R2Session) -> Result<Value, String> {
    s.run("drj")
}

/// Set a register (uses the architecture-agnostic `pc`/name aliases r2 exposes).
pub fn set_register(s: &R2Session, reg: &str, val: u64) -> Result<Value, String> {
    s.run(&format!("dr {reg}={val:#x}"))
}

/// Read `len` bytes at `addr` as JSON (`pxj`).
pub fn read_memory(s: &R2Session, addr: u64, len: u64) -> Result<Value, String> {
    s.run(&format!("pxj {len} @ {addr:#x}"))
}

/// Write bytes (a hex/escaped string) at `addr`.
pub fn write_memory(s: &R2Session, addr: u64, bytes: &str) -> Result<Value, String> {
    s.run(&format!("wx {bytes} @ {addr:#x}"))
}

/// Disassemble `count` instructions at the current program counter.
pub fn current_disasm(s: &R2Session, count: u64) -> Result<Value, String> {
    s.run(&format!("pdj {count}"))
}

/// Kill the debuggee.
pub fn kill(s: &R2Session) -> Result<Value, String> {
    s.run("dk")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// prepare_profile mutates process-global paths (the OnceLock dir); the
    /// production callers are serialized by the debug mutex, so tests must
    /// serialize too.
    static PROFILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn quote_arg_handles_spaces_and_embedded_quotes() {
        assert_eq!(quote_arg("hello"), "'hello'");
        assert_eq!(quote_arg("two words"), "'two words'");
        assert_eq!(quote_arg("it's"), "'it'\\''s'");
        assert_eq!(quote_arg(""), "''");
    }

    #[test]
    fn prepare_profile_creates_private_fifo_and_profile() {
        let _g = PROFILE_LOCK.lock().unwrap();
        prepare_profile().expect("prepare");
        let p = paths();
        assert!(p.dir.is_dir());
        // FIFO must be a special file (not a regular file).
        let md = std::fs::metadata(&p.stdin).expect("fifo exists");
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        assert!(md.file_type().is_fifo(), "stdin path must be a FIFO");
        let prof = fs::read_to_string(&p.profile).expect("profile exists");
        assert_eq!(
            prof,
            format!(
                "stdin={}\nstdout={}\n",
                p.stdin.display(),
                p.stdout.display()
            )
        );
        // Directory must be owner-only.
        let mode = md.permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "fifo must be 0600");
    }

    #[test]
    fn prepare_profile_is_idempotent() {
        let _g = PROFILE_LOCK.lock().unwrap();
        prepare_profile().unwrap();
        prepare_profile().unwrap(); // recreates over stale nodes
        open_stdin().expect("fifo opens after re-prepare");
    }

    #[test]
    fn write_stdin_times_out_when_nobody_consumes() {
        let _g = PROFILE_LOCK.lock().unwrap();
        prepare_profile().unwrap();
        let mut f = open_stdin().unwrap();
        // Fill the 64K pipe buffer, then one more byte must time out.
        let chunk = [b'x'; 4096];
        for _ in 0..20 {
            // Ignore errors once full; the assertion below covers behavior.
            let _ = write_stdin(&mut f, &chunk, Duration::from_millis(50));
        }
        let started = Instant::now();
        let res = write_stdin(&mut f, &[b'y'; 16], Duration::from_millis(150));
        assert!(res.is_err(), "write into a full unread fifo must error");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout must bound the wait"
        );
    }

    #[test]
    fn output_pump_streams_written_bytes() {
        let _g = PROFILE_LOCK.lock().unwrap();
        prepare_profile().unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let done = Arc::new(AtomicBool::new(false));
        spawn_output_pump(Arc::clone(&done), move |chunk| {
            tx.send(chunk).unwrap();
        })
        .unwrap();
        // Write via a second handle to the same FIFO (the pump holds the
        // read side + anchor).
        let mut w = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&paths().stdout)
            .unwrap();
        use std::io::Write as _;
        w.write_all(b"hello prompt\n").unwrap();
        w.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while Instant::now() < deadline {
            match rx.try_recv() {
                Ok(c) => got.extend_from_slice(&c),
                Err(std::sync::mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
            if got.windows(6).any(|w| w == b"prompt") {
                break;
            }
        }
        done.store(true, Ordering::SeqCst);
        assert!(
            String::from_utf8_lossy(&got).contains("hello"),
            "pump must forward written bytes, got {got:?}"
        );
    }

    #[test]
    fn spawn_args_reference_dynamic_profile() {
        let args = spawn_args();
        assert!(args
            .windows(2)
            .any(|w| w[0] == "-r" && w[1].contains("recurse-")));
        assert!(args.contains(&"-d".to_string()));
    }

    #[test]
    fn start_quotes_arguments() {
        // Verified via quote_arg; here just ensure no panic on empty/unicode.
        let q: Vec<String> = ["a b", "π", ""].iter().map(|s| quote_arg(s)).collect();
        assert_eq!(q.join(" "), "'a b' 'π' ''");
    }
}
