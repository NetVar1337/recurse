//! Eval suite: graded crackme fixtures proving what Recurse's toolchain can
//! and cannot solve — deterministically, without an LLM.
//!
//! Each eval drives the *same primitives the agent uses* (`R2Session`,
//! `debugger::*`, FIFO stdin) against a compiled fixture:
//!   1. recon via r2 (strings/imports),
//!   2. candidate keys through the debuggee via continue+stdin — the oracle
//!      primitive every agentic crack relies on,
//!   3. per-tier outcome assertions.
//!
//! Tiers: easy (static literal) · medium (per-char arithmetic) ·
//! hard (rolling XOR) · impossible (OS entropy — must be *recognized*, not
//! chased). The optional live-LLM protocol is documented in
//! `fixtures/evals/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use recurse_lib::session::R2Session;

const EASY_KEY: &str = "RECURSE{plaintext_rookie}";
const MEDIUM_KEY: &str = "szqWtyvS";

/// All evals share one process-global FIFO; prepare_profile() swaps the node,
/// so tests must run serialized (production serializes via the debug mutex).
static EVAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tool_available(bin: &str) -> bool {
    let flag = if bin == "r2" { "-v" } else { "--version" };
    Command::new(bin)
        .arg(flag)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn compile(name: &str) -> Option<PathBuf> {
    if !tool_available("r2") || !tool_available("cc") {
        return None;
    }
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("fixtures/evals/{name}.c"));
    let out =
        std::env::temp_dir().join(format!("recurse-eval-{name}-{}", std::process::id()));
    let status = Command::new("cc")
        .args(["-O0", "-g", "-o"])
        .arg(&out)
        .arg(&src)
        .status()
        .ok()?;
    if status.success() {
        Some(out)
    } else {
        None
    }
}

/// Anchors for both FIFO ends while oracle runs are live. r2 applies the run
/// profile's redirects sequentially during startup — `stdin=` blocks until a
/// writer opens the FIFO, `stdout=` until a reader does — so both ends must
/// exist before the debug session spawns, or startup deadlocks (see
/// `debugger::spawn_debug_session`, whose ordering this mirrors). The
/// `O_RDWR` handles never block on open and keep both sides anchored; the
/// stdout handle doubles as the console drain.
struct DebugIo {
    _stdin: File,
    _stdout: File,
}

/// Prepare the process-global debug FIFOs and return anchored handles,
/// mirroring what `debug_start_impl` sets up for app sessions.
fn prep_io() -> Result<DebugIo, String> {
    recurse_lib::debugger::prepare_profile()?;
    let dir = std::env::temp_dir().join(format!("recurse-{}", std::process::id()));
    let open_nb = |name: &str| -> Result<File, String> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(dir.join(format!("debug.{name}")))
            .map_err(|e| e.to_string())
    };
    Ok(DebugIo {
        _stdin: open_nb("stdin")?,
        _stdout: open_nb("stdout")?,
    })
}

/// Oracle primitive: run the crackme under the sandboxed debugger, feed
/// `input`, and return what the program reported — drained live from the
/// stdout FIFO the profile redirects it to (program output does NOT ride the
/// r2 pipe), plus whatever `dc` itself returns. Bounded: a wedged continue is
/// interrupted, then killed, instead of hanging the suite and orphaning r2.
fn oracle(binary: &std::path::Path, input: &str, io: &DebugIo) -> String {
    let argv = recurse_lib::sandbox::wrap_r2_argv(
        binary,
        &recurse_lib::debugger::spawn_args(),
        &std::env::temp_dir(),
    )
    .expect("argv");
    // Arc so the blocking `dc` can own a handle while we keep cleanup duty.
    let sess = std::sync::Arc::new(R2Session::open_argv(argv).expect("debug session"));
    sess.run("ood").expect("ood");

    let dc_sess = std::sync::Arc::clone(&sess);
    let (dc_tx, dc_rx) = std::sync::mpsc::channel();
    let dc = std::thread::spawn(move || {
        let _ = dc_tx.send(dc_sess.run("dc"));
    });
    std::thread::sleep(Duration::from_millis(400));
    (&io._stdin)
        .write_all(format!("{input}\n").as_bytes())
        .and_then(|_| (&io._stdin).flush())
        .expect("fifo write");

    // Poll for dc's result while draining the console FIFO.
    let mut reader = io._stdout.try_clone().expect("stdout clone");
    let mut console = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let outcome = loop {
        if let Ok(res) = dc_rx.try_recv() {
            break Some(res);
        }
        let mut chunk = [0u8; 4096];
        match reader.read(&mut chunk) {
            Ok(0) => {}
            Ok(n) => console.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            sess.interrupt();
            match dc_rx.recv_timeout(Duration::from_secs(3)) {
                Ok(res) => break Some(res),
                Err(_) => {
                    sess.force_kill();
                    break None;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    dc.join().ok();

    // Final drain: the child's writes complete before exit, but the loop may
    // have observed dc's result before reading the last buffered chunk.
    let flush_deadline = Instant::now() + Duration::from_millis(250);
    loop {
        let mut chunk = [0u8; 4096];
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => console.extend_from_slice(&chunk[..n]),
        }
        if Instant::now() >= flush_deadline {
            break;
        }
    }

    let mut report = format!("console: {}", String::from_utf8_lossy(&console));
    match outcome {
        Some(Ok(serde_json::Value::String(s))) => report.push_str(&format!("dc: {s}")),
        Some(Ok(other)) => report.push_str(&format!("dc: {other}")),
        Some(Err(e)) => report.push_str(&format!("dc error: {e}")),
        None => report.push_str("ORACLE TIMEOUT"),
    }
    report
}

#[test]
fn eval_easy_static_literal_is_crackable_by_strings_plus_oracle() {
    let _g = EVAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bin) = compile("easy_strcmp") else {
        eprintln!("skip: r2/cc unavailable");
        return;
    };
    let io = prep_io().unwrap();

    // Static recon: the flag is visible to the strings tool.
    let recon = R2Session::open(&bin).unwrap();
    assert!(recon.run("izzj").unwrap().to_string().contains(EASY_KEY));

    assert!(oracle(&bin, "wrong-key", &io).contains("denied"));
    assert!(oracle(&bin, EASY_KEY, &io).contains("ACCESS GRANTED"));
}

#[test]
fn eval_medium_arithmetic_transform_crackable_via_derived_key_oracle() {
    let _g = EVAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bin) = compile("medium_transform") else {
        eprintln!("skip: r2/cc unavailable");
        return;
    };
    let io = prep_io().unwrap();

    // The transform hides the key from static strings…
    let recon = R2Session::open(&bin).unwrap();
    assert!(!recon.run("izzj").unwrap().to_string().contains(MEDIUM_KEY));

    // …but a derived key passes the oracle while garbage is denied.
    assert!(oracle(&bin, "aaaaaaaa", &io).contains("denied"));
    assert!(oracle(&bin, MEDIUM_KEY, &io).contains("ACCESS GRANTED"));
}

#[test]
fn eval_hard_rolling_xor_crackable_via_solver_plus_oracle() {
    let enc = [
        0x3du8, 0x25, 0x6f, 0x33, 0x71, 0x2a, 0x5d, 0x24, 0x63, 0x39, 0x7a, 0x21,
    ];
    // Stand-in for the agent's analysis: invert the rolling transform.
    let mut prev = 0x42u8;
    let mut solved = String::new();
    for (i, e) in enc.iter().enumerate() {
        let c = e.wrapping_sub(i as u8) ^ prev;
        solved.push(c as char);
        prev = *e;
    }

    let _g = EVAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bin) = compile("hard_rolling") else {
        eprintln!("skip: r2/cc unavailable");
        return;
    };
    let io = prep_io().unwrap();
    assert!(
        oracle(&bin, solved.trim_end(), &io).contains("ACCESS GRANTED"),
        "solver output must pass the oracle"
    );
    assert!(oracle(&bin, "wrong", &io).contains("denied"));
}

#[test]
fn eval_impossible_entropy_target_is_recognized_not_chased() {
    let _g = EVAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bin) = compile("impossible_random") else {
        eprintln!("skip: r2/cc unavailable");
        return;
    };
    let io = prep_io().unwrap();

    // Recon must surface the entropy dependency: the honest "cannot crack"
    // signal an agent should report instead of brute-forcing forever.
    let recon = R2Session::open(&bin).unwrap();
    let hay = format!("{} {}", recon.run("ii").unwrap(), recon.run("iz").unwrap());
    assert!(
        hay.to_lowercase().contains("urandom"),
        "entropy source must be discoverable: {hay}"
    );
    // And no candidate can ever pass the oracle.
    assert!(oracle(&bin, "anything", &io).contains("denied"));
}
