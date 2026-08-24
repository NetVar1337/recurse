// Integration tests may freely unwrap/expect/panic — failure IS the signal.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! End-to-end debugger tests against real radare2.
//!
//! These tests drive the exact production command implementations
//! (`open_binary_impl`, `debug_start_impl`, `execute_debug_command`,
//! `debug_stop_impl`, `debug_stdin_impl`) over a compiled fixture binary,
//! asserting both functional behavior (breakpoints hit, stdin delivered) and
//! the concurrency contract (fail-fast gating, interrupt of a blocked
//! continue, teardown under load).
//!
//! Skipped gracefully (with a note) when `r2` or a C compiler is missing so
//! the suite stays runnable on minimal machines.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use recurse_lib::commands;
use recurse_lib::session::R2Session;

const WAIT: Duration = Duration::from_secs(15);
const FAST: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CRACKME_C: &str = r#"
#include <stdio.h>
int secret(int x) { return x * 3 + 1; }
int main(void) {
    int v = secret(5);
    printf("value=%d\n", v);
    return 0;
}
"#;

/// Reads one line from stdin before exiting: a deterministic way to keep a
/// `dc` blocked forever until we choose to release it.
const WAITER_C: &str = r#"
#include <stdio.h>
int main(void) {
    char buf[64];
    printf("waiting\n");
    fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    printf("got:%s", buf);
    return 0;
}
"#;

fn tool_available(bin: &str) -> bool {
    // r2 only supports `-v`; --version errors on every radare2 build.
    let flag = if bin == "r2" { "-v" } else { "--version" };
    std::process::Command::new(bin)
        .arg(flag)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Compile each fixture exactly once per test-binary process: tests run in
/// parallel threads and concurrent cc/link invocations on the same output
/// path corrupt each other.
fn fixture(name: &str, src: &'static str) -> Option<PathBuf> {
    use std::sync::OnceLock;
    static CRACKME: OnceLock<Option<PathBuf>> = OnceLock::new();
    static WAITER: OnceLock<Option<PathBuf>> = OnceLock::new();
    match name {
        "crackme" => CRACKME.get_or_init(|| compile("crackme", src)).clone(),
        _ => WAITER.get_or_init(|| compile("waiter", src)).clone(),
    }
}

fn compile(name: &str, src: &str) -> Option<PathBuf> {
    if !tool_available("r2") || !tool_available("cc") {
        return None;
    }
    let out = std::env::temp_dir().join(format!("recurse-e2e-{name}-{}", std::process::id()));
    let cpath = out.with_extension("c");
    std::fs::write(&cpath, src).ok()?;
    let status = std::process::Command::new("cc")
        .args(["-O0", "-g", "-o"])
        .arg(&out)
        .arg(&cpath)
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// All debugger-lifecycle tests share the process-global FIFO/profile paths
/// (`debugger::paths()` is a OnceLock singleton). Production serializes
/// access through the debug mutex; tests replicate that by holding this lock
/// for the whole test, preventing one test's `prepare_profile` from swapping
/// the FIFO node out from under another test's open fd.
static DBG_LOCK: Mutex<()> = Mutex::new(());

struct Harness {
    state: recurse_lib::AppState,
    _guard: std::sync::MutexGuard<'static, ()>,
}

/// Build the exact production state container. All fields are public, so the
/// e2e suite constructs it without a Tauri runtime — the same object the
/// commands operate on in the running app.
fn harness() -> Harness {
    Harness {
        state: recurse_lib::AppState {
            session: Arc::new(Mutex::new(None)),
            debug: Arc::new(Mutex::new(None)),
            debug_stdin: Arc::new(Mutex::new(None)),
            debug_busy: Arc::new(AtomicBool::new(false)),
            debug_pid: Arc::new(AtomicU32::new(0)),
            debug_output_done: Arc::new(AtomicBool::new(false)),
            debug_output: Arc::new(Mutex::new(Vec::new())),
            agent: Arc::new(Mutex::new(recurse_lib::agent::Agent::new())),
            llm: Mutex::new(recurse_lib::agent::LlmConfig {
                endpoint: "http://127.0.0.1:9".into(),
                api_key: None,
                model: "e2e".into(),
            }),
            models: Mutex::new(None),
            project: Mutex::new(None),
            current_session: Mutex::new(None),
            shell: recurse_lib::shell::ShellManager::new(),
        },
        _guard: DBG_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
    }
}

impl Harness {
    fn debug(&self) -> Arc<Mutex<Option<R2Session>>> {
        self.state.debug.clone()
    }
    fn busy(&self) -> Arc<AtomicBool> {
        self.state.debug_busy.clone()
    }

    /// Run a debug command through the production gate.
    fn cmd(&self, c: &str) -> Result<serde_json::Value, String> {
        commands::execute_debug_command(self.debug(), self.busy(), c.to_string())
    }

    /// Run a debug command on another thread (simulates the blocking pool).
    fn cmd_async(&self, c: &str) -> std::thread::JoinHandle<Result<serde_json::Value, String>> {
        let (d, b, c) = (self.debug(), self.busy(), c.to_string());
        std::thread::spawn(move || commands::execute_debug_command(d, b, c))
    }

    fn wait_busy(&self, want: bool) {
        let deadline = Instant::now() + WAIT;
        while self.state.debug_busy.load(Ordering::SeqCst) != want {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for busy={want}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn registers(&self) -> serde_json::Value {
        let guard = self.state.debug.lock().unwrap_or_else(|e| e.into_inner());
        let sess = guard.as_ref().expect("debug session present");
        recurse_lib::debugger::registers(sess).expect("drj works")
    }
}

// ---------------------------------------------------------------------------
// Analysis lifecycle e2e
// ---------------------------------------------------------------------------

#[test]
fn open_binary_and_analysis_pipeline() {
    let Some(binary) = fixture("crackme", CRACKME_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    let _summary =
        commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).expect("open_binary");

    // Production flow runs `aaa` right after open; do the same, then counts
    // must be non-trivial.
    {
        let guard = h.state.session.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .expect("analysis session present")
            .analyze()
            .expect("aaa completes");
    }
    let summary = {
        let guard = h.state.session.lock().unwrap_or_else(|e| e.into_inner());
        recurse_lib::engine::summary(guard.as_ref().expect("analysis session present"))
    };
    assert!(
        summary["function_count"].as_u64().unwrap_or(0) >= 1,
        "functions found after analysis: {summary}"
    );

    // Engine queries flow through the same session mutex as production.
    funcs_strings_imports(&h);
}

fn funcs_strings_imports(h: &Harness) {
    let guard = h.state.session.lock().unwrap_or_else(|e| e.into_inner());
    let sess = guard.as_ref().expect("analysis session present");
    let f = recurse_lib::engine::functions(sess).expect("aflj");
    assert!(f.is_array());
    let i = recurse_lib::engine::imports(sess).expect("iij");
    assert!(i.is_array() || i.is_null() || i.is_object());
}

#[test]
fn open_missing_binary_fails_cleanly() {
    if !tool_available("r2") {
        eprintln!("skipping: r2 unavailable");
        return;
    }
    let h = harness();
    let missing = "/tmp/recurse-e2e-nope-does-not-exist";
    // Either construction fails or later use fails — but it must never hang.
    if let Err(e) = commands::open_binary_impl(missing.into(), &h.state) {
        assert!(!e.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Debug lifecycle e2e
// ---------------------------------------------------------------------------

#[test]
fn debug_start_inspect_stop_clean() {
    let Some(binary) = fixture("crackme", CRACKME_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();

    commands::debug_start_impl(&h.state, None).expect("debug start");

    // Inspection commands work while stopped.
    let regs = h.cmd("drj").expect("registers");
    assert!(regs.is_object(), "drj should be an object: {regs}");
    let dis = h.cmd("pdj 8").expect("disasm");
    assert!(dis.is_array());

    // Idempotent start must not replace the session.
    commands::debug_start_impl(&h.state, None).expect("second start is a no-op");

    commands::debug_stop_impl(&h.state).expect("stop");
    assert!(h.cmd("drj").is_err(), "commands fail after stop");
}

#[test]
fn breakpoint_hit_flow_end_to_end() {
    let Some(binary) = fixture("crackme", CRACKME_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();

    let pc_before = pc_of(&h.registers());
    assert_ne!(pc_before, u64::MAX, "pc readable before continue");

    // Breakpoint on main (symbol from symtab; -O0 -g keeps it).
    h.cmd("db main").expect("set bp");
    let bps = h.cmd("dbj").expect("list bps");
    assert_eq!(bps.as_array().map(|a| a.len()), Some(1), "{bps}");

    // Continue runs and stops at the breakpoint; dc returns only then.
    let res = h.cmd_async("dc").expect_spawn();
    let out = res.join_with_deadline(WAIT).expect("dc returns at bp");
    assert!(out.is_ok(), "dc errored: {out:?}");

    h.wait_busy(false);
    let regs = h.registers();
    let pc_after = pc_of(&regs);
    assert_ne!(pc_before, pc_after, "pc advanced to breakpoint");

    // The stop address equals the enabled breakpoint's address.
    let bps = h.cmd("dbj").unwrap();
    let bp_addr = bps[0]["addr"].as_u64();
    assert_eq!(Some(pc_after), bp_addr, "stopped exactly on the bp");

    // Remove bp and finish the program.
    h.cmd("db -main").unwrap();
    let _ = h.cmd_async("dc").join_with_deadline(WAIT); // process exits

    commands::debug_stop_impl(&h.state).unwrap();
}

#[test]
fn double_continue_is_rejected_not_queued() {
    let Some(binary) = fixture("waiter", WAITER_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();

    let first = h.cmd_async("dc");
    first.assert_busy_within(&h, Duration::from_secs(5));
    let second = h.cmd_async("dc");
    let r = second.join_with_deadline(FAST);
    match r.expect("second dc answered fast") {
        Err(e) => assert!(e.contains("already running"), "{e}"),
        Ok(v) => panic!("second dc unexpectedly succeeded: {v:?}"),
    }
    // First dc still running; clean up.
    commands::debug_stop_impl(&h.state).unwrap();
    let _ = first.join_with_deadline(WAIT);
}

// ---------------------------------------------------------------------------
// Race-condition regressions — the reason this suite exists
// ---------------------------------------------------------------------------

/// A continue blocked on debuggee input must not swallow other commands:
/// inspections fail fast with "running" instead of queueing behind it.
#[test]
fn inspection_fails_fast_while_continue_blocks() {
    let Some(binary) = fixture("waiter", WAITER_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();

    let dc = h.cmd_async("dc");
    dc.assert_busy_within(&h, Duration::from_secs(5));

    let started = Instant::now();
    let probe = h.cmd_async("db 0x401000");
    let r = probe.join_with_deadline(FAST);
    let elapsed = started.elapsed();
    match r.expect("probe answered without hanging") {
        Err(e) => assert!(e.contains("running"), "{e}"),
        Ok(v) => panic!("inspection ran during continue: {v:?}"),
    }
    assert!(
        elapsed < FAST,
        "fail-fast must be immediate, took {elapsed:?}"
    );

    commands::debug_stop_impl(&h.state).unwrap();
    let _ = dc.join_with_deadline(WAIT);
}

/// The old deadlock: Stop used to refuse while `dc` was blocked. It must now
/// interrupt the continue, tear everything down, and stay responsive.
#[test]
fn stop_works_while_continue_is_blocked_forever() {
    let Some(binary) = fixture("waiter", WAITER_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();

    let dc = h.cmd_async("dc"); // blocks on stdin read forever
    dc.assert_busy_within(&h, Duration::from_secs(5));

    let started = Instant::now();
    commands::debug_stop_impl(&h.state)
        .expect("stop must interrupt the blocked continue, not refuse");
    assert!(
        started.elapsed() < WAIT,
        "stop took too long: {:?}",
        started.elapsed()
    );

    // Session gone; pending dc resolved with an error (killed pipe).
    assert!(h
        .debug()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_none());
    let r = dc.join_with_deadline(WAIT);
    assert!(r.is_some(), "blocked dc thread must terminate after stop");
    if let Some(Err(_)) = r {
        // expected: pipe broke when r2 was killed
    }
    assert_eq!(
        h.state.debug_pid.load(Ordering::SeqCst),
        0,
        "pid cleared on teardown"
    );
}

/// Feeding the FIFO while a continue waits must unblock it — the designed
/// interactive flow — with the program's output coming back on `dc`.
#[test]
fn stdin_write_unblocks_continue_and_delivers_data() {
    let Some(binary) = fixture("waiter", WAITER_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();

    let dc = h.cmd_async("dc");
    dc.assert_busy_within(&h, Duration::from_secs(5));

    commands::debug_stdin_impl(&h.state, "hello\n").expect("fifo write");

    let out = dc.join_result(WAIT);
    // Program output no longer rides the r2 pipe (stdout= redirect sends it
    // to the console FIFO); the key assertion is that continue RETURNED.
    match out {
        Ok(_) => {}
        Err(e) => panic!("continue failed after stdin write: {e}"),
    }
    h.wait_busy(false);

    // The echoed input must have been streamed into the console buffer.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let buf = String::from_utf8_lossy(
            &h.state
                .debug_output
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
        .into_owned();
        if buf.contains("got:hello") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "console buffer missing echo, got: {buf:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    commands::debug_stop_impl(&h.state).unwrap();
}

/// Opening a new binary while a continue blocks must succeed quickly —
/// previously it deadlocked on the debug mutex forever.
#[test]
fn open_binary_tears_down_blocked_debugger() {
    let Some(waiter) = fixture("waiter", WAITER_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let Some(crackme) = fixture("crackme", CRACKME_C) else {
        eprintln!("skipping: cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(waiter.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();

    let dc = h.cmd_async("dc");
    dc.assert_busy_within(&h, Duration::from_secs(5));

    let started = Instant::now();
    let summary = commands::open_binary_impl(crackme.to_string_lossy().into(), &h.state)
        .expect("open must not hang behind blocked dc");
    assert!(
        started.elapsed() < WAIT,
        "open took {:?}",
        started.elapsed()
    );
    // Freshly opened binaries report zero functions until `aaa` runs (the
    // frontend triggers analysis separately) — just require a sane summary.
    assert!(summary.is_object(), "summary shape: {summary}");
    assert_eq!(summary["path"], crackme.to_string_lossy().to_string());

    assert!(h
        .debug()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_none());
    let _ = dc.join_with_deadline(WAIT);
}

/// Re-running start while stopped keeps breakpoints (no spurious `ood`).
#[test]
fn idempotent_start_preserves_breakpoints() {
    let Some(binary) = fixture("crackme", CRACKME_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();
    h.cmd("db main").unwrap();

    commands::debug_start_impl(&h.state, None).expect("idempotent restart");
    let bps = h.cmd("dbj").unwrap();
    assert_eq!(bps.as_array().map(|a| a.len()), Some(1));

    commands::debug_stop_impl(&h.state).unwrap();
}

/// Live console streaming: debuggee stdout must land in the shared buffer
/// while a continue is blocked, and include both the prompt and the echoed
/// input — the data source for the UI's unified I/O console.
#[test]
fn stdout_streams_into_console_buffer_during_blocked_continue() {
    let Some(binary) = fixture("waiter", WAITER_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();

    let dc = h.cmd_async("dc");
    dc.assert_busy_within(&h, Duration::from_secs(5));

    commands::debug_stdin_impl(&h.state, "hi\n").expect("fifo write");

    // Program runs to completion; output must have been pumped live.
    let _ = dc.join_with_deadline(WAIT);
    h.wait_busy(false);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf;
    loop {
        buf = String::from_utf8_lossy(
            &h.state
                .debug_output
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
        .into_owned();
        if buf.contains("waiting") && buf.contains("got:hi") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "console buffer missing expected output, got: {buf:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    commands::debug_stop_impl(&h.state).unwrap();
    assert!(
        h.state
            .debug_output
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "teardown clears the console buffer"
    );
}

// ---------------------------------------------------------------------------
// Sandbox e2e — the debugger actually debugging inside bubblewrap
// ---------------------------------------------------------------------------

#[test]
fn debugger_runs_inside_bwrap_sandbox() {
    let Some(binary) = fixture("crackme", CRACKME_C) else {
        eprintln!("skipping: r2/cc unavailable");
        return;
    };
    if !tool_available("bwrap") {
        eprintln!("skipping: bubblewrap unavailable");
        return;
    }
    let privdir = std::env::temp_dir().join(format!("recurse-e2e-sb-{}", std::process::id()));
    std::fs::create_dir_all(&privdir).unwrap();
    let argv = recurse_lib::sandbox::wrap_r2_argv_with(
        recurse_lib::sandbox::Sandbox::Bwrap,
        &binary,
        &[
            "-d".to_string(),
            "-e".to_string(),
            "bin.cache=true".to_string(),
        ],
        &privdir,
    )
    .expect("bwrap argv builds");

    let sess = R2Session::open_argv(argv).expect("r2 boots inside bwrap");
    // ptrace across the namespace boundary: ood + run to a breakpoint.
    sess.run("ood").expect("ood inside sandbox");
    sess.run("db main").expect("bp inside sandbox");
    let dc = sess.run("dc");
    assert!(
        dc.is_ok(),
        "continue under bwrap must reach the breakpoint: {dc:?}"
    );
    let regs = sess.run("drj");
    assert!(regs.is_ok(), "ptrace inspection works in sandbox: {regs:?}");
    drop(sess);
    let _ = std::fs::remove_dir_all(&privdir);
}

// ---------------------------------------------------------------------------
// Small helpers as extension traits for readability above
// ---------------------------------------------------------------------------

trait SpawnExt {
    fn expect_spawn(self) -> std::thread::JoinHandle<Result<serde_json::Value, String>>;
}
impl SpawnExt for std::thread::JoinHandle<Result<serde_json::Value, String>> {
    fn expect_spawn(self) -> Self {
        self
    }
}

trait DcExt {
    fn join_with_deadline(self, d: Duration) -> Option<Result<serde_json::Value, String>>;
    fn join_result(self, d: Duration) -> Result<serde_json::Value, String>;
    fn assert_busy_within(&self, h: &Harness, d: Duration);
}
impl DcExt for std::thread::JoinHandle<Result<serde_json::Value, String>> {
    fn join_with_deadline(self, d: Duration) -> Option<Result<serde_json::Value, String>> {
        let deadline = Instant::now() + d;
        loop {
            if self.is_finished() {
                return self.join().ok();
            }
            if Instant::now() > deadline {
                // Detach: thread will be killed when test process ends.
                std::mem::forget(self);
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn join_result(self, d: Duration) -> std::result::Result<serde_json::Value, String> {
        let inner = self.join_with_deadline(d).expect("thread finished")?;
        Ok(inner)
    }
    fn assert_busy_within(&self, h: &Harness, d: Duration) {
        h.wait_busy_within(d, true);
    }
}

impl Harness {
    fn wait_busy_within(&self, d: Duration, want: bool) {
        let deadline = Instant::now() + d;
        while self.state.debug_busy.load(Ordering::SeqCst) != want {
            assert!(Instant::now() < deadline, "busy never became {want}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn pc_of(regs: &serde_json::Value) -> u64 {
    ["pc", "rip", "eip"]
        .iter()
        .find_map(|k| regs[*k].as_u64())
        .unwrap_or(u64::MAX)
}

#[test]
fn zz_dc_probe() {
    let Some(binary) = fixture("waiter", WAITER_C) else {
        return;
    };
    let h = harness();
    commands::open_binary_impl(binary.to_string_lossy().into(), &h.state).unwrap();
    commands::debug_start_impl(&h.state, None).unwrap();
    // What does ood/dc actually do here?
    if let Ok(v) = h.cmd("ood") {
        println!("zz ood -> {v}");
    }
    let dcer = h.cmd_async("dc");
    std::thread::sleep(Duration::from_secs(2));
    println!("zz busy={}", h.state.debug_busy.load(Ordering::SeqCst));
    let _ = commands::debug_stdin_impl(&h.state, "hi\n");
    match dcer.join_with_deadline(WAIT) {
        Some(Ok(v)) => println!(
            "zz dc -> {}",
            String::from_utf8_lossy(serde_json::to_string(&v).unwrap().as_bytes())
        ),
        Some(Err(e)) => println!("zz dc ERR {e}"),
        None => println!("zz dc still hung"),
    }
    let _ = commands::debug_stop_impl(&h.state);
}

// ---------------------------------------------------------------------------
// Agent-tool layer over real sessions — same gates, real r2
// ---------------------------------------------------------------------------

#[test]
fn agent_tools_are_bash_read_write_edit_only() {
    use recurse_lib::tools::execute;

    let mk = |name: &str| recurse_lib::agent::ToolCall {
        id: format!("t-{name}"),
        call_type: "function".into(),
        function: recurse_lib::agent::ToolCallFn {
            name: name.into(),
            arguments: "{}".into(),
        },
    };

    // The agent surface is bash/read/write/edit only — every native r2/debug
    // tool must be refused so the agent drives analysis via bash.
    for native in [
        "functions",
        "debug_start",
        "debug_breakpoint",
        "debug_registers",
        "debug_continue",
        "debug_stdin",
    ] {
        let err = execute(&mk(native))
            .err()
            .unwrap_or_else(|| format!("{native}: expected rejection"));
        assert!(err.contains("unknown tool"), "{native}: {err}");
    }
}

#[test]
fn storage_and_llm_command_impls_roundtrip() {
    recurse_lib::testhome::with_test_home(|_| {
        let h = harness();
        // LLM config flows through the shared AppState.
        let st = commands::llm_status_impl(&h.state).unwrap();
        assert!(!st.configured);
        commands::save_api_key_impl(&h.state, "  sk-x  ").unwrap();
        commands::set_model_impl(&h.state, "m-1").unwrap();
        let st = commands::llm_status_impl(&h.state).unwrap();
        assert!(st.configured && st.model == "m-1");
        // Empty key clears.
        commands::save_api_key_impl(&h.state, "   ").unwrap();
        assert!(!commands::llm_status_impl(&h.state).unwrap().configured);

        // Project + session lifecycle through the impls.
        let p = commands::create_project_impl(&h.state, "evalproj", "/bin/true").unwrap();
        assert_eq!(p.name, "evalproj");
        let opened = commands::open_project_impl(&h.state, "evalproj").unwrap();
        assert_eq!(opened.binary_path, "/bin/true");

        let s = commands::sessions_create_impl(&h.state).unwrap();
        let sel = commands::sessions_select_impl(&h.state, &s.id).unwrap();
        assert_eq!(sel.id, s.id);

        recurse_lib::sessions::set_name(Some("evalproj"), &s.id, "renamed").unwrap();
        let all = recurse_lib::sessions::list(Some("evalproj")).unwrap();
        assert_eq!(all[0].name, "renamed");
        recurse_lib::sessions::remove(Some("evalproj"), &s.id).unwrap();
        assert!(recurse_lib::sessions::get(Some("evalproj"), &s.id).is_err());

        recurse_lib::project::remove("evalproj").unwrap();
    });
}
