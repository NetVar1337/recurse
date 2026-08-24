use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Emitter, State};

use crate::agent::{self, AgentEvent, ModelInfo, ToolCall};
use crate::config;
use crate::debugger;
use crate::engine;
use crate::memory;
use crate::project::{self, Project};
use crate::session::R2Session;
use crate::sessions::{self, Session};
use crate::AppState;

/// How long to wait after SIGINT before escalating to SIGKILL when stopping
/// a debugger that has a blocked `dc`.
const INTERRUPT_GRACE: Duration = Duration::from_secs(5);
/// How long a stdin write may wait for the debuggee to consume input.
const STDIN_TIMEOUT: Duration = Duration::from_secs(3);
/// Rolling console buffer cap for live debuggee output (~64 KiB).
const OUTPUT_CAP: usize = 64 * 1024;

fn session_of(state: &AppState) -> Result<std::sync::MutexGuard<'_, Option<R2Session>>, String> {
    state
        .session
        .lock()
        .map_err(|e| format!("session lock poisoned: {e}"))
}

fn session<'a>(
    state: &'a State<'_, AppState>,
) -> Result<std::sync::MutexGuard<'a, Option<R2Session>>, String> {
    state
        .session
        .lock()
        .map_err(|e| format!("session lock poisoned: {e}"))
}

fn with_sess<'a>(
    guard: &'a std::sync::MutexGuard<'a, Option<R2Session>>,
) -> Result<&'a R2Session, String> {
    guard.as_ref().ok_or_else(|| "no binary loaded".into())
}

fn current_project_of(state: &AppState) -> Result<Option<String>, String> {
    Ok(state
        .project
        .lock()
        .map_err(|e| format!("project lock poisoned: {e}"))?
        .as_ref()
        .map(|p| p.name.clone()))
}

fn current_project(state: &State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state
        .project
        .lock()
        .map_err(|e| format!("project lock poisoned: {e}"))?
        .as_ref()
        .map(|p| p.name.clone()))
}

fn current_session_id_of(state: &AppState) -> Result<Option<String>, String> {
    Ok(state
        .current_session
        .lock()
        .map_err(|e| format!("current_session lock poisoned: {e}"))?
        .clone())
}

fn current_session_id(state: &State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state
        .current_session
        .lock()
        .map_err(|e| format!("current_session lock poisoned: {e}"))?
        .clone())
}

fn persist_history(project: Option<&str>, session_id: &str, messages: &[agent::ChatMessage]) {
    if let Ok(json) = serde_json::to_string(messages) {
        let _ = sessions::save_history(project, session_id, &json);
    }
}

// ---------------------------------------------------------------------------
// Debugger lifecycle helpers (shared by commands; race-condition core)
// ---------------------------------------------------------------------------

/// Interrupt a blocked continue so it releases the debug mutex.
///
/// A `dc` runs on the blocking pool while holding the debug mutex, so nothing
/// that needs that mutex can proceed until it returns — and a debuggee waiting
/// for stdin (or hung) would block it forever. We therefore signal r2 out of
/// band: SIGINT unwinds the command like Ctrl-C in an interactive session; if
/// r2 does not respond in time we escalate to SIGKILL, which breaks the pipe
/// and errors the pending command immediately.
pub fn interrupt_busy_debugger(state: &AppState) -> Result<(), String> {
    if !state.debug_busy.load(Ordering::SeqCst) {
        return Ok(());
    }
    let pid = state.debug_pid.load(Ordering::SeqCst);
    if pid == 0 {
        // Busy flag with no live process: stale leftover from a crashed
        // session — clear it rather than deadlocking on it.
        eprintln!("[recurse][debug] clearing stale busy flag (no live pid)");
        state.debug_busy.store(false, Ordering::SeqCst);
        return Ok(());
    }
    // Signal the whole process group so the sandbox wrapper (bwrap) cannot
    // swallow the signal meant for r2. Cross-platform via `process` helper.
    if !crate::process::interrupt_process(pid) {
        return Err(format!("failed to signal debugger group {pid}"));
    }
    eprintln!("[recurse][debug] interrupted r2 group {pid}");
    let deadline = Instant::now() + INTERRUPT_GRACE;
    while state.debug_busy.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if state.debug_busy.load(Ordering::SeqCst) {
        eprintln!("[recurse][debug] SIGINT ignored — escalating to SIGKILL for group {pid}");
        crate::process::terminate_process(pid);
        let deadline = Instant::now() + Duration::from_secs(3);
        while state.debug_busy.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    if state.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger did not respond to interrupt".into());
    }
    Ok(())
}

/// Tear down the debug session under its locks: kill the debuggee, drop the
/// r2 session (which quits r2 and reaps it), clear the stdin handle, busy flag
/// and published PID.
pub fn teardown_debug(state: &AppState) -> Result<(), String> {
    let mut debug = acquire_debug_for_teardown(state)?;
    if let Some(sess) = debug.as_ref() {
        // Best effort: kill the inferior first so it does not linger as an
        // orphan once r2 exits.
        let _ = debugger::kill(sess);
    }
    debug.take();
    state
        .debug_stdin
        .lock()
        .map_err(|e| format!("debug stdin lock poisoned: {e}"))?
        .take();
    state.debug_busy.store(false, Ordering::SeqCst);
    state.debug_pid.store(0, Ordering::SeqCst);
    state.debug_output_done.store(true, Ordering::SeqCst);
    if let Ok(mut b) = state.debug_output.lock() {
        b.clear();
    }
    Ok(())
}

/// Try to take the debug mutex with a deadline. A wedged command thread
/// holding this guard must never hang shutdown: on timeout we force-kill the
/// recorded process group (the broken pipe guarantees the holder errors out)
/// and keep retrying briefly.
fn acquire_debug_for_teardown(
    state: &AppState,
) -> Result<std::sync::MutexGuard<'_, Option<R2Session>>, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut escalated = false;
    loop {
        match state.debug.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(e)) => return Ok(e.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline && !escalated {
                    let pid = state.debug_pid.load(Ordering::SeqCst);
                    if pid != 0 {
                        eprintln!("[recurse][debug] teardown: force-killing group {pid}");
                        crate::process::terminate_process(pid);
                    }
                    escalated = true;
                } else if escalated && Instant::now() >= deadline + Duration::from_secs(10) {
                    return Err("debug mutex still held during teardown".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Full shutdown path used by open/close binary and debug stop: interrupt any
/// blocked continue first (so locks are free), then tear down.
pub fn shutdown_debug(state: &AppState) -> Result<(), String> {
    interrupt_busy_debugger(state)?;
    teardown_debug(state)
}

// ---------------------------------------------------------------------------
// Binary / analysis commands
// ---------------------------------------------------------------------------

/// Core of [`open_binary`], taking plain state so integration tests can
/// drive the exact production path without a Tauri runtime.
pub fn open_binary_impl(path: String, state: &AppState) -> Result<Value, String> {
    eprintln!("[recurse] open_binary: {path}");
    // Force-stop any running debug session first: a blocked `dc` must not
    // wedge opening another binary.
    shutdown_debug(state)?;
    let mut guard = session_of(state)?;
    let sess = R2Session::open(path)?;
    let summary = engine::summary(&sess);
    eprintln!(
        "[recurse] open_binary: funcs={} strings={}",
        summary["function_count"], summary["string_count"]
    );
    *guard = Some(sess);
    *state
        .current_session
        .lock()
        .map_err(|e| format!("current_session lock poisoned: {e}"))? = None;
    Ok(summary)
}

#[tauri::command]
pub fn open_binary(path: String, state: State<'_, AppState>) -> Result<Value, String> {
    open_binary_impl(path, &state)
}

#[tauri::command]
pub fn analyze(state: State<'_, AppState>) -> Result<(), String> {
    analyze_impl(&state)
}

/// Core of [`analyze`]; see [`open_binary_impl`].
pub fn analyze_impl(state: &AppState) -> Result<(), String> {
    eprintln!("[recurse] analyze: starting `aaa`");
    let guard = session_of(state)?;
    with_sess(&guard)?.analyze()?;
    eprintln!("[recurse] analyze: done");
    Ok(())
}

/// Core of [`close_binary`]; see [`open_binary_impl`].
pub fn close_binary_impl(state: &AppState) -> Result<(), String> {
    shutdown_debug(state)?;
    session_of(state)?.take();
    *state
        .project
        .lock()
        .map_err(|e| format!("project lock poisoned: {e}"))? = None;
    *state
        .current_session
        .lock()
        .map_err(|e| format!("current_session lock poisoned: {e}"))? = None;
    Ok(())
}

#[tauri::command]
pub fn close_binary(state: State<'_, AppState>) -> Result<(), String> {
    close_binary_impl(&state)
}

#[tauri::command]
pub fn binary_info(state: State<'_, AppState>) -> Result<Value, String> {
    binary_info_impl(&state)
}

/// Core of [`binary_info`]; see [`open_binary_impl`].
pub fn binary_info_impl(state: &AppState) -> Result<Value, String> {
    let guard = session_of(state)?;
    Ok(engine::info(with_sess(&guard)?))
}

#[tauri::command]
pub fn functions(state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    let v = engine::functions(with_sess(&guard)?)?;
    eprintln!(
        "[recurse] functions: {}",
        v.as_array().map(|a| a.len()).unwrap_or(0)
    );
    Ok(v)
}

#[tauri::command]
pub fn disassemble(addr: u64, count: u64, state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    engine::disassemble(with_sess(&guard)?, addr, count)
}

#[tauri::command]
pub fn function_at(addr: u64, state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    engine::function_at(with_sess(&guard)?, addr)
}

#[tauri::command]
pub fn function_disasm(addr: u64, state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    engine::function_disasm(with_sess(&guard)?, addr)
}

#[tauri::command]
pub fn function_graph(addr: u64, state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    engine::function_graph(with_sess(&guard)?, addr)
}

#[tauri::command]
pub fn strings(state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    let v = engine::strings(with_sess(&guard)?)?;
    eprintln!(
        "[recurse] strings: {}",
        v.as_array().map(|a| a.len()).unwrap_or(0)
    );
    Ok(v)
}

#[tauri::command]
pub fn imports(state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    let v = engine::imports(with_sess(&guard)?)?;
    eprintln!(
        "[recurse] imports: {}",
        v.as_array().map(|a| a.len()).unwrap_or(0)
    );
    Ok(v)
}

#[tauri::command]
pub fn xrefs_to(addr: u64, state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    engine::xrefs_to(with_sess(&guard)?, addr)
}

#[tauri::command]
pub fn decompile(addr: u64, state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    engine::decompile(with_sess(&guard)?, addr)
}

#[tauri::command]
pub fn raw(cmd: String, state: State<'_, AppState>) -> Result<Value, String> {
    let guard = session(&state)?;
    engine::raw(with_sess(&guard)?, &cmd)
}

/// Zoom the whole window (native webview zoom, like VS Code's Ctrl +/-).
#[tauri::command]
pub fn set_zoom(scale: f64, window: tauri::WebviewWindow) -> Result<(), String> {
    window
        .set_zoom(scale)
        .map_err(|e| format!("set_zoom failed: {e}"))
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

/// Start an agent turn in the given session. Returns immediately; progress
/// streams over the `agent-event` channel. The blocking loop (LLM streaming +
/// r2 tool calls) runs on the Tauri blocking pool.
#[tauri::command]
pub async fn agent_chat(
    message: String,
    session_id: String,
    on_event: tauri::ipc::Channel<AgentEvent>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let (path, info) = {
        let guard = state
            .session
            .lock()
            .map_err(|e| format!("session lock poisoned: {e}"))?;
        let sess = guard
            .as_ref()
            .ok_or_else(|| "no binary loaded".to_string())?;
        (sess.path.to_string_lossy().to_string(), engine::info(sess))
    };
    let config = state
        .llm
        .lock()
        .map_err(|e| format!("llm lock poisoned: {e}"))?
        .clone();
    let agent = state.agent.clone();
    let project = current_project(&state)?;
    let project_storage = project.clone();
    let config_storage = config.clone();
    let sid = session_id.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let tools = crate::tools::schema();
        let memory = memory::summary_for(project.as_deref(), &message);

        // Wrapped so any panic still surfaces an Error event to the frontend.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<Vec<agent::ChatMessage>, String> {
                let mut guard = agent
                    .lock()
                    .map_err(|_| "agent lock poisoned".to_string())?;
                let mut exec = |tc: &ToolCall| crate::tools::execute(tc);
                let mut emit = |ev: AgentEvent| {
                    let _ = on_event.send(ev);
                };
                guard
                    .run(
                        "run", &config, &path, &info, &memory, &message, &tools, &mut exec,
                        &mut emit,
                    )
                    .map(|_| guard.messages().to_vec())
            },
        ));

        match outcome {
            Ok(Ok(messages)) => {
                persist_history(project_storage.as_deref(), &sid, &messages);
            }
            Ok(Err(e)) => {
                let _ = on_event.send(AgentEvent::Error {
                    run_id: "run".into(),
                    message: e,
                });
            }
            Err(_) => {
                let _ = on_event.send(AgentEvent::Error {
                    run_id: "run".into(),
                    message: "agent worker panicked".into(),
                });
            }
        }

        // Remember the model + bump the recency, and title a brand-new session.
        let _ = sessions::set_model(project_storage.as_deref(), &sid, &config_storage.model);
        let _ = sessions::touch(project_storage.as_deref(), &sid);
        ensure_session_name(project_storage.as_deref(), &sid, &config_storage, &message);
    });

    Ok(())
}

/// If this is a brand-new session (still named "New session"), ask the model
/// to title it from the first user message. Falls back to a truncated message.
fn ensure_session_name(
    project: Option<&str>,
    session_id: &str,
    config: &agent::LlmConfig,
    message: &str,
) {
    if let Ok(s) = sessions::get(project, session_id) {
        if s.name.is_empty() || s.name == "New session" {
            let name = agent::generate_title(config, message);
            let _ = sessions::set_name(project, session_id, &name);
        }
    }
}

/// Ask the in-flight agent run to stop. Cooperative: lands between tool
/// iterations; the run then emits an Error("run cancelled") event like any
/// other failure so the frontend resets uniformly.
#[tauri::command]
pub fn agent_cancel_run(state: State<'_, AppState>) -> Result<(), String> {
    state
        .agent
        .lock()
        .map_err(|e| format!("agent lock poisoned: {e}"))?
        .request_cancel();
    Ok(())
}

#[tauri::command]
pub fn agent_reset(state: State<'_, AppState>) -> Result<(), String> {
    {
        let mut agent = state
            .agent
            .lock()
            .map_err(|e| format!("agent lock poisoned: {e}"))?;
        agent.reset();
    }
    let project = current_project_of(&state)?;
    if let Some(sid) = current_session_id_of(&state)? {
        let _ = sessions::save_history(project.as_deref(), &sid, "[]");
    }
    Ok(())
}

/// Restore the active session's persisted conversation into the agent and
/// return the messages (used by the frontend to render on load / reload).
#[tauri::command]
pub fn agent_history(state: State<'_, AppState>) -> Result<Vec<agent::ChatMessage>, String> {
    let project = current_project(&state)?;
    let sid = current_session_id(&state)?;
    let mut agent = state
        .agent
        .lock()
        .map_err(|e| format!("agent lock poisoned: {e}"))?;
    if let Some(sid) = sid {
        if let Some(json) = sessions::load_history(project.as_deref(), &sid) {
            if let Ok(msgs) = serde_json::from_str::<Vec<agent::ChatMessage>>(&json) {
                agent.load(msgs.clone());
                return Ok(msgs);
            }
        }
    }
    agent.reset();
    Ok(vec![])
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn sessions_list(project: String) -> Result<Vec<Session>, String> {
    sessions::list(Some(&project))
}

/// Create a new session for the active project and make it current.
/// Core of [`sessions_create`]; see [`open_binary_impl`].
pub fn sessions_create_impl(state: &AppState) -> Result<Session, String> {
    let project = current_project_of(state)?;
    let model = state
        .llm
        .lock()
        .map_err(|e| format!("llm lock poisoned: {e}"))?
        .model
        .clone();
    let s = sessions::create(project.as_deref(), &model)?;
    state
        .agent
        .lock()
        .map_err(|e| format!("agent lock poisoned: {e}"))?
        .reset();
    *state
        .current_session
        .lock()
        .map_err(|e| format!("current_session lock poisoned: {e}"))? = Some(s.id.clone());
    Ok(s)
}

#[tauri::command]
pub fn sessions_create(state: State<'_, AppState>) -> Result<Session, String> {
    sessions_create_impl(&state)
}

/// Switch to a session: load its history into the agent and restore its model.
/// Core of [`sessions_select`]; see [`open_binary_impl`].
pub fn sessions_select_impl(state: &AppState, session_id: &str) -> Result<Session, String> {
    let project = current_project_of(state)?;
    let s = sessions::get(project.as_deref(), session_id)?;
    {
        let mut agent = state
            .agent
            .lock()
            .map_err(|e| format!("agent lock poisoned: {e}"))?;
        match sessions::load_history(project.as_deref(), session_id) {
            Some(json) => match serde_json::from_str::<Vec<agent::ChatMessage>>(&json) {
                Ok(msgs) => agent.load(msgs),
                Err(_) => agent.reset(),
            },
            None => agent.reset(),
        }
    }
    {
        let mut llm = state
            .llm
            .lock()
            .map_err(|e| format!("llm lock poisoned: {e}"))?;
        if !s.model.is_empty() {
            llm.model = s.model.clone();
        }
    }
    *state
        .current_session
        .lock()
        .map_err(|e| format!("current_session lock poisoned: {e}"))? = Some(s.id.clone());
    Ok(s)
}

#[tauri::command]
pub fn sessions_select(session_id: String, state: State<'_, AppState>) -> Result<Session, String> {
    sessions_select_impl(&state, &session_id)
}

#[tauri::command]
pub fn sessions_delete(project: String, session_id: String) -> Result<(), String> {
    sessions::remove(Some(&project), &session_id)
}

#[tauri::command]
pub fn sessions_rename(project: String, session_id: String, name: String) -> Result<(), String> {
    sessions::set_name(Some(&project), &session_id, &name)
}

// ---------------------------------------------------------------------------
// Debugger commands
// ---------------------------------------------------------------------------

/// Live debuggee output chunk pushed to the frontend console.
#[derive(Clone, Serialize)]
struct DebugOutputEvent {
    data: String,
}

/// Start a debug session for the currently loaded binary (`r2 -d`).
/// Idempotent: if already started for this binary, does NOT re-issue `ood`
/// (which would clear breakpoints). Only spawns on first start or after stop.
/// Core of [`debug_start`]; see [`open_binary_impl`]. `app` (present in the
/// running app, `None` in tests) enables live `debug-output` event streaming.
pub fn debug_start_impl(state: &AppState, app: Option<&AppHandle>) -> Result<(), String> {
    if state.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for it to stop".into());
    }
    eprintln!("[recurse][debug] start requested");
    let path = {
        let guard = session_of(state)?;
        with_sess(&guard)?.path.clone()
    };
    eprintln!("[recurse][debug] target: {}", path.display());

    // Hold the debug mutex across the whole spawn so no command can slip in
    // against a half-initialized session. Re-check busy under the lock to
    // close the start-vs-continue race window.
    let mut debug = state
        .debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))?;
    if state.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for it to stop".into());
    }

    let stdin_ready = state
        .debug_stdin
        .lock()
        .map_err(|e| format!("debug stdin lock poisoned: {e}"))?
        .is_some();
    let already_started = debug.is_some() && stdin_ready;
    if already_started {
        eprintln!("[recurse][debug] already started — reusing session (no ood)");
        return Ok(());
    }
    if debug.is_some() {
        eprintln!("[recurse][debug] replacing stale debug session");
        if let Some(sess) = debug.as_ref() {
            let _ = debugger::kill(sess);
        }
        debug.take();
        state
            .debug_stdin
            .lock()
            .map_err(|e| format!("debug stdin lock poisoned: {e}"))?
            .take();
    }
    eprintln!("[recurse][debug] spawning r2 debug session");
    // Reset console state, then spawn: the pump (reader side of the stdout
    // FIFO) must exist BEFORE r2 applies its profile redirects or startup
    // deadlocks.
    state.debug_output_done.store(true, Ordering::SeqCst);
    if let Ok(mut b) = state.debug_output.lock() {
        b.clear();
    }
    state.debug_output_done.store(false, Ordering::SeqCst);
    let done = Arc::clone(&state.debug_output_done);
    let buffer = Arc::clone(&state.debug_output);
    let emitter = app.cloned();
    let t0 = std::time::Instant::now();
    let (sess, stdin) = debugger::spawn_debug_session(&path, done, move |chunk| {
        if let Ok(mut buf) = buffer.lock() {
            buf.extend_from_slice(&chunk);
            let len = buf.len();
            if len > OUTPUT_CAP {
                let drop = len - OUTPUT_CAP;
                buf.drain(..drop);
            }
        }
        // Live stream to the UI console; lossy UTF-8 keeps chunk boundaries
        // (which can split a multibyte char) from erroring the whole run.
        if let Some(app) = &emitter {
            let _ = app.emit(
                "debug-output",
                DebugOutputEvent {
                    data: String::from_utf8_lossy(&chunk).into_owned(),
                },
            );
        }
    })?;
    eprintln!(
        "[recurse][debug] r2 debug session spawned (sandbox={}) in {:?}",
        crate::sandbox::current().as_str(),
        t0.elapsed()
    );
    // `ood` only on first spawn — it clears breakpoints if re-issued.
    eprintln!("[recurse][debug] reopening debuggee with ood");
    let t1 = std::time::Instant::now();
    let spawn_result = debugger::start(&sess, &[]);
    eprintln!("[recurse][debug] ood took {:?}", t1.elapsed());
    if let Err(e) = spawn_result {
        eprintln!("[recurse][debug] ood failed: {e}");
        // Dropping sess quits r2 and reaps the child.
        return Err(e);
    }
    // Publish the PID before the session becomes visible to other threads so
    // stop/interrupt can always reach a live process they observe as busy.
    state.debug_pid.store(sess.pid(), Ordering::SeqCst);

    eprintln!("[recurse][debug] stdout pump attached");
    *debug = Some(sess);
    *state
        .debug_stdin
        .lock()
        .map_err(|e| format!("debug stdin lock poisoned: {e}"))? = Some(stdin);
    state.debug_busy.store(false, Ordering::SeqCst);
    eprintln!("[recurse][debug] start completed");
    Ok(())
}

#[tauri::command]
pub fn debug_start(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    debug_start_impl(&state, Some(&app))
}
/// Pass a raw r2 debugger command through to the debug session.
///
/// Core of `debug_command`, implementing the full gating contract against
/// plain shared state: one continue at a time, fail-fast inspections, and a
/// gate taken atomically under the mutex.
///
/// Concurrency contract:
/// - Only one `dc` at a time (`debug_busy` CAS'd true before running).
/// - Inspection commands fail fast instead of queueing behind a blocked
///   `dc`: acquisition uses `try_lock`, and while a continue is flagged busy
///   any contending inspection errors immediately.
/// - All gating happens atomically with execution (under the mutex), so there
///   is no check-then-run window where a breakpoint could land after a new
///   continue started or against a replaced session.
///
/// Public so the e2e suite drives the exact production path; the Tauri
/// command only adds logging and the blocking-pool hop.
pub fn execute_debug_command(
    debug: std::sync::Arc<std::sync::Mutex<Option<R2Session>>>,
    busy: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cmd: String,
) -> Result<Value, String> {
    let trimmed = cmd.trim();
    let is_continue = trimmed == "dc" || trimmed.starts_with("dc ");

    // Advisory fast-fail before acquiring anything; the authoritative
    // gate is taken again under the lock below.
    if !is_continue && busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for continue to hit a breakpoint".into());
    }
    if is_continue
        && busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return Err("debugger already running".into());
    }

    let busy_in = busy.clone();
    let command = cmd.clone();
    let result = (move || {
        let guard = loop {
            match debug.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err("debug lock poisoned".to_string());
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    // Contended. If a continue holds the session, fail fast
                    // instead of silently queueing behind it; otherwise yield
                    // briefly (inspection commands are short-lived).
                    if busy_in.load(Ordering::SeqCst) {
                        return Err(
                            "debugger is running — wait for continue to hit a breakpoint"
                                .to_string(),
                        );
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        };
        let sess = guard
            .as_ref()
            .ok_or_else(|| "debugger not started".to_string())?;
        sess.run(&command)
        // guard drops here, releasing the mutex before the busy flag
        // clears, so a subsequent continue can never observe busy=false
        // behind a held mutex.
    })();

    if is_continue {
        busy.store(false, Ordering::SeqCst);
    }
    match &result {
        Ok(value) => eprintln!(
            "[recurse][debug] command completed: {cmd} (json_type={})",
            match value {
                Value::Null => "null",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "text",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            }
        ),
        Err(error) => eprintln!("[recurse][debug] command failed: {cmd}: {error}"),
    }
    result
}

#[tauri::command]
pub async fn debug_command(cmd: String, state: State<'_, AppState>) -> Result<Value, String> {
    eprintln!("[recurse][debug] command started: {cmd}");
    let debug = state.debug.clone();
    let busy = state.debug_busy.clone();
    let logged = cmd.clone();
    let result =
        tauri::async_runtime::spawn_blocking(move || execute_debug_command(debug, busy, cmd))
            .await
            .map_err(|e| format!("debug command worker failed: {e}"));
    if let Ok(Err(error)) = &result {
        eprintln!("[recurse][debug] command failed: {logged}: {error}");
    } else if let Ok(Ok(v)) = &result {
        eprintln!(
            "[recurse][debug] command completed: {logged} (json_type={})",
            match v {
                Value::Null => "null",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "text",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            }
        );
    }
    result.unwrap_or_else(Err)
}

/// Interrupt a running continue (`dc`) without tearing down the debugger:
/// sends SIGINT to r2 exactly like pressing Ctrl-C in an interactive session.
/// No-op when the debugger is not running.
/// Fetch the accumulated live debuggee output (console bootstrap + poll).
#[tauri::command]
pub fn debug_output_get(state: State<'_, AppState>) -> Result<String, String> {
    let buf = state
        .debug_output
        .lock()
        .map_err(|e| format!("debug output lock poisoned: {e}"))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[tauri::command]
pub fn debug_interrupt(state: State<'_, AppState>) -> Result<(), String> {
    if !state.debug_busy.load(Ordering::SeqCst) {
        return Ok(());
    }
    let pid = state.debug_pid.load(Ordering::SeqCst);
    if pid == 0 {
        return Err("debugger is marked running but no live r2 process is known".into());
    }
    if crate::process::interrupt_process(pid) {
        eprintln!("[recurse][debug] sent SIGINT to r2 pid {pid}");
        Ok(())
    } else {
        Err(format!("failed to signal r2 pid {pid}"))
    }
}

/// Core of [`debug_stop`]; see [`open_binary_impl`].
pub fn debug_stop_impl(state: &AppState) -> Result<(), String> {
    eprintln!("[recurse][debug] stop requested");
    // If a continue is blocked, interrupt it first so the debug mutex frees
    // up; previously this refused to run at all, wedging the app.
    shutdown_debug(state)?;
    eprintln!("[recurse][debug] stopped");
    Ok(())
}

#[tauri::command]
pub fn debug_stop(state: State<'_, AppState>) -> Result<(), String> {
    debug_stop_impl(&state)
}

/// Core of [`debug_stdin`]; see [`open_binary_impl`].
pub fn debug_stdin_impl(state: &AppState, data: &str) -> Result<(), String> {
    eprintln!("[recurse][debug] stdin write: {} bytes", data.len());
    let mut stdin = state
        .debug_stdin
        .lock()
        .map_err(|e| format!("debug stdin lock poisoned: {e}"))?;
    let pipe = stdin
        .as_mut()
        .ok_or_else(|| "debugger stdin is not available".to_string())?;
    // Nonblocking + bounded retry: a stopped/full FIFO must never hold this
    // mutex indefinitely (it previously froze every other stdin write and all
    // start/stop paths).
    debugger::write_stdin(pipe, data.as_bytes(), STDIN_TIMEOUT)
}

#[tauri::command]
pub fn debug_stdin(data: String, state: State<'_, AppState>) -> Result<(), String> {
    debug_stdin_impl(&state, &data)
}

/// Which sandbox backend dynamic analysis uses right now, plus availability.
#[derive(Serialize)]
pub struct SandboxStatus {
    pub backend: String,
    pub available: bool,
    pub detail: String,
}

#[tauri::command]
pub fn sandbox_status() -> SandboxStatus {
    match crate::sandbox::status() {
        Ok(sb) => SandboxStatus {
            backend: sb.as_str().into(),
            available: true,
            detail: "dynamic analysis runs sandboxed".into(),
        },
        Err(e) => SandboxStatus {
            backend: crate::sandbox::current().as_str().into(),
            available: false,
            detail: e,
        },
    }
}

#[tauri::command]
pub fn debug_registers(state: State<'_, AppState>) -> Result<Value, String> {
    let debug = state
        .debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))?;
    // Authoritative check under the lock: reaching here means no continue can
    // be mid-flight (it holds this same mutex).
    if state.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for it to stop".into());
    }
    eprintln!("[recurse][debug] registers requested");
    let sess = debug
        .as_ref()
        .ok_or_else(|| "debugger not started".to_string())?;
    debugger::registers(sess)
}

#[tauri::command]
pub fn debug_disassemble(count: u64, state: State<'_, AppState>) -> Result<Value, String> {
    let debug = state
        .debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))?;
    if state.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for it to stop".into());
    }
    eprintln!("[recurse][debug] disassemble requested: count={count}");
    let sess = debug
        .as_ref()
        .ok_or_else(|| "debugger not started".to_string())?;
    debugger::current_disasm(sess, count)
}

#[tauri::command]
pub fn debug_breakpoints(state: State<'_, AppState>) -> Result<Value, String> {
    let debug = state
        .debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))?;
    if state.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for it to stop".into());
    }
    eprintln!("[recurse][debug] breakpoints requested");
    let sess = debug
        .as_ref()
        .ok_or_else(|| "debugger not started".to_string())?;
    debugger::breakpoints(sess)
}

// ---------------------------------------------------------------------------
// LLM / projects / shells
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LlmStatus {
    pub provider: String,
    pub configured: bool,
    pub model: String,
}

/// Core of [`llm_status`]; see [`open_binary_impl`].
pub fn llm_status_impl(state: &AppState) -> Result<LlmStatus, String> {
    let config = state
        .llm
        .lock()
        .map_err(|e| format!("llm lock poisoned: {e}"))?;
    Ok(LlmStatus {
        provider: "openrouter".into(),
        configured: config
            .api_key
            .as_ref()
            .map(|k| !k.is_empty())
            .unwrap_or(false),
        model: config.model.clone(),
    })
}

#[tauri::command]
pub fn llm_status(state: State<'_, AppState>) -> Result<LlmStatus, String> {
    llm_status_impl(&state)
}

/// Core of [`set_model`]; see [`open_binary_impl`].
pub fn set_model_impl(state: &AppState, id: &str) -> Result<(), String> {
    config::set_model(id.to_string())?;
    let mut config = state
        .llm
        .lock()
        .map_err(|e| format!("llm lock poisoned: {e}"))?;
    config.model = id.to_string();
    Ok(())
}

#[tauri::command]
pub fn set_model(id: String, state: State<'_, AppState>) -> Result<(), String> {
    set_model_impl(&state, &id)
}

/// Core of [`save_api_key`]; see [`open_binary_impl`].
pub fn save_api_key_impl(state: &AppState, key: &str) -> Result<(), String> {
    let trimmed = key.trim();
    let key_opt = if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    };
    config::set_api_key(key_opt.clone())?;
    let mut config = state
        .llm
        .lock()
        .map_err(|e| format!("llm lock poisoned: {e}"))?;
    config.api_key = key_opt;
    Ok(())
}

#[tauri::command]
pub fn save_api_key(key: String, state: State<'_, AppState>) -> Result<(), String> {
    save_api_key_impl(&state, &key)
}

#[tauri::command]
pub fn list_models(refresh: bool, state: State<'_, AppState>) -> Result<Vec<ModelInfo>, String> {
    {
        let guard = state
            .models
            .lock()
            .map_err(|e| format!("models lock poisoned: {e}"))?;
        if !refresh {
            if let Some(cached) = guard.as_ref() {
                return Ok(cached.clone());
            }
        }
    }
    let models = agent::fetch_models()?;
    let mut guard = state
        .models
        .lock()
        .map_err(|e| format!("models lock poisoned: {e}"))?;
    *guard = Some(models.clone());
    Ok(models)
}

#[tauri::command]
pub fn list_projects() -> Result<Vec<Project>, String> {
    project::list()
}

/// Core of [`create_project`]; see [`open_binary_impl`].
pub fn create_project_impl(
    state: &AppState,
    name: &str,
    binary_path: &str,
) -> Result<Project, String> {
    let p = project::create(name, binary_path)?;
    *state
        .project
        .lock()
        .map_err(|e| format!("project lock poisoned: {e}"))? = Some(p.clone());
    Ok(p)
}

#[tauri::command]
pub fn create_project(
    name: String,
    binary_path: String,
    state: State<'_, AppState>,
) -> Result<Project, String> {
    create_project_impl(&state, &name, &binary_path)
}

/// Core of [`open_project`]; see [`open_binary_impl`].
pub fn open_project_impl(state: &AppState, name: &str) -> Result<Project, String> {
    let p = project::get(name)?;
    project::touch(name)?;
    *state
        .project
        .lock()
        .map_err(|e| format!("project lock poisoned: {e}"))? = Some(p.clone());
    Ok(p)
}

#[tauri::command]
pub fn open_project(name: String, state: State<'_, AppState>) -> Result<Project, String> {
    open_project_impl(&state, &name)
}

#[tauri::command]
pub fn delete_project(name: String) -> Result<(), String> {
    project::remove(&name)
}

#[tauri::command]
pub fn project_read_file(name: String, path: String) -> Result<String, String> {
    project::read_file(&name, &path)
}

#[tauri::command]
pub fn project_write_file(name: String, path: String, content: String) -> Result<(), String> {
    project::write_file(&name, &path, &content)
}

#[tauri::command]
pub fn project_list_files(name: String) -> Result<Vec<String>, String> {
    project::list_files(&name)
}

#[tauri::command]
pub fn shell_spawn(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<crate::shell::SpawnedShell, String> {
    state.shell.spawn(app)
}

#[tauri::command]
pub fn shell_write(id: u32, data: String, state: State<'_, AppState>) -> Result<(), String> {
    state.shell.write(id, &data)
}

#[tauri::command]
pub fn shell_resize(
    id: u32,
    rows: u16,
    cols: u16,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.shell.resize(id, rows, cols)
}

#[tauri::command]
pub fn shell_kill(id: u32, state: State<'_, AppState>) -> Result<(), String> {
    state.shell.kill(id)
}

#[tauri::command]
pub fn shell_list(state: State<'_, AppState>) -> Vec<u32> {
    state.shell.list()
}
