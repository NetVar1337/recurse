use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::agent::ToolCall;
use crate::debugger;
use crate::engine;
use crate::memory;
use crate::session::R2Session;

/// Shared state the tool executor needs to reach the live analysis session,
/// the debug session, and the active project's memory.
pub struct ToolContext {
    pub session: Arc<Mutex<Option<R2Session>>>,
    pub debug: Arc<Mutex<Option<R2Session>>>,
    pub debug_stdin: Arc<Mutex<Option<File>>>,
    /// Same gate the Tauri commands use, so agent-issued continues cannot
    /// interleave with a UI-issued one and inspections fail fast either way.
    pub debug_busy: Arc<AtomicBool>,
    /// Published r2 PID for stop/interrupt — agent-spawned sessions must be
    /// reachable by the teardown path exactly like UI-spawned ones.
    pub debug_pid: Arc<std::sync::atomic::AtomicU32>,
    /// Stop flag for the stdout drain pump (agent path, no UI attached).
    pub debug_output_done: Arc<std::sync::atomic::AtomicBool>,
    pub project: Option<String>,
}

const MAX_RESULT_CHARS: usize = 12_000;
/// Matches `commands::STDIN_TIMEOUT`; kept local so the modules stay decoupled.
const STDIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

fn tool(name: &str, description: &str, params: Value) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": params,
        }
    })
}

fn props(entries: &[(&str, &str, &str, bool)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (name, ty, desc, req) in entries {
        properties.insert(
            (*name).to_string(),
            json!({ "type": ty, "description": desc }),
        );
        if *req {
            required.push(Value::String((*name).to_string()));
        }
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

/// The full tool schema sent to the model.
pub fn schema() -> Vec<Value> {
    vec![
        tool(
            "disassemble",
            "Disassemble `count` instructions at `addr`.",
            props(&[
                ("addr", "integer", "Address to disassemble", true),
                (
                    "count",
                    "integer",
                    "Number of instructions (default 32)",
                    false,
                ),
            ]),
        ),
        tool(
            "decompile",
            "Decompile the function containing `addr` (r2ghidra).",
            props(&[("addr", "integer", "Address inside the function", true)]),
        ),
        tool("functions", "List all analyzed functions.", props(&[])),
        tool(
            "strings",
            "List all strings referenced in the binary.",
            props(&[]),
        ),
        tool("imports", "List imported symbols.", props(&[])),
        tool(
            "xrefs_to",
            "List cross-references pointing to `addr`.",
            props(&[("addr", "integer", "Target address", true)]),
        ),
        tool(
            "search",
            "Search strings for a substring (case-insensitive).",
            props(&[("pattern", "string", "Substring to find", true)]),
        ),
        tool(
            "debug_start",
            "Start (or restart) the program under the debugger, optionally with arguments.",
            props(&[("args", "array", "Program arguments", false)]),
        ),
        tool(
            "debug_breakpoint",
            "Set a breakpoint at `addr`.",
            props(&[("addr", "integer", "Breakpoint address", true)]),
        ),
        tool("debug_breakpoints", "List current breakpoints.", props(&[])),
        tool(
            "debug_continue",
            "Continue execution until breakpoint or exit.",
            props(&[]),
        ),
        tool(
            "debug_step",
            "Single-step into the next instruction.",
            props(&[]),
        ),
        tool(
            "debug_step_over",
            "Single-step over the next instruction.",
            props(&[]),
        ),
        tool(
            "debug_stdin",
            "Write a line to the debuggee stdin when it is waiting for input.",
            props(&[("data", "string", "Input to send", true)]),
        ),
        tool("debug_registers", "Dump all registers.", props(&[])),
        tool(
            "debug_read_memory",
            "Read `len` bytes at `addr`.",
            props(&[
                ("addr", "integer", "Address to read", true),
                ("len", "integer", "Number of bytes (default 16)", false),
            ]),
        ),
        tool(
            "debug_write_memory",
            "Write raw bytes (hex string) at `addr`.",
            props(&[
                ("addr", "integer", "Address to write", true),
                ("bytes", "string", "Hex bytes, e.g. \"9090\"", true),
            ]),
        ),
        tool(
            "debug_write_register",
            "Set a register to a value.",
            props(&[
                (
                    "reg",
                    "string",
                    "Register name, e.g. \"pc\" or \"eax\"",
                    true,
                ),
                ("value", "integer", "Value to set", true),
            ]),
        ),
        tool(
            "debug_disassemble",
            "Disassemble `count` instructions at the current program counter.",
            props(&[(
                "count",
                "integer",
                "Number of instructions (default 16)",
                false,
            )]),
        ),
        tool("debug_kill", "Kill the debuggee.", props(&[])),
        tool(
            "save_memory",
            "Persist a finding to project memory under a key.",
            props(&[
                ("key", "string", "Short key, e.g. \"password_check\"", true),
                ("value", "string", "The finding to remember", true),
            ]),
        ),
        tool(
            "load_memory",
            "Read a previously saved memory entry.",
            props(&[("key", "string", "Key to load", true)]),
        ),
        tool("list_memory", "List saved memory keys.", props(&[])),
        tool(
            "delete_memory",
            "Delete a saved memory entry.",
            props(&[("key", "string", "Key to delete", true)]),
        ),
    ]
}

fn get_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing string argument '{key}'"))
}

fn get_u64(args: &Value, key: &str) -> Result<u64, String> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("missing integer argument '{key}'"))
}

fn get_u64_opt(args: &Value, key: &str, default: u64) -> u64 {
    args.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

fn render(value: Value) -> String {
    match value {
        Value::String(s) => s,
        other => serde_json::to_string(&other).unwrap_or_else(|_| other.to_string()),
    }
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_RESULT_CHARS {
        return s.to_string();
    }
    // Byte-slicing would panic on a multi-byte UTF-8 boundary; cut on a char
    // boundary instead.
    let mut cut = MAX_RESULT_CHARS;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}\n...\n[truncated {} characters]",
        &s[..cut],
        s.len() - cut
    )
}

fn with_sess<F>(ctx: &ToolContext, f: F) -> Result<Value, String>
where
    F: FnOnce(&R2Session) -> Result<Value, String>,
{
    let guard = ctx
        .session
        .lock()
        .map_err(|e| format!("session lock poisoned: {e}"))?;
    let sess = guard
        .as_ref()
        .ok_or_else(|| "no binary loaded".to_string())?;
    f(sess)
}

/// Run `f` against the live debug session, failing fast when a continue is
/// in flight (same contract as the Tauri inspection commands).
fn with_debug<F>(ctx: &ToolContext, f: F) -> Result<Value, String>
where
    F: FnOnce(&R2Session) -> Result<Value, String>,
{
    if ctx.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for continue to hit a breakpoint".into());
    }
    let guard = ctx
        .debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))?;
    // Re-check under the lock: a continue may have started while we waited.
    if ctx.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for continue to hit a breakpoint".into());
    }
    let sess = guard
        .as_ref()
        .ok_or_else(|| "debugger not started".to_string())?;
    f(sess)
}

/// Ensure a debug session exists (spawned on the currently loaded binary) so
/// the agent can start the debugger autonomously, then run `f` against it.
/// Refuses to spawn while a continue is running.
fn with_debug_mut<F>(ctx: &ToolContext, f: F) -> Result<Value, String>
where
    F: FnOnce(&R2Session) -> Result<Value, String>,
{
    if ctx.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for continue to hit a breakpoint".into());
    }
    let mut guard = ctx
        .debug
        .lock()
        .map_err(|e| format!("debug lock poisoned: {e}"))?;
    if ctx.debug_busy.load(Ordering::SeqCst) {
        return Err("debugger is running — wait for continue to hit a breakpoint".into());
    }
    if guard.is_none() {
        let path = {
            let s = ctx
                .session
                .lock()
                .map_err(|e| format!("session lock poisoned: {e}"))?;
            s.as_ref()
                .ok_or_else(|| "no binary loaded".to_string())?
                .path
                .clone()
        };
        // Discarding pump (attached inside spawn): the agent path has no UI
        // to feed, but the stdout FIFO must be drained or the debuggee blocks
        // on a full pipe.
        ctx.debug_output_done
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let done = Arc::clone(&ctx.debug_output_done);
        let (sess, stdin) = debugger::spawn_debug_session(&path, done, |_| {})
            .map_err(|e| format!("failed to start debugger: {e}"))?;
        ctx.debug_pid.store(sess.pid(), Ordering::SeqCst);
        *guard = Some(sess);
        *ctx.debug_stdin
            .lock()
            .map_err(|e| format!("debug stdin lock poisoned: {e}"))? = Some(stdin);
    }
    let sess = guard
        .as_ref()
        .ok_or_else(|| "debugger session vanished".to_string())?;
    f(sess)
}

/// Agent-side continue. Takes the same single-continue gate as the UI's
/// `dc` so an agent turn and a user click can never run two continues at
/// once; the flag is always cleared afterwards (success or failure).
fn agent_continue(ctx: &ToolContext) -> Result<Value, String> {
    if ctx
        .debug_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("debugger already running".into());
    }
    // Take the lock directly — with_debug would reject because we just set
    // the very busy flag it treats as a blocked-continue marker.
    let guard = match ctx.debug.lock() {
        Ok(g) => g,
        Err(e) => {
            ctx.debug_busy.store(false, Ordering::SeqCst);
            return Err(format!("debug lock poisoned: {e}"));
        }
    };
    let result = match guard.as_ref() {
        Some(sess) => debugger::continue_run(sess),
        None => Err("debugger not started".into()),
    };
    drop(guard);
    ctx.debug_busy.store(false, Ordering::SeqCst);
    result
}

/// Execute a single tool call against the live sessions and return its result
/// text (truncated for the token budget).
pub fn execute(tc: &ToolCall, ctx: &ToolContext) -> Result<String, String> {
    let args: Value = serde_json::from_str(&tc.function.arguments).unwrap_or(Value::Null);
    let project = ctx.project.as_deref();

    let result: Result<Value, String> = match tc.function.name.as_str() {
        "disassemble" => {
            let addr = get_u64(&args, "addr")?;
            let count = get_u64_opt(&args, "count", 32);
            with_sess(ctx, |s| engine::disassemble(s, addr, count))
        }
        "decompile" => {
            let addr = get_u64(&args, "addr")?;
            with_sess(ctx, |s| engine::decompile(s, addr))
        }
        "functions" => with_sess(ctx, engine::functions),
        "strings" => with_sess(ctx, engine::strings),
        "imports" => with_sess(ctx, engine::imports),
        "xrefs_to" => {
            let addr = get_u64(&args, "addr")?;
            with_sess(ctx, |s| engine::xrefs_to(s, addr))
        }
        "search" => {
            let pattern = get_str(&args, "pattern")?.to_lowercase();
            with_sess(ctx, |s| {
                let strings = engine::strings(s)?;
                let matches: Vec<Value> = strings
                    .as_array()
                    .map(|a| a.as_slice())
                    .unwrap_or(&[])
                    .iter()
                    .filter(|x| {
                        x["string"]
                            .as_str()
                            .map(|st| st.to_lowercase().contains(&pattern))
                            .unwrap_or(false)
                    })
                    .take(200)
                    .cloned()
                    .collect();
                Ok(Value::Array(matches))
            })
        }
        "debug_start" => {
            let argv: Vec<String> = args
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default();
            with_debug_mut(ctx, |s| debugger::start(s, &argv))
        }
        "debug_breakpoint" => {
            let addr = get_u64(&args, "addr")?;
            with_debug(ctx, |s| debugger::breakpoint(s, addr))
        }
        "debug_breakpoints" => with_debug(ctx, debugger::breakpoints),
        "debug_continue" => agent_continue(ctx),
        "debug_step" => with_debug(ctx, debugger::step),
        "debug_step_over" => with_debug(ctx, debugger::step_over),
        "debug_stdin" => {
            let data = get_str(&args, "data")?;
            let mut stdin = ctx
                .debug_stdin
                .lock()
                .map_err(|e| format!("debug stdin lock poisoned: {e}"))?;
            let pipe = stdin
                .as_mut()
                .ok_or_else(|| "debugger stdin is not available".to_string())?;
            // Bounded nonblocking write: a stopped debuggee must not wedge
            // the agent loop.
            debugger::write_stdin(pipe, format!("{data}\n").as_bytes(), STDIN_TIMEOUT)
                .map(|_| json!({ "written": true }))
        }
        "debug_registers" => with_debug(ctx, debugger::registers),
        "debug_read_memory" => {
            let addr = get_u64(&args, "addr")?;
            let len = get_u64_opt(&args, "len", 16);
            with_debug(ctx, |s| debugger::read_memory(s, addr, len))
        }
        "debug_write_memory" => {
            let addr = get_u64(&args, "addr")?;
            let bytes = get_str(&args, "bytes")?;
            with_debug(ctx, |s| debugger::write_memory(s, addr, &bytes))
        }
        "debug_write_register" => {
            let reg = get_str(&args, "reg")?;
            let value = get_u64(&args, "value")?;
            with_debug(ctx, |s| debugger::set_register(s, &reg, value))
        }
        "debug_disassemble" => {
            let count = get_u64_opt(&args, "count", 16);
            with_debug(ctx, |s| debugger::current_disasm(s, count))
        }
        "debug_kill" => with_debug(ctx, debugger::kill),
        "save_memory" => {
            let key = get_str(&args, "key")?;
            let value = get_str(&args, "value")?;
            memory::save(project, &key, &value)?;
            Ok(json!({ "saved": key }))
        }
        "load_memory" => {
            let key = get_str(&args, "key")?;
            Ok(Value::String(memory::load(project, &key)?))
        }
        "list_memory" => Ok(Value::Array(
            memory::list(project)?
                .into_iter()
                .map(Value::String)
                .collect(),
        )),
        "delete_memory" => {
            let key = get_str(&args, "key")?;
            memory::remove(project, &key)?;
            Ok(json!({ "deleted": key }))
        }
        other => Err(format!("unknown tool: {other}")),
    };

    result.map(|v| truncate(&render(v)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    mod tooltests {
        use super::*;
        use crate::agent::{ToolCall, ToolCallFn};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        fn ctx() -> ToolContext {
            ToolContext {
                session: Arc::new(Mutex::new(None)),
                debug: Arc::new(Mutex::new(None)),
                debug_stdin: Arc::new(Mutex::new(None)),
                debug_busy: Arc::new(AtomicBool::new(false)),
                debug_pid: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                debug_output_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                project: None,
            }
        }

        #[test]
        fn truncate_respects_utf8_boundaries() {
            // Regression: byte-slicing at MAX_RESULT_CHARS panicked when the
            // cut landed inside a multi-byte character.
            let ascii = "a".repeat(MAX_RESULT_CHARS);
            assert_eq!(truncate(&ascii), ascii);
            let cjk = "漢".repeat(10_000); // 30k bytes of 3-byte chars
            let t = truncate(&cjk);
            assert!(t.chars().count() <= MAX_RESULT_CHARS / 3 + 100);
            assert!(t.contains("[truncated"));
        }

        #[test]
        fn arg_helpers() {
            let v = serde_json::json!({"s": "x", "n": 7});
            assert_eq!(get_str(&v, "s").unwrap(), "x");
            assert!(get_str(&v, "missing").is_err());
            assert_eq!(get_u64(&v, "n").unwrap(), 7);
            assert!(get_u64(&v, "s").is_err());
            assert_eq!(get_u64_opt(&v, "n", 1), 7);
            assert_eq!(get_u64_opt(&v, "nope", 42), 42);
        }

        #[test]
        fn render_and_unknown_tool() {
            assert_eq!(render(Value::String("s".into())), "s");
            assert!(render(serde_json::json!({"a":1})).contains("\"a\":1"));
            let tc = ToolCall {
                id: "i".into(),
                call_type: "function".into(),
                function: ToolCallFn {
                    name: "nope".into(),
                    arguments: "{}".into(),
                },
            };
            assert!(execute(&tc, &ctx()).unwrap_err().contains("unknown tool"));
        }

        #[test]
        fn missing_sessions_report_clean_errors() {
            for name in ["disassemble", "debug_registers", "debug_continue"] {
                let tc = ToolCall {
                    id: "i".into(),
                    call_type: "function".into(),
                    function: ToolCallFn {
                        name: name.into(),
                        arguments: if name == "disassemble" {
                            r#"{"addr":16}"#.into()
                        } else {
                            "{}".into()
                        },
                    },
                };
                let err = execute(&tc, &ctx()).unwrap_err();
                assert!(
                    err.contains("no binary loaded") || err.contains("debugger not started"),
                    "{name}: {err}"
                );
            }
        }

        #[test]
        fn memory_tools_roundtrip_via_execute() {
            crate::testhome::with_test_home(|_| {
                let c = ctx();
                let mk = |n: &str, a: serde_json::Value| ToolCall {
                    id: "i".into(),
                    call_type: "function".into(),
                    function: ToolCallFn {
                        name: n.into(),
                        arguments: a.to_string(),
                    },
                };
                execute(
                    &mk("save_memory", serde_json::json!({"key":"k","value":"v"})),
                    &c,
                )
                .unwrap();
                let out = execute(&mk("load_memory", serde_json::json!({"key":"k"})), &c).unwrap();
                assert!(out.contains("v"));
                execute(&mk("list_memory", serde_json::json!({})), &c).unwrap();
                execute(&mk("delete_memory", serde_json::json!({"key":"k"})), &c).unwrap();
                assert!(execute(&mk("load_memory", serde_json::json!({"key":"k"})), &c).is_err());
            });
        }
    }
}
