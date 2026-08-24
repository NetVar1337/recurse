use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::agent::ToolCall;
use crate::session::R2Session;

static DOOM_LOOP: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();
fn doom_tracker() -> &'static Mutex<HashMap<String, usize>> {
    DOOM_LOOP.get_or_init(|| Mutex::new(HashMap::new()))
}

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
    /// Agent runs must begin with a shell-driven action. The UI's direct tool
    /// tests can disable this compatibility gate.
    pub action_first: bool,
    pub bash_used: Arc<AtomicBool>,
    /// RE agents get two shell reconnaissance calls before the harness forces
    /// the analysis into an executable Python/uv phase.
    pub bash_calls: Arc<std::sync::atomic::AtomicU32>,
    pub python_used: Arc<AtomicBool>,
    pub project: Option<String>,
}

const MAX_RESULT_CHARS: usize = 12_000;
const DEFAULT_READ_LIMIT: usize = 2000;
const MAX_LINE_LENGTH: usize = 2000;

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

/// Minimal agent schema for now: bash + read + write + edit.
/// Native r2/debug/memory/todo/skill/question remain UI-only to avoid the
/// decompile/search loop; the agent drives all analysis through bash.
pub fn schema() -> Vec<Value> {
    vec![
        tool(
            "bash",
            "Executes a given bash command in a persistent shell session with optional timeout, ensuring proper handling and security measures. Use workdir instead of cd.",
            json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "The command to execute" },
                    "timeout": { "type": "integer", "description": "Optional timeout in milliseconds" },
                    "workdir": { "type": "string", "description": "The working directory to run the command in. Defaults to the current directory." }
                },
                "required": ["command"]
            }),
        ),
        tool(
            "read",
            "Read a file or directory from the local filesystem. If the path does not exist, an error is returned. Use offset/limit for large files. Lines are prefixed with line numbers.",
            json!({
                "type": "object",
                "properties": {
                    "filePath": { "type": "string", "description": "The absolute path to the file or directory to read" },
                    "limit": { "type": "integer", "description": "The maximum number of lines to read (defaults to 2000)" },
                    "offset": { "type": "integer", "description": "The line number to start reading from (1-indexed)" }
                },
                "required": ["filePath"]
            }),
        ),
        tool(
            "write",
            "Writes a file to the local filesystem. This tool will overwrite the existing file if there is one at the provided path. Always prefer editing existing files.",
            json!({
                "type": "object",
                "properties": {
                    "filePath": { "type": "string", "description": "The absolute path to the file to write (must be absolute, not relative)" },
                    "content": { "type": "string", "description": "The content to write to the file" }
                },
                "required": ["filePath", "content"]
            }),
        ),
        tool(
            "edit",
            "Performs exact string replacements in files. You must use read at least once before editing. oldString must appear exactly once unless replaceAll is true.",
            json!({
                "type": "object",
                "properties": {
                    "filePath": { "type": "string", "description": "The absolute path to the file to modify" },
                    "oldString": { "type": "string", "description": "The text to replace" },
                    "newString": { "type": "string", "description": "The text to replace it with (must be different from oldString)" },
                    "replaceAll": { "type": "boolean", "description": "Replace all occurrences of oldString (default false)" }
                },
                "required": ["filePath", "oldString", "newString"]
            }),
        ),
    ]
}

fn get_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing string argument '{key}'"))
}

fn get_str_opt(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
fn get_u64(args: &Value, key: &str) -> Result<u64, String> {
    args.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("missing integer argument '{key}'"))
}

#[cfg(test)]
fn get_u64_opt(args: &Value, key: &str, default: u64) -> u64 {
    args.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

fn get_bool_opt(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
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

// ---------------------------------------------------------------------------
// opencode-parity helpers (bash, read, write, edit)
// ---------------------------------------------------------------------------

fn bash_execute_simple(
    command: &str,
    workdir: Option<String>,
    timeout: Option<u64>,
) -> Result<String, String> {
    // Simpler path using Command::output with manual timeout thread – more reliable stdout capture.
    let workdir = workdir.unwrap_or_else(|| ".".to_string());
    let cmd_str = command.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    let workdir_clone = workdir.clone();
    std::thread::spawn(move || {
        let out = Command::new("bash")
            .arg("-lc")
            .arg(&cmd_str)
            .current_dir(&workdir_clone)
            .output();
        let _ = tx.send(out);
    });
    let dur = Duration::from_millis(timeout.unwrap_or(120_000));
    match rx.recv_timeout(dur) {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            let combined = if stdout.is_empty() {
                stderr
            } else if stderr.is_empty() {
                stdout
            } else {
                format!("{stdout}\n{stderr}")
            };
            // opencode includes exit handling but returns combined; we just return combined
            if !out.status.success() && combined.is_empty() {
                Ok(format!(
                    "exit {} (no output)",
                    out.status.code().unwrap_or(-1)
                ))
            } else {
                Ok(combined)
            }
        }
        Ok(Err(e)) => Err(format!("bash spawn failed: {e}")),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "command timed out after {}ms: {command}",
            dur.as_millis()
        )),
        Err(e) => Err(format!("bash channel error: {e}")),
    }
}

fn read_path(file_path: &str, offset: Option<u64>, limit: Option<u64>) -> Result<Value, String> {
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("File not found: {file_path}"));
    }
    if path.is_dir() {
        let mut entries = std::fs::read_dir(path)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if e.path().is_dir() {
                    format!("{name}/")
                } else {
                    name
                }
            })
            .collect::<Vec<_>>();
        entries.sort();
        let total = entries.len();
        // opencode returns directory listing with trailing / for dirs
        let out = entries.join("\n");
        return Ok(json!({
            "path": file_path,
            "type": "directory",
            "entries": entries,
            "output": out,
            "totalEntries": total
        }));
    }
    // file
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {file_path}: {e}"))?;
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();
    let off = offset.unwrap_or(1).saturating_sub(1) as usize;
    let lim = limit.unwrap_or(DEFAULT_READ_LIMIT as u64) as usize;
    if off >= total_lines && total_lines != 0 {
        return Ok(Value::String(format!("<path>{file_path}</path>\n<type>file</type>\n<content>\n(empty, offset beyond file)\n</content>")));
    }
    let slice = if total_lines == 0 {
        vec![]
    } else {
        let end = std::cmp::min(off + lim, total_lines);
        lines[off..end].to_vec()
    };
    let mut out = String::new();
    out.push_str(&format!(
        "<path>{file_path}</path>\n<type>file</type>\n<content>\n"
    ));
    for (i, line) in slice.iter().enumerate() {
        let lineno = off + i + 1;
        let truncated = if line.len() > MAX_LINE_LENGTH {
            format!(
                "{}... (line truncated to {} chars)",
                &line[..MAX_LINE_LENGTH],
                MAX_LINE_LENGTH
            )
        } else {
            (*line).to_string()
        };
        out.push_str(&format!("{lineno}: {truncated}\n"));
    }
    if slice.len() < total_lines.saturating_sub(off) {
        out.push_str(&format!(
            "\n(Truncated, total {} lines, showing {} from offset {})",
            total_lines,
            slice.len(),
            off + 1
        ));
    }
    out.push_str("\n</content>");
    Ok(Value::String(out))
}

fn write_path(file_path: &str, content: &str) -> Result<Value, String> {
    let path = Path::new(file_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create dirs for {file_path}: {e}"))?;
        }
    }
    std::fs::write(path, content).map_err(|e| format!("failed to write {file_path}: {e}"))?;
    Ok(json!({ "wrote": file_path, "bytes": content.len() }))
}

fn edit_path(
    file_path: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> Result<Value, String> {
    if old_string == new_string {
        return Err("oldString and newString are identical".into());
    }
    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("File not found: {file_path}"));
    }
    if path.is_dir() {
        return Err(format!("Path is a directory, not a file: {file_path}"));
    }
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {file_path}: {e}"))?;
    if old_string.is_empty() {
        return Err("oldString cannot be empty".into());
    }
    let count = content.matches(old_string).count();
    if count == 0 {
        return Err("oldString not found in content".into());
    }
    if !replace_all && count > 1 {
        return Err("Found multiple matches for oldString. Provide more surrounding lines to make it unique or use replaceAll=true".into());
    }
    let new_content = if replace_all {
        content.replace(old_string, new_string)
    } else {
        content.replacen(old_string, new_string, 1)
    };
    std::fs::write(path, &new_content).map_err(|e| format!("failed to write {file_path}: {e}"))?;
    Ok(json!({ "edited": file_path, "replacements": if replace_all { count } else { 1 } }))
}

/// Execute a single tool call against the live sessions and return its result
/// text (truncated for the token budget).
pub fn execute(tc: &ToolCall, ctx: &ToolContext) -> Result<String, String> {
    let args: Value = serde_json::from_str(&tc.function.arguments).unwrap_or(Value::Null);

    if ctx.action_first && !ctx.bash_used.load(Ordering::SeqCst) && tc.function.name != "bash" {
        return Err(format!(
            "action_first: use bash before '{}' for this RE task. Start with `file`, `ls`, and `r2 -AA -q -c 'izz; afl; pdf @ main; px ...'`, then use Python/uv to build the solver. Do not inspect this binary with the UI-only wrapper first.",
            tc.function.name
        ));
    }

    // --- doom_loop: same as opencode's permission doom_loop (ask after 3 identical calls) ---
    // Prevents redundant read/grep loops like `search {"pattern":"serial"}` x3 that stalled
    // the Orrery run (see transcript.md for history 0→32 with 15 redundant searches).
    // We fail fast so the model must try a different tool/args (e.g. bash+r2 or write+python).
    {
        let key = format!("{}:{}", tc.function.name, tc.function.arguments);
        let mut map = doom_tracker().lock().unwrap_or_else(|e| e.into_inner());
        let cnt = map.entry(key.clone()).or_insert(0);
        *cnt += 1;
        if *cnt >= 3 {
            return Err(format!(
                "doom_loop: tool '{}' repeated 3 times with identical args. {}",
                tc.function.name,
                match tc.function.name.as_str() {
                    "read" => "File already read — use edit/write or read with different offset/limit, or use bash to inspect via r2/python.",
                    "grep" | "search" | "glob" => "Search already returned empty/no new results — try bash with r2 (e.g. `r2 -AA -q -c 'izz; afl; pdf @ 0x140002b60'`) or narrow pattern with include/path.",
                    "bash" => "Same bash command repeated — check output truncation (12k) or try different r2 address/python script.",
                    _ => "Try a different tool or different arguments."
                }
            ));
        }
        if map.len() > 128 {
            map.clear();
        }
    }

    let result: Result<Value, String> = match tc.function.name.as_str() {
        // -- opencode parity --
        "bash" => {
            ctx.bash_used.store(true, Ordering::SeqCst);
            let command = get_str(&args, "command")?;
            let lower = command.to_ascii_lowercase();
            let bash_call = ctx.bash_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if lower.contains("python") || lower.contains("uv ") || lower.contains("uv\n") {
                ctx.python_used.store(true, Ordering::SeqCst);
            } else if ctx.action_first && bash_call > 2 && !ctx.python_used.load(Ordering::SeqCst) {
                return Err("action_first: reconnaissance budget exhausted after two bash calls. Start the executable phase now: use `uv run --with numpy --with numba python /tmp/keygen.py` (or write it first), and only use targeted r2 output inside a Python-driven command. Do not run another standalone r2/afl/pdf/search command.".into());
            }
            if lower.contains("pdf @") || lower.contains("pdc @") || lower.contains("pdgj @") {
                return Err("action_first: broad decompilation is disabled for agent bash calls because it produces huge output and stalls the solve. Use targeted r2 commands (`izz; iz; afl~main; axt @ <string>`, `pd 80 @ <address>`, `p8 32 @ <address>`, `ps @ <address>`) and then switch to Python/uv to model or brute-force. Do not retry `pdf`/`pdc`/`pdgj`.".into());
            }
            let workdir = get_str_opt(&args, "workdir");
            let timeout = args.get("timeout").and_then(|v| v.as_u64());
            let out = bash_execute_simple(&command, workdir, timeout)?;
            Ok(Value::String(out))
        }
        "read" => {
            let file_path = get_str(&args, "filePath")?;
            let offset = args.get("offset").and_then(|v| v.as_u64());
            let limit = args.get("limit").and_then(|v| v.as_u64());
            read_path(&file_path, offset, limit)
        }
        "write" => {
            let file_path = get_str(&args, "filePath")?;
            let content = get_str(&args, "content")?;
            write_path(&file_path, &content)
        }
        "edit" => {
            let file_path = get_str(&args, "filePath")?;
            let old_string = get_str(&args, "oldString")?;
            let new_string = get_str(&args, "newString")?;
            let replace_all = get_bool_opt(&args, "replaceAll", false);
            edit_path(&file_path, &old_string, &new_string, replace_all)
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
                action_first: false,
                bash_used: Arc::new(AtomicBool::new(false)),
                bash_calls: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                python_used: Arc::new(AtomicBool::new(false)),
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
            for name in ["read", "nope"] {
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
                    err.contains("no binary loaded")
                        || err.contains("debugger not started")
                        || err.contains("unknown tool")
                        || err.contains("missing string")
                        || err.contains("File not found"),
                    "{name}: {err}"
                );
            }
        }

        #[test]
        fn bash_tool_executes() {
            let c = ctx();
            let tc = ToolCall {
                id: "i".into(),
                call_type: "function".into(),
                function: ToolCallFn {
                    name: "bash".into(),
                    arguments: r#"{"command":"echo hello; echo err 1>&2"}"#.into(),
                },
            };
            let out = execute(&tc, &c).unwrap();
            assert!(out.contains("hello"), "bash stdout: {out}");
        }

        #[test]
        fn agent_must_start_with_bash() {
            let c = ToolContext {
                action_first: true,
                bash_used: Arc::new(AtomicBool::new(false)),
                ..ctx()
            };
            let tc = ToolCall {
                id: "i".into(),
                call_type: "function".into(),
                function: ToolCallFn {
                    name: "read".into(),
                    arguments: r#"{"filePath":"/tmp/anything"}"#.into(),
                },
            };
            let err = execute(&tc, &c).unwrap_err();
            assert!(err.contains("action_first"));
        }

        #[test]
        fn read_write_edit_roundtrip() {
            let dir = std::env::temp_dir().join(format!("recurse-test-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let file = dir.join("hello.txt");
            let fp = file.to_string_lossy().into_owned();
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
                &mk(
                    "write",
                    json!({"filePath": fp, "content": "line1\nline2\n"}),
                ),
                &c,
            )
            .unwrap();
            let out = execute(&mk("read", json!({"filePath": fp})), &c).unwrap();
            assert!(out.contains("line1"), "read: {out}");
            execute(
                &mk(
                    "edit",
                    json!({"filePath": fp, "oldString": "line1", "newString": "hello"}),
                ),
                &c,
            )
            .unwrap();
            let out2 = execute(&mk("read", json!({"filePath": fp})), &c).unwrap();
            assert!(out2.contains("hello"), "edit: {out2}");
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn skill_todowrite_question_schema_present() {
            // Minimal schema for now: bash, read, write, edit only.
            let names: Vec<String> = schema()
                .iter()
                .filter_map(|v| v["function"]["name"].as_str().map(|s| s.to_string()))
                .collect();
            for need in ["bash", "read", "write", "edit"] {
                assert!(
                    names.contains(&need.to_string()),
                    "missing tool {need} in schema: {names:?}"
                );
            }
            for hidden in [
                "apply_patch",
                "todowrite",
                "grep",
                "glob",
                "skill",
                "question",
                "disassemble",
                "decompile",
                "search",
                "debug_start",
            ] {
                assert!(
                    !names.contains(&hidden.to_string()),
                    "native tool {hidden} must remain UI-only"
                );
            }
        }
    }
}
