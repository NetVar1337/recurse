//! Headless CLI that exposes the same `Agent` the Tauri UI uses, but without a
//! WebView.  Every `AgentEvent` is streamed deterministically to stdout / a
//! JSONL file so you can `diff` runs, grep for `tool_call:bash`, or replay a
//! session exactly.
//!
//! Agent-first but human-readable: each `run` appends a Markdown transcript
//! (`transcript.md`) and a JSONL event log (`events.jsonl`) in the session
//! dir, so both the agent (JSON) and a human (Markdown) can read the same
//! session. Back-and-forth is handled by `--session` / `--continue` / `--interactive`.
//!
//! Opencode interop: `recurse-cli export --opencode` writes a JSON file that
//! `opencode import <file>` can read, and `recurse-cli import --file <export.json>`
//! reads opencode's export format into `~/.recurse`.
//!
//! ```bash
//! cargo run --bin recurse-cli -- run --binary ./fixtures/evals/easy_strcmp.bin \
//!   --prompt "find the flag" --verbose --json-log ./run.jsonl
//! cargo run --bin recurse-cli -- tools
//! cargo run --bin recurse-cli -- history --session s-xxx --project pwn101 --format human
//! cargo run --bin recurse-cli -- export --session s-xxx --project pwn101 --opencode --output /tmp/op.json
//! opencode import /tmp/op.json  # opencode now sees the session
//! ```

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;

use crate::agent::{Agent, AgentEvent, ChatMessage, LlmConfig};
use crate::engine;
use crate::memory;
use crate::project;
use crate::session::R2Session;
use crate::sessions;
use crate::tools::ToolContext;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "recurse-cli",
    version,
    about = "Headless agent harness for Recurse — deterministic r2 + bash + file tools"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run one agent turn headlessly and stream events deterministically.
    Run(RunArgs),
    /// List the tool schema the agent sees (same payload the UI sends the model).
    Tools,
    /// List available LLM models (needs OPENROUTER_API_KEY or config).
    Models,
    /// Show agent history for a session (agent-first JSON, human-readable Markdown, or raw JSON).
    History(HistoryArgs),
    /// Export a recurse session to JSON (optionally opencode-compatible for `opencode import`).
    Export(ExportArgs),
    /// Import a session from JSON (opencode export format or recurse chat.json).
    Import(ImportArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct RunArgs {
    /// Path to target binary. Mutually exclusive with --project.
    #[arg(long)]
    pub binary: Option<PathBuf>,

    /// Project name (loads binary_path from ~/.recurse/<project>/project.json).
    #[arg(long)]
    pub project: Option<String>,

    /// User prompt / task for the agent. If omitted, reads from stdin when piped, or enters interactive REPL when --interactive.
    #[arg(long, short = 'p')]
    pub prompt: Option<String>,

    /// Positional prompt (alternative to --prompt).
    #[arg(value_name = "PROMPT")]
    pub prompt_pos: Vec<String>,

    /// Model override, e.g. openrouter/auto or anthropic/claude-sonnet-4
    #[arg(long)]
    pub model: Option<String>,

    /// Endpoint override
    #[arg(long)]
    pub endpoint: Option<String>,

    /// API key override (else OPENROUTER_API_KEY / ~/.recurse/config.json)
    #[arg(long)]
    pub api_key: Option<String>,

    /// Existing session id to continue (else a new session is created). Use --continue to pick last session.
    #[arg(long)]
    pub session: Option<String>,

    /// Continue the most recent session for this project/binary (like `opencode --continue`).
    #[arg(long, default_value_t = false)]
    pub continue_last: bool,

    /// Interactive REPL: after one turn completes, read next prompt from stdin without exiting (back-and-forth).
    #[arg(long, default_value_t = false)]
    pub interactive: bool,

    /// Write every AgentEvent as a JSON line to this file (deterministic replay). Defaults to <session>/events.jsonl when omitted.
    #[arg(long)]
    pub json_log: Option<PathBuf>,

    /// Also print events as pretty JSON lines to stdout (default is human-readable).
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Verbose: print reasoning deltas and full tool arguments / truncations.
    #[arg(long, short = 'v', default_value_t = false)]
    pub verbose: bool,

    /// Dry-run: don't call the LLM, just echo the prompt (tests harness without API key).
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct HistoryArgs {
    /// Project name (defaults to "default")
    #[arg(long)]
    pub project: Option<String>,
    /// Session id
    #[arg(long)]
    pub session: String,
    /// Output format: json (raw ChatMessage array), human (pretty), markdown (transcript.md)
    #[arg(long, value_enum, default_value_t = HistoryFormat::Human)]
    pub format: HistoryFormat,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum HistoryFormat {
    Json,
    Human,
    Markdown,
}

#[derive(Parser, Debug, Clone)]
pub struct ExportArgs {
    /// Project name (defaults to default)
    #[arg(long)]
    pub project: Option<String>,
    /// Session id
    #[arg(long)]
    pub session: String,
    /// Output file (default stdout)
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Emit opencode-compatible JSON (info + messages/parts) for `opencode import`
    #[arg(long, default_value_t = false)]
    pub opencode: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ImportArgs {
    /// Path to JSON file (recurse chat.json or opencode export)
    #[arg(long)]
    pub file: PathBuf,
    /// Target project name (defaults to file's project or "default")
    #[arg(long)]
    pub project: Option<String>,
    /// Session id to create (else generated)
    #[arg(long)]
    pub session: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

pub fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Tools => cmd_tools(),
        Commands::Models => cmd_models(),
        Commands::History(args) => cmd_history(args),
        Commands::Export(args) => cmd_export(args),
        Commands::Import(args) => cmd_import(args),
        Commands::Run(args) => cmd_run(args),
    }
}

fn cmd_tools() -> Result<(), String> {
    let schema = crate::tools::schema();
    println!(
        "{}",
        serde_json::to_string_pretty(&schema).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn cmd_models() -> Result<(), String> {
    let models = crate::agent::fetch_models()?;
    for m in models {
        println!(
            "{}\t{}\tfree={} ctx={} price={}",
            m.id, m.name, m.free, m.context_length, m.prompt_price
        );
    }
    Ok(())
}

fn cmd_history(args: HistoryArgs) -> Result<(), String> {
    match args.format {
        HistoryFormat::Json => {
            let json = sessions::load_history(args.project.as_deref(), &args.session)
                .ok_or_else(|| format!("no history for session {}", args.session))?;
            let msgs: Value = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&msgs).map_err(|e| e.to_string())?
            );
        }
        HistoryFormat::Human => {
            let json = sessions::load_history(args.project.as_deref(), &args.session)
                .ok_or_else(|| format!("no history for session {}", args.session))?;
            let msgs: Vec<ChatMessage> = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            for (i, m) in msgs.iter().enumerate() {
                let role = &m.role;
                let content = m.content.as_deref().unwrap_or("");
                let reasoning = m.reasoning.as_deref().unwrap_or("");
                println!("--- message {} [{}] ---", i + 1, role);
                if !reasoning.is_empty() {
                    println!("[reasoning] {}", reasoning);
                }
                if let Some(tcs) = &m.tool_calls {
                    for tc in tcs {
                        println!("[tool_call] {} {}", tc.function.name, tc.function.arguments);
                    }
                }
                if let Some(tid) = &m.tool_call_id {
                    println!("[tool_result {}] {}", tid, content);
                } else if !content.is_empty() {
                    println!("{}", content);
                }
                println!();
            }
        }
        HistoryFormat::Markdown => {
            let md_path = sessions::session_dir(args.project.as_deref(), &args.session)
                .map(|p| p.join("transcript.md"))
                .map_err(|e| e.to_string())?;
            if md_path.exists() {
                let md = std::fs::read_to_string(&md_path).map_err(|e| e.to_string())?;
                println!("{}", md);
            } else {
                // Fallback: render from chat.json
                let json = sessions::load_history(args.project.as_deref(), &args.session)
                    .ok_or_else(|| format!("no history for session {}", args.session))?;
                let msgs: Vec<ChatMessage> =
                    serde_json::from_str(&json).map_err(|e| e.to_string())?;
                println!("{}", render_markdown(&msgs, &args.session));
            }
        }
    }
    Ok(())
}

fn cmd_export(args: ExportArgs) -> Result<(), String> {
    let session = sessions::get(args.project.as_deref(), &args.session)
        .map_err(|e| format!("get session: {e}"))?;
    let history_json = sessions::load_history(args.project.as_deref(), &args.session)
        .unwrap_or_else(|| "[]".into());
    let msgs: Vec<ChatMessage> = serde_json::from_str(&history_json).map_err(|e| e.to_string())?;

    let out_value = if args.opencode {
        // Opencode-compatible export: { info, messages: [{info, parts}] }
        // Opencode SessionID must start with "ses" — map our s-... ids to ses_...
        let op_id = {
            let alnum: String = session.id.chars().filter(|c| c.is_alphanumeric()).collect();
            format!("ses_{}", alnum)
        };
        let info = serde_json::json!({
            "id": op_id,
            "slug": session.name.to_lowercase().replace(' ', "-"),
            "projectID": "global",
            "directory": project::project_dir(args.project.as_deref().unwrap_or("default")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
            "path": project::project_dir(args.project.as_deref().unwrap_or("default")).map(|p| p.file_name().and_then(|n| n.to_str()).unwrap_or("default").to_string()).unwrap_or_default(),
            "title": session.name,
            "agent": "build",
            "model": { "id": session.model, "providerID": "opencode" },
            "version": "1.0.0",
            "time": { "created": session.created_at, "updated": session.updated_at },
            "tokens": { "input": 0, "output": 0, "reasoning": 0, "cache": { "read": 0, "write": 0 } }
        });
        let mut messages = Vec::new();
        let mut prev_id: Option<String> = None;
        for (idx, m) in msgs.iter().enumerate() {
            let msg_id = format!("msg_{:04}_{}", idx, &op_id[4..8]);
            let mut parts = Vec::new();
            if let Some(reasoning) = &m.reasoning {
                if !reasoning.is_empty() {
                    parts.push(serde_json::json!({"type":"reasoning","text": reasoning, "id": format!("prt_{:04}_r_{}", idx, &op_id[4..8]), "sessionID": op_id, "messageID": msg_id}));
                }
            }
            if let Some(content) = &m.content {
                if !content.is_empty() {
                    parts.push(serde_json::json!({"type":"text","text": content, "id": format!("prt_{:04}_t_{}", idx, &op_id[4..8]), "sessionID": op_id, "messageID": msg_id}));
                }
            }
            if let Some(tcs) = &m.tool_calls {
                for tc in tcs {
                    parts.push(serde_json::json!({
                        "type":"tool","tool": tc.function.name, "callID": tc.id,
                        "state": {"status":"completed","input": serde_json::from_str::<Value>(&tc.function.arguments).unwrap_or(Value::Null)},
                        "id": format!("prt_{}_{}", idx, tc.id), "sessionID": op_id, "messageID": msg_id
                    }));
                }
            }
            if m.tool_call_id.is_some() {
                // tool result already as text part above
            }
            // Ensure at least one part per message (opencode requires messages have parts)
            if parts.is_empty() {
                parts.push(serde_json::json!({"type":"text","text": "", "id": format!("prt_{:04}_empty", idx), "sessionID": op_id, "messageID": msg_id}));
            }
            let role = m.role.clone();
            let directory = project::project_dir(args.project.as_deref().unwrap_or("default"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "/tmp".into());
            let mut info = serde_json::json!({
                "id": msg_id, "role": role, "agent": "build", "mode": "build", "path": {"cwd": directory, "root": "/"}, "providerID": "opencode", "modelID": session.model, "model": { "modelID": session.model, "providerID": "opencode", "id": session.model }, "time": { "created": session.created_at, "completed": session.updated_at }, "sessionID": op_id, "cost": 0, "tokens": {"total": 0, "input": 0, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}}, "finish": "stop"
            });
            if let Some(pid) = prev_id.clone() {
                info["parentID"] = serde_json::json!(pid);
            }
            messages.push(serde_json::json!({
                "info": info,
                "parts": parts
            }));
            prev_id = Some(msg_id);
        }
        serde_json::json!({ "info": info, "messages": messages })
    } else {
        serde_json::json!({
            "session": session,
            "messages": msgs
        })
    };

    let pretty = serde_json::to_string_pretty(&out_value).map_err(|e| e.to_string())?;
    if let Some(out) = args.output {
        std::fs::write(&out, pretty).map_err(|e| e.to_string())?;
        eprintln!(
            "[recurse-cli] exported {} to {}",
            args.session,
            out.display()
        );
    } else {
        println!("{}", pretty);
    }
    Ok(())
}

fn cmd_import(args: ImportArgs) -> Result<(), String> {
    let raw = std::fs::read_to_string(&args.file)
        .map_err(|e| format!("read {}: {e}", args.file.display()))?;
    // Opencode's `export` prints "Exporting session: ses_..." to stdout before JSON when
    // redirected via `> file`; be tolerant and slice to first `{`.
    let data = raw
        .trim_start()
        .find('{')
        .map(|i| &raw[i..])
        .unwrap_or(&raw);
    let v: Value = serde_json::from_str(data).map_err(|e| {
        format!(
            "parse {}: {e} (first 200 chars: {})",
            args.file.display(),
            &data[..data.len().min(200)]
        )
    })?;

    // Detect opencode export (has "info" + "messages" with parts) vs recurse export (has "session" + "messages" as ChatMessage)
    let (session_id, chat_json) = if v.get("info").is_some() && v.get("messages").is_some() {
        // opencode format
        let info = &v["info"];
        let sid = args.session.clone().unwrap_or_else(|| {
            info.get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("imported")
                .to_string()
        });
        let sid = if sid.starts_with("ses_") {
            format!("s-op-{}", &sid[4..8])
        } else {
            sid
        };
        let messages = v
            .get("messages")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        let mut chat: Vec<ChatMessage> = Vec::new();
        for m in messages {
            let info = m.get("info").cloned().unwrap_or(Value::Null);
            let role = info
                .get("role")
                .and_then(|x| x.as_str())
                .unwrap_or("assistant")
                .to_string();
            let parts = m
                .get("parts")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            let mut content: Vec<String> = Vec::new();
            let mut tool_calls = Vec::new();
            let mut reasoning: Option<String> = None;
            for p in parts {
                let typ = p.get("type").and_then(|x| x.as_str()).unwrap_or("");
                match typ {
                    "text" => {
                        if let Some(t) = p.get("text").and_then(|x| x.as_str()) {
                            content.push(t.to_string());
                        }
                    }
                    "reasoning" => {
                        if let Some(t) = p.get("text").and_then(|x| x.as_str()) {
                            reasoning = Some(t.to_string());
                        }
                    }
                    "tool" => {
                        let tool = p
                            .get("tool")
                            .and_then(|x| x.as_str())
                            .unwrap_or("bash")
                            .to_string();
                        let call_id = p
                            .get("callID")
                            .and_then(|x| x.as_str())
                            .unwrap_or("call_import")
                            .to_string();
                        let input = p
                            .get("state")
                            .and_then(|s| s.get("input"))
                            .cloned()
                            .unwrap_or(Value::Null);
                        tool_calls.push(crate::agent::ToolCall {
                            id: call_id,
                            call_type: "function".into(),
                            function: crate::agent::ToolCallFn {
                                name: tool,
                                arguments: input.to_string(),
                            },
                        });
                    }
                    _ => {}
                }
            }
            let text = if content.is_empty() {
                None
            } else {
                Some(content.join("\n"))
            };
            let tc_opt = if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            };
            let mut msg = ChatMessage {
                role: role.clone(),
                content: text,
                tool_calls: tc_opt,
                tool_call_id: None,
                reasoning: reasoning.clone(),
            };
            // For tool results, opencode stores them as separate tool messages; we approximate
            if role == "tool" {
                msg.tool_call_id = Some("imported".into());
            }
            chat.push(msg);
        }
        (
            sid,
            serde_json::to_string(&chat).map_err(|e| e.to_string())?,
        )
    } else if v.get("session").is_some() {
        let sess = &v["session"];
        let sid = args
            .session
            .clone()
            .or_else(|| {
                sess.get("id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| {
                format!(
                    "s-import-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis()
                )
            });
        let msgs = v.get("messages").cloned().unwrap_or(Value::Array(vec![]));
        (
            sid,
            serde_json::to_string(&msgs).map_err(|e| e.to_string())?,
        )
    } else if v.is_array() {
        // raw ChatMessage array
        let sid = args.session.clone().unwrap_or_else(|| {
            format!(
                "s-import-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            )
        });
        (sid, data.to_string())
    } else {
        return Err("unrecognized import format (expected opencode export, recurse export, or ChatMessage array)".into());
    };

    let project = args.project.clone();
    let model = "imported".to_string();
    // Ensure session exists — clone id for the closure to avoid borrow issues
    let sid_for_closure = session_id.clone();
    let _ = sessions::get(project.as_deref(), &session_id).or_else(|_| {
        let sid = sid_for_closure.clone();
        sessions::create(project.as_deref(), &model).map(|s| {
            // rename to requested id by moving dir (hack: create then rename)
            let src = sessions::session_dir(project.as_deref(), &s.id).unwrap();
            let dst = sessions::session_dir(project.as_deref(), &sid).unwrap();
            if src != dst {
                let _ = std::fs::rename(&src, &dst);
                // also fix session.json id
                if let Ok(mut sess) = sessions::get(project.as_deref(), &sid) {
                    sess.id = sid.clone();
                    let _ = std::fs::write(
                        dst.join("session.json"),
                        serde_json::to_string_pretty(&sess).unwrap_or_default(),
                    );
                }
            }
            sessions::get(project.as_deref(), &sid).unwrap()
        })
    })?;
    sessions::save_history(project.as_deref(), &session_id, &chat_json)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "[recurse-cli] imported {} ({} bytes) into project={} session={}",
        args.file.display(),
        chat_json.len(),
        project.as_deref().unwrap_or("default"),
        &session_id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render_markdown(msgs: &[ChatMessage], session_id: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Session {}\n\n", session_id));
    for (i, m) in msgs.iter().enumerate() {
        out.push_str(&format!(
            "## {}: {} ({} of {})\n\n",
            m.role,
            m.content
                .as_deref()
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or(""),
            i + 1,
            msgs.len()
        ));
        if let Some(r) = &m.reasoning {
            if !r.is_empty() {
                out.push_str(&format!("> Reasoning: {}\n\n", r));
            }
        }
        if let Some(tcs) = &m.tool_calls {
            for tc in tcs {
                out.push_str(&format!(
                    "**Tool call `{}`** `id={}`\n```json\n{}\n```\n\n",
                    tc.function.name, tc.id, tc.function.arguments
                ));
            }
        }
        if let Some(tid) = &m.tool_call_id {
            out.push_str(&format!(
                "*Tool result {}*\n```\n{}\n```\n\n",
                tid,
                m.content.as_deref().unwrap_or("")
            ));
        } else if m.tool_calls.is_none() {
            if let Some(c) = &m.content {
                if !c.is_empty() {
                    out.push_str(&format!("{}\n\n", c));
                }
            }
        }
        out.push_str("---\n\n");
    }
    out
}

fn write_transcript(
    project: Option<&str>,
    session_id: &str,
    prompt: &str,
    agent: &Agent,
    info: &Value,
    duration_ms: u128,
) {
    let msgs = agent.messages();
    let md = render_markdown(msgs, session_id);
    let header = format!(
        "# Transcript for {}\n\nPrompt: {}\nBinary info: {}\nDuration: {}ms\n\n",
        session_id, prompt, info, duration_ms
    );
    let full = header + &md;
    if let Ok(dir) = sessions::session_dir(project, session_id) {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("transcript.md");
        let _ = std::fs::write(&path, full);
        // Also append to per-project log for human browsing
        if let Ok(proj_dir) = project::project_dir(project.unwrap_or("default")) {
            let log = proj_dir.join("transcript.log");
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .and_then(|mut f| {
                    writeln!(
                        f,
                        "\n=== {} session={} ===\nPrompt: {}\nMessages: {}\n",
                        chrono_lite(),
                        session_id,
                        prompt,
                        msgs.len()
                    )
                });
        }
    }
}

fn chrono_lite() -> String {
    // Cheap timestamp without adding chrono dep: seconds since epoch
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}", secs)
}

fn cmd_run(mut args: RunArgs) -> Result<(), String> {
    // Agent-first but human-readable: mark CLI mode for tools like `question` to prompt via tty
    // SAFETY: single-threaded setup path before any threads that read this.
    unsafe {
        std::env::set_var("RECURSE_CLI", "1");
    }

    // If --interactive and no prompt, enter REPL loop (back-and-forth)
    if args.interactive
        && args.prompt.is_none()
        && args.prompt_pos.is_empty()
        && atty::is(atty::Stream::Stdin)
    {
        return cmd_run_repl(args);
    }

    // Resolve prompt (single turn)
    let prompt = resolve_prompt(&mut args)?;

    // Resolve binary path
    let binary_path = resolve_binary(&args)?;

    // --continue: pick most recent session if --session not given
    let mut session_id_opt = args.session.clone();
    if args.continue_last && session_id_opt.is_none() {
        let proj = args.project.as_deref();
        if let Ok(list) = sessions::list(proj) {
            if let Some(s) = list.first() {
                eprintln!("[recurse-cli] --continue: using session {}", s.id);
                session_id_opt = Some(s.id.clone());
            }
        }
    }

    run_one_turn(args, prompt, binary_path, session_id_opt)
}

fn resolve_prompt(args: &mut RunArgs) -> Result<String, String> {
    if let Some(p) = args.prompt.take() {
        if !p.trim().is_empty() {
            return Ok(p);
        }
    }
    if !args.prompt_pos.is_empty() {
        return Ok(args.prompt_pos.join(" "));
    }
    if !atty::is(atty::Stream::Stdin) {
        let mut buf = String::new();
        use std::io::Read;
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| e.to_string())?;
        let t = buf.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    Err("prompt required: --prompt \"<task>\" or positional PROMPT or piped stdin (or --interactive for REPL)".into())
}

fn resolve_binary(args: &RunArgs) -> Result<PathBuf, String> {
    if let Some(p) = args.binary.clone() {
        if !p.exists() {
            return Err(format!("binary not found: {}", p.display()));
        }
        Ok(p)
    } else if let Some(proj) = args.project.clone() {
        let pr = project::get(&proj).map_err(|e| format!("project {proj}: {e}"))?;
        project::touch(&proj).ok();
        let pb = PathBuf::from(pr.binary_path);
        if !pb.exists() {
            return Err(format!(
                "project {} binary not found: {}",
                proj,
                pb.display()
            ));
        }
        Ok(pb)
    } else {
        Err("either --binary <path> or --project <name> is required".into())
    }
}

fn run_one_turn(
    args: RunArgs,
    prompt: String,
    binary_path: PathBuf,
    session_id_opt: Option<String>,
) -> Result<(), String> {
    // Resolve LLM config with CLI overrides
    let mut cfg = LlmConfig::default();
    if let Some(m) = args.model.clone() {
        cfg.model = m;
    }
    if let Some(e) = args.endpoint.clone() {
        cfg.endpoint = e;
    }
    if let Some(k) = args.api_key.clone() {
        cfg.api_key = Some(k);
    }
    if args.dry_run {
        cfg.api_key = None;
    }

    let proj_name = args.project.clone();
    let session_id = if let Some(sid) = session_id_opt {
        sessions::get(proj_name.as_deref(), &sid).map_err(|e| format!("session {sid}: {e}"))?;
        sid
    } else {
        let s = sessions::create(proj_name.as_deref(), &cfg.model).map_err(|e| e.to_string())?;
        eprintln!(
            "[recurse-cli] new session {} (project={})",
            s.id,
            proj_name.as_deref().unwrap_or("default")
        );
        s.id
    };

    // Load prior history into agent (back-and-forth)
    let mut agent = Agent::new();
    if let Some(json) = sessions::load_history(proj_name.as_deref(), &session_id) {
        if let Ok(msgs) = serde_json::from_str(&json) {
            agent.load(msgs);
        }
    }
    let history_len_before = agent.messages().len();

    // Open binary via R2Session
    eprintln!("[recurse-cli] opening {} ...", binary_path.display());
    let r2 = R2Session::open(binary_path.to_string_lossy().to_string())?;
    let info = engine::info(&r2);
    eprintln!(
        "[recurse-cli] binary: {}",
        serde_json::to_string(&info).unwrap_or_default()
    );
    eprintln!("[recurse-cli] analyzing (aaa) ...");
    let _ = r2.analyze();

    let session = Arc::new(Mutex::new(Some(r2)));
    let debug = Arc::new(Mutex::new(None::<R2Session>));
    let debug_stdin: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
    let debug_busy = Arc::new(AtomicBool::new(false));
    let debug_pid = Arc::new(AtomicU32::new(0));
    let debug_output_done = Arc::new(AtomicBool::new(false));
    let memory_str = memory::summary_for(proj_name.as_deref(), &prompt);
    if !memory_str.is_empty() {
        eprintln!("[recurse-cli] memory: {} chars", memory_str.len());
    }

    // Determine json_log path: explicit or <session>/events.jsonl (agent-first log)
    let json_log_path = args.json_log.clone().or_else(|| {
        sessions::session_dir(proj_name.as_deref(), &session_id)
            .ok()
            .map(|p| p.join("events.jsonl"))
    });
    let json_writer: Option<Arc<Mutex<BufWriter<File>>>> = if let Some(p) = &json_log_path {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match File::create(p) {
            Ok(f) => {
                eprintln!("[recurse-cli] json-log: {}", p.display());
                Some(Arc::new(Mutex::new(BufWriter::new(f))))
            }
            Err(e) => {
                eprintln!("[recurse-cli] warn: create {}: {e}", p.display());
                None
            }
        }
    } else {
        None
    };

    // Write deterministic header for replay (system prompt + tool schema + info)
    if let Some(w) = &json_writer {
        if let Ok(mut g) = w.lock() {
            let header = serde_json::json!({
                "kind": "header",
                "session": session_id,
                "project": proj_name,
                "binary": binary_path.to_string_lossy(),
                "prompt": prompt,
                "info": info,
                "memory_chars": memory_str.len(),
                "tools": crate::tools::schema().iter().map(|v| v.get("function").and_then(|f| f.get("name")).and_then(|n| n.as_str()).unwrap_or("")).collect::<Vec<_>>(),
                "model": cfg.model,
                "time": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
            });
            let _ = writeln!(g, "{}", header);
        }
    }

    let tools = crate::tools::schema();
    let path_str = session
        .lock()
        .map_err(|e| e.to_string())?
        .as_ref()
        .map(|s| s.path.to_string_lossy().to_string())
        .unwrap_or_default();
    let info_clone = session
        .lock()
        .map_err(|e| e.to_string())?
        .as_ref()
        .map(|s| s.info.clone())
        .unwrap_or(Value::Null);
    let run_id = session_id.clone();
    let verbose = args.verbose;
    let emit_json = args.json;

    #[derive(Default)]
    struct Counters {
        tool_calls: usize,
        tool_results: usize,
        tokens: usize,
        reasoning_chars: usize,
        errors: usize,
    }
    let counters = Arc::new(Mutex::new(Counters::default()));
    let counters_clone = counters.clone();

    let ctx = ToolContext {
        session: session.clone(),
        debug: debug.clone(),
        debug_stdin: debug_stdin.clone(),
        debug_busy: debug_busy.clone(),
        debug_pid: debug_pid.clone(),
        debug_output_done: debug_output_done.clone(),
        action_first: true,
        bash_used: Arc::new(AtomicBool::new(false)),
        bash_calls: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        python_used: Arc::new(AtomicBool::new(false)),
        project: proj_name.clone(),
    };

    let cancel = agent.cancel.clone();
    let _ = ctrlc::set_handler(move || {
        eprintln!("\n[recurse-cli] SIGINT -> request_cancel");
        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    let start = std::time::Instant::now();
    let emit = {
        let json_writer = json_writer.clone();
        let counters = counters_clone.clone();
        move |ev: AgentEvent| {
            if let Ok(mut c) = counters.lock() {
                match &ev {
                    AgentEvent::ToolCall { .. } => c.tool_calls += 1,
                    AgentEvent::ToolResult { .. } => c.tool_results += 1,
                    AgentEvent::Token { delta, .. } => c.tokens += delta.chars().count(),
                    AgentEvent::Reasoning { delta, .. } => {
                        c.reasoning_chars += delta.chars().count()
                    }
                    AgentEvent::Error { .. } => c.errors += 1,
                    _ => {}
                }
            }
            if let Some(w) = &json_writer {
                if let Ok(mut g) = w.lock() {
                    let line = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".into());
                    let _ = writeln!(g, "{}", line);
                }
            }
            if emit_json {
                println!(
                    "{}",
                    serde_json::to_string(&ev).unwrap_or_else(|_| "{}".into())
                );
            } else {
                match &ev {
                    AgentEvent::Reasoning { delta, .. } if verbose => eprint!("{}", delta),
                    AgentEvent::Reasoning { .. } => {}
                    AgentEvent::Token { delta, .. } => print!("{}", delta),
                    AgentEvent::ToolCall {
                        id,
                        name,
                        arguments,
                        ..
                    } => eprintln!(
                        "\n[tool_call:{}] {} {}",
                        id,
                        name,
                        truncate_for_log(arguments, verbose)
                    ),
                    AgentEvent::ToolResult {
                        id, name, result, ..
                    } => {
                        let status = if result.contains("tool error") {
                            "ERR"
                        } else {
                            "ok"
                        };
                        eprintln!(
                            "[tool_result:{}] {} [{}] -> {}",
                            id,
                            name,
                            status,
                            truncate_for_log(result, verbose)
                        );
                    }
                    AgentEvent::Done { content, .. } => eprintln!("\n[done] {}", content),
                    AgentEvent::Error { message, .. } => eprintln!("\n[error] {}", message),
                }
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().flush();
            }
        }
    };

    let mut emit_box: Box<dyn FnMut(AgentEvent)> = Box::new(emit);
    let mut exec = |tc: &crate::agent::ToolCall| crate::tools::execute(tc, &ctx);
    let res = agent.run(
        &run_id,
        &cfg,
        &path_str,
        &info_clone,
        &memory_str,
        &prompt,
        &tools,
        &mut exec,
        &mut *emit_box,
    );
    let elapsed = start.elapsed().as_millis();

    // Persist history + update transcript (human-readable, agent-first)
    if let Ok(json) = serde_json::to_string(agent.messages()) {
        let _ = sessions::save_history(proj_name.as_deref(), &session_id, &json);
        let _ = sessions::set_model(proj_name.as_deref(), &session_id, &cfg.model);
        let _ = sessions::touch(proj_name.as_deref(), &session_id);
        if let Ok(s) = sessions::get(proj_name.as_deref(), &session_id) {
            if s.name.is_empty() || s.name == "New session" {
                let title = crate::agent::generate_title(&cfg, &prompt);
                let _ = sessions::set_name(proj_name.as_deref(), &session_id, &title);
            }
        }
    }
    // Human-readable Markdown transcript (append)
    write_transcript(
        proj_name.as_deref(),
        &session_id,
        &prompt,
        &agent,
        &info_clone,
        elapsed,
    );
    // Also flush json_writer header counters
    let c = counters
        .lock()
        .map(|g| {
            format!(
                "tool_calls={} tool_results={} tokens={} reasoning_chars={} errors={}",
                g.tool_calls, g.tool_results, g.tokens, g.reasoning_chars, g.errors
            )
        })
        .unwrap_or_default();
    eprintln!(
        "\n[recurse-cli] finished session={} history={}→{} {} res={:?}",
        session_id,
        history_len_before,
        agent.messages().len(),
        c,
        res.as_ref().map(|_| "ok").unwrap_or("err")
    );
    if let Some(w) = json_writer {
        if let Ok(mut g) = w.lock() {
            let summary = serde_json::json!({"kind":"summary","session":session_id,"prompt":prompt,"counters":c,"elapsed_ms":elapsed,"result": res.as_ref().map(|_| "ok").unwrap_or("err"), "history_len": agent.messages().len()});
            let _ = writeln!(g, "{}", summary);
            let _ = g.flush();
        }
    }
    // If interactive and we succeeded, loop for back-and-forth
    if args.interactive && res.is_ok() {
        eprintln!("\n[recurse-cli] interactive: type next prompt (or 'exit'/'quit'):");
        let mut next_args = args.clone();
        next_args.session = Some(session_id.clone());
        next_args.prompt = None;
        next_args.prompt_pos.clear();
        // Re-enter REPL without re-opening binary? For determinism we keep same session but re-resolve binary each turn.
        // Use a simple loop reading lines.
        loop {
            eprint!("recurse[{}]> ", session_id);
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            if std::io::stdin()
                .read_line(&mut line)
                .map(|n| n == 0)
                .unwrap_or(true)
            {
                break;
            }
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if t == "exit" || t == "quit" {
                break;
            }
            let mut inner = next_args.clone();
            inner.prompt = Some(t.to_string());
            if let Err(e) = run_one_turn(
                inner,
                t.to_string(),
                binary_path.clone(),
                Some(session_id.clone()),
            ) {
                eprintln!("[recurse-cli] turn error: {e}");
            }
        }
    }

    res.map_err(|e| e)
}

fn cmd_run_repl(args: RunArgs) -> Result<(), String> {
    // REPL entry: no initial prompt, just loop
    let binary_path = resolve_binary(&args)?;
    let mut session_id: Option<String> = None;
    if args.continue_last {
        if let Ok(list) = sessions::list(args.project.as_deref()) {
            if let Some(s) = list.first() {
                session_id = Some(s.id.clone());
            }
        }
    }
    eprintln!(
        "[recurse-cli] interactive REPL for {} (project={})",
        binary_path.display(),
        args.project.as_deref().unwrap_or("default")
    );
    eprintln!("Type your task, or 'exit' to quit. Agent is deterministic; every turn is logged to <session>/events.jsonl + transcript.md");
    loop {
        eprint!(
            "recurse{}> ",
            session_id
                .as_deref()
                .map(|s| format!("[{}]", &s[..8]))
                .unwrap_or_default()
        );
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin()
            .read_line(&mut line)
            .map(|n| n == 0)
            .unwrap_or(true)
        {
            break;
        }
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t == "exit" || t == "quit" {
            break;
        }
        let mut inner = args.clone();
        inner.prompt = Some(t.to_string());
        inner.prompt_pos.clear();
        inner.interactive = false; // one turn per REPL iteration
        inner.session = session_id.clone();
        match run_one_turn(
            inner,
            t.to_string(),
            binary_path.clone(),
            session_id.clone(),
        ) {
            Ok(()) => {
                // Update session_id for next loop (if it was None, now it exists)
                if session_id.is_none() {
                    if let Ok(list) = sessions::list(args.project.as_deref()) {
                        if let Some(s) = list.first() {
                            session_id = Some(s.id.clone());
                        }
                    }
                }
            }
            Err(e) => eprintln!("[recurse-cli] error: {e}"),
        }
    }
    Ok(())
}

fn truncate_for_log(s: &str, verbose: bool) -> String {
    if verbose || s.len() <= 2000 {
        s.to_string()
    } else {
        let mut cut = 2000;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{} ...[truncated {} chars]", &s[..cut], s.len() - cut)
    }
}

// Tiny atty shim
mod atty {
    #[allow(dead_code)]
    pub enum Stream {
        Stdin,
        Stdout,
        Stderr,
    }
    pub fn is(s: Stream) -> bool {
        use std::io::IsTerminal;
        match s {
            Stream::Stdin => std::io::stdin().is_terminal(),
            Stream::Stdout => std::io::stdout().is_terminal(),
            Stream::Stderr => std::io::stderr().is_terminal(),
        }
    }
}
