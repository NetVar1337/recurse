//! Headless task runner: drives one crackme end-to-end through
//! [`librecurse::agent::Agent`] with debug tracing on, bounded turns and a
//! wall-clock timeout, then grades the final answer. Rust only.

use std::path::{Path, PathBuf};
use std::time::Duration;

use librecurse::agent::{Agent, AgentEvent, LlmConfig, PromptTarget, ToolCall};
use librecurse::memory::MemoryStore;

use crate::{contains_token, cost_usd, grade_flag, prompt_target_for, Task};

/// Eval-wide knobs. Everything a tier swap or nightly matrix would vary.
#[derive(Clone, Debug)]
pub struct EvalOpts {
    pub model: String,
    pub endpoint: String,
    pub api_key: String,
    pub max_turns: usize,
    pub timeout_secs: u64,
    pub corpus_dir: PathBuf,
    pub trace_dir: PathBuf,
}

impl EvalOpts {
    /// Resolve from the environment (`RECURSE_LLM_*`, `EVAL_*`), with the
    /// same defaults as the app. Missing API key is an error, not a panic.
    pub fn from_env(corpus_dir: PathBuf, trace_dir: PathBuf) -> Result<Self, String> {
        let fallback = LlmConfig::default();
        let api_key = fallback.api_key.filter(|k| !k.is_empty()).ok_or_else(|| {
            "no API key: set RECURSE_LLM_API_KEY or OPENROUTER_API_KEY".to_string()
        })?;
        Ok(Self {
            model: std::env::var("EVAL_MODEL").unwrap_or(fallback.model),
            endpoint: std::env::var("EVAL_ENDPOINT").unwrap_or(fallback.endpoint),
            api_key,
            max_turns: std::env::var("EVAL_MAX_TURNS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(40),
            timeout_secs: std::env::var("EVAL_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(480),
            corpus_dir,
            trace_dir,
        })
    }
}

/// What happened on one task.
#[derive(Clone, Debug)]
pub struct TaskOutcome {
    pub hexid: String,
    pub name: String,
    pub pass: bool,
    pub final_answer: String,
    pub turns: usize,
    pub est_in_tokens: u64,
    pub est_out_tokens: u64,
    pub cost_usd: f64,
    pub error: Option<String>,
    pub trace_path: PathBuf,
    /// Kept workdir (temp task dir) for post-mortems.
    pub workdir: PathBuf,
}

fn task_prompt(binary: &Path) -> String {
    format!(
        "Recover a valid serial/key for the binary at {}.\n\
         Use r2 for static analysis (`r2 -q -c '...' <path>`) and Python for \
         decoding/brute-force. When you have a serial that works, finish with \
         a final message containing the exact serial on its own line prefixed \
         with `FLAG:` (e.g. `FLAG: hunter2`).",
        binary.display()
    )
}

/// Run one task: isolated workdir + memory DB, debug trace on, bounded.
pub async fn run_task(task: &Task, binary: &Path, opts: &EvalOpts) -> Result<TaskOutcome, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let workdir = std::env::temp_dir().join(format!(
        "recurse-eval-{}-{}-{}",
        task.hexid,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&workdir).map_err(|e| format!("workdir: {e}"))?;

    let target: PromptTarget = prompt_target_for(task, &binary.to_string_lossy());
    let config = LlmConfig::new(
        opts.endpoint.clone(),
        Some(opts.api_key.clone()),
        opts.model.clone(),
    );
    let mem_project = format!("eval-{}", task.hexid);
    // Fresh memory DB per task; `open` creates tables idempotently.
    let store = MemoryStore::open(workdir.join("memory.db"))?;

    let mut tools = librecurse::tools::schema();
    tools.extend(librecurse::memory::memory_tool_schema());

    let mut agent = Agent::new();
    agent.set_debug(true);
    let mut exec = |tc: &ToolCall| {
        let tc = tc.clone();
        let mem_project = mem_project.clone();
        let store = store.clone();
        async move {
            match tc.function.name.as_str() {
                "memory_save" | "memory_load" | "memory_search" => {
                    let args: serde_json::Value = serde_json::from_str(&tc.function.arguments)
                        .unwrap_or(serde_json::Value::Null);
                    store.execute_tool(&mem_project, &tc.function.name, &args)
                }
                _ => librecurse::tools::execute(&tc).await,
            }
        }
    };
    let mut emit = |_: AgentEvent| {};

    let run_id = format!("eval-{}", task.hexid);
    let task_msg = task_prompt(binary);
    let timeout = Duration::from_secs(opts.timeout_secs);
    let run = agent.run_limited(
        &run_id,
        &config,
        &target,
        &task_msg,
        &tools,
        opts.max_turns,
        &mut exec,
        &mut emit,
    );
    let run_result = tokio::time::timeout(timeout, run).await;
    let error = match &run_result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.clone()),
        Err(_) => Some(format!("wall-clock timeout after {}s", opts.timeout_secs)),
    };

    let final_answer = agent
        .messages()
        .iter()
        .rev()
        .find(|m| m.role == "assistant" && m.tool_calls.is_none())
        .and_then(|m| m.content.clone())
        .unwrap_or_default();
    let pass = error.is_none() && grade_flag(&final_answer, &task.flag);
    let turns = agent.trace().len();
    let est_in_tokens: u64 = agent.trace().iter().map(|t| t.est_input_tokens).sum();
    let est_out_tokens: u64 = agent.trace().iter().map(|t| t.est_output_tokens).sum();

    std::fs::create_dir_all(&opts.trace_dir).map_err(|e| format!("trace dir: {e}"))?;
    let trace_path = opts.trace_dir.join(format!("{}.json", task.hexid));
    // Trace write is best-effort: grading must not fail because of it.
    let _ = agent.save_trace(&trace_path).await;

    // Sanity: the flag must be discoverable in principle — if even the
    // task's own description can't grade, the manifest is wrong, not the agent.
    debug_assert!(
        contains_token(&format!("FLAG: {}", task.flag), &task.flag),
        "manifest flag does not self-grade"
    );

    Ok(TaskOutcome {
        hexid: task.hexid.clone(),
        name: task.name.clone(),
        pass,
        final_answer,
        turns,
        est_in_tokens,
        est_out_tokens,
        cost_usd: cost_usd(est_in_tokens, est_out_tokens),
        error,
        trace_path,
        workdir,
    })
}
