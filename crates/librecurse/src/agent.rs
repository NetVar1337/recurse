use std::future::Future;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const OPENROUTER_MODELS: &str = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_MODEL: &str = "openrouter/auto";

/// Shared HTTP client (connection pooling across turns).
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// One tool call emitted by the model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: ToolCallFn,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolCallFn {
    pub name: String,
    pub arguments: String,
}

/// One turn in the agent conversation. Compatible with the OpenAI chat
/// format: `tool_calls` marks an assistant request to run tools; `tool_call_id`
/// marks a `role: "tool"` result message.
///
/// `reasoning` holds the model's thinking trace for the turn. It is persisted
/// with the conversation history but is never sent back to the model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reasoning: Option<String>,
}

impl ChatMessage {
    fn user(content: &str) -> Self {
        Self {
            role: "user".into(),
            content: Some(content.to_string()),
            tool_calls: None,
            tool_call_id: None,
            reasoning: None,
        }
    }

    fn system(content: &str) -> Self {
        Self {
            role: "system".into(),
            content: Some(content.to_string()),
            tool_calls: None,
            tool_call_id: None,
            reasoning: None,
        }
    }

    fn assistant(content: Option<String>, tool_calls: Option<Vec<ToolCall>>) -> Self {
        Self {
            role: "assistant".into(),
            content,
            tool_calls,
            tool_call_id: None,
            reasoning: None,
        }
    }

    fn tool(tool_call_id: String, content: String) -> Self {
        Self {
            role: "tool".into(),
            content: Some(content),
            tool_calls: None,
            tool_call_id: Some(tool_call_id),
            reasoning: None,
        }
    }

    fn with_reasoning(mut self, reasoning: Option<String>) -> Self {
        if reasoning.as_ref().map(|s| !s.is_empty()).unwrap_or(false) {
            self.reasoning = reasoning;
        }
        self
    }

    /// Clone without the reasoning trace, for the wire format sent to the model.
    fn without_reasoning(&self) -> Self {
        let mut c = self.clone();
        c.reasoning = None;
        c
    }
}

/// Runtime LLM configuration. A plain interface type: hosts construct it
/// (from their own config file, environment, or UI) and hand it to the
/// run loop — the library never reads configuration storage itself.
#[derive(Clone)]
pub struct LlmConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub model: String,
}

impl LlmConfig {
    /// Explicit construction from resolved values. `endpoint` may be a base
    /// URL (`https://host/v1`) or a full completions URL — see
    /// [`normalize_endpoint`].
    pub fn new(endpoint: String, api_key: Option<String>, model: String) -> Self {
        Self {
            endpoint: normalize_endpoint(&endpoint),
            api_key,
            model,
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        // Environment + built-in defaults only. File-backed precedence
        // (e.g. `~/.recurse/config.json`) is the host's job: it loads its
        // file and calls [`LlmConfig::new`], falling back to these fields.
        let api_key = std::env::var("OPENROUTER_API_KEY")
            .ok()
            .or_else(|| std::env::var("RECURSE_LLM_API_KEY").ok());
        let endpoint = std::env::var("RECURSE_LLM_ENDPOINT")
            .ok()
            .unwrap_or_else(|| OPENROUTER_MODELS.to_string());
        let model = std::env::var("RECURSE_LLM_MODEL")
            .ok()
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());
        Self {
            endpoint,
            api_key,
            model,
        }
    }
}

/// OpenAI-compatible endpoint normalization. Accepts a bare base URL
/// (`https://openrouter.ai/api/v1`, the usual "base URL" you copy from a
/// provider) or a full route; `/chat/completions` is appended only when the
/// path doesn't already name a completions route. Empty falls back to the
/// built-in default so a blank config value can't produce a relative URL.
pub fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return OPENROUTER_MODELS.to_string();
    }
    if trimmed.ends_with("/chat/completions") || trimmed.ends_with("/completions") {
        return trimmed.to_string();
    }
    format!("{trimmed}/chat/completions")
}

/// Total attempts for one request before giving up (initial try included).
const MAX_SEND_ATTEMPTS: u32 = 4;
/// Ceiling on a single wait, so a hostile/incorrect hint can't hang a run.
const MAX_RETRY_WAIT: std::time::Duration = std::time::Duration::from_secs(70);

fn is_rate_limited(resp: &reqwest::Response) -> bool {
    resp.status().as_u16() == 429
}

/// True when a failed send is worth retrying. These all mean no response was
/// received, so nothing was streamed and re-sending cannot duplicate a turn
/// (`is_request` covers connection-level failures such as a reused-but-closed
/// pooled connection, which `is_connect` misses).
fn is_transient_send(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_timeout() || e.is_request()
}

/// Exponential backoff: 500ms, 1s, 2s, ...
fn backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(500 * 2u64.saturating_pow(attempt.saturating_sub(1)))
}

/// How long to wait before retrying. Prefers what the server tells us —
/// `Retry-After` (seconds, or an HTTP date we don't parse) and OpenRouter's
/// `X-RateLimit-Reset` (unix milliseconds) — falling back to exponential
/// backoff. Always capped by [`MAX_RETRY_WAIT`].
fn retry_delay(resp: &reqwest::Response, attempt: u32) -> std::time::Duration {
    let headers = resp.headers();
    if let Some(secs) = headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        return std::time::Duration::from_secs(secs).min(MAX_RETRY_WAIT);
    }
    if let Some(reset_ms) = headers
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // +250ms so we land just after the window rather than on the boundary.
        let wait_ms = reset_ms.saturating_sub(now_ms).saturating_add(250);
        return std::time::Duration::from_millis(wait_ms).min(MAX_RETRY_WAIT);
    }
    backoff(attempt).min(MAX_RETRY_WAIT)
}

/// A model entry returned by OpenRouter's `/models` endpoint.
#[derive(Clone, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub context_length: u64,
    pub prompt_price: String,
    pub free: bool,
}

/// Events streamed from the agent worker to the frontend over a single
/// `agent-event` channel, discriminated by `kind`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentEvent {
    Reasoning {
        run_id: String,
        delta: String,
    },
    Token {
        run_id: String,
        delta: String,
    },
    ToolCall {
        run_id: String,
        id: String,
        name: String,
        arguments: String,
    },
    ToolResult {
        run_id: String,
        id: String,
        name: String,
        result: String,
    },
    Done {
        run_id: String,
        content: String,
    },
    Error {
        run_id: String,
        message: String,
    },
}

/// Accumulates streamed tool-call fragments (OpenAI streams `tool_calls` as
/// several deltas across an `index`).
#[derive(Default)]
struct ToolCallAccumulator {
    calls: Vec<ToolCall>,
}

impl ToolCallAccumulator {
    fn ensure(&mut self, index: usize) -> &mut ToolCall {
        while self.calls.len() <= index {
            self.calls.push(ToolCall {
                id: String::new(),
                call_type: "function".into(),
                function: ToolCallFn {
                    name: String::new(),
                    arguments: String::new(),
                },
            });
        }
        &mut self.calls[index]
    }

    fn set_id(&mut self, index: usize, id: &str) {
        self.ensure(index).id = id.to_string();
    }

    fn set_name(&mut self, index: usize, name: &str) {
        self.ensure(index).function.name = name.to_string();
    }

    fn append_args(&mut self, index: usize, args: &str) {
        self.ensure(index).function.arguments.push_str(args);
    }
}

/// Result of a single streamed completion.
struct StreamOutcome {
    content: String,
    reasoning: String,
    tool_calls: Vec<ToolCall>,
    /// Model that actually served the request, as reported by the endpoint.
    /// Meaningful with routers (`openrouter/auto`, `openrouter/free`) where
    /// the configured id does not identify the model that answered.
    model: Option<String>,
}

fn echo_reply(user: &str) -> String {
    format!(
        "[echo] Set the OPENROUTER_API_KEY environment variable to enable the \
         real model, then pick a model from the selector above.\n\nYou asked:\n{user}"
    )
}

/// Target description the system prompt is built from. Plain interface
/// type: hosts fill it in from whatever binary metadata they hold, so the
/// library never depends on the host's JSON shapes.
#[derive(Clone, Debug)]
pub struct PromptTarget {
    /// Binary path, shown to the model verbatim.
    pub path: String,
    /// Architecture label (e.g. `"x86"`, `"?"` when unknown).
    pub arch: String,
    /// Address width in bits (0 when unknown).
    pub bits: u64,
    /// Binary type label (e.g. `"elf"`, `"pe"`).
    pub kind: String,
    /// Previously saved agent memory, appended verbatim when non-empty.
    pub memory: String,
}

/// Build the system prompt for a run. Public library interface: hosts can
/// preview or log the exact prompt a turn will use.
pub fn system_prompt(target: &PromptTarget) -> String {
    let PromptTarget {
        path,
        arch,
        bits,
        kind,
        memory,
    } = target;
    let mut prompt = format!(
        "You are Recurse, an expert reverse-engineering agent. Crack the target: recover the serial/key.\n\
         Target: {path} arch={arch} bits={bits} type={kind} ({})\n\
         Tooling: use the `r2` tool for ALL binary inspection — never run r2 through bash. Use `bash` only to run scripts and the target itself (python, ./target). read/write/edit handle files.\n\
         Workflow: 1) r2 `aaa` once to analyse. 2) r2 `afl` for the function list, `pdf @ <fn>` to read a function, `axt @ <addr>` for xrefs, `izz` for strings, `iij` for imports. 3) Decide what the check is, then confirm it by running the target (bash) with a candidate key on stdin. 4) If a transform is involved (xor/hash/compare), write a short python keygen with bash and verify it.\n\
         Efficiency (measured and expected of you): never repeat an identical r2 call; chain related commands in ONE call (`aaa; afl; izz`); do not re-dump data you already have; keep queries narrow (`pd 40 @ main`, not a whole huge function). Keep prose under 4 lines.",
        if kind.contains("pe") || kind.contains("mach0") { "PE/Mach-O — static analysis on Linux" } else { "" }
    );
    if !memory.is_empty() {
        prompt.push_str("\n\nPreviously saved memory (from earlier sessions):\n");
        prompt.push_str(memory);
    }
    prompt
}

/// Extracted content from one SSE `data:` payload.
struct DeltaChunk {
    content: String,
    reasoning: Vec<String>,
    model: Option<String>,
}

/// Parse one SSE `data:` payload, extracting content/reasoning and
/// accumulating tool-call fragments into `acc`.
fn parse_delta(data: &str, acc: &mut ToolCallAccumulator) -> DeltaChunk {
    let mut chunk = DeltaChunk {
        content: String::new(),
        reasoning: Vec::new(),
        model: None,
    };
    let value: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(_) => return chunk,
    };
    let Some(choices) = value["choices"].as_array() else {
        return chunk;
    };
    if let Some(m) = value["model"].as_str() {
        if !m.is_empty() {
            chunk.model = Some(m.to_string());
        }
    }
    let Some(choice) = choices.first() else {
        return chunk;
    };
    let delta = &choice["delta"];

    if let Some(s) = delta["content"].as_str() {
        chunk.content = s.to_string();
    }
    // OpenRouter uses `reasoning`; DeepSeek-style endpoints use `reasoning_content`.
    for key in ["reasoning", "reasoning_content"] {
        if let Some(s) = delta[key].as_str() {
            if !s.is_empty() {
                chunk.reasoning.push(s.to_string());
            }
        }
    }
    if let Some(arr) = delta["tool_calls"].as_array() {
        for tc in arr {
            let index = tc["index"].as_u64().unwrap_or(0) as usize;
            if let Some(id) = tc["id"].as_str() {
                acc.set_id(index, id);
            }
            if let Some(name) = tc["function"]["name"].as_str() {
                acc.set_name(index, name);
            }
            if let Some(args) = tc["function"]["arguments"].as_str() {
                acc.append_args(index, args);
            }
        }
    }
    chunk
}

/// Stream a chat completion, emitting tokens and returning the accumulated
/// content + any requested tool calls.
async fn stream_http(
    run_id: &str,
    config: &LlmConfig,
    messages: &[ChatMessage],
    tools: &[Value],
    emit: &mut (dyn FnMut(AgentEvent) + Send),
) -> Result<StreamOutcome, String> {
    let model = if config.model.is_empty() {
        DEFAULT_MODEL
    } else {
        &config.model
    };
    let mut body = serde_json::json!({
        "model": model,
        "messages": messages,
        "stream": true,
    });
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools.to_vec());
    }

    let key = config.api_key.as_deref().unwrap_or("");
    let send = || {
        http_client()
            .post(&config.endpoint)
            .bearer_auth(key)
            .header("X-Title", "Recurse")
            .json(&body)
            .send()
    };
    // Transient failures are worth waiting out and are retried before any
    // bytes are streamed: connect/timeout errors with a short backoff, and
    // rate limiting / 5xx with the wait the server asks for. A 4xx other than
    // 429 will not fix itself, so it fails immediately. Once streaming has
    // started we never retry — the transcript would get a duplicate turn.
    let mut resp = {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let last = attempt >= MAX_SEND_ATTEMPTS;
            match send().await {
                Ok(r) if r.status().is_success() => break r,
                Ok(r) if (is_rate_limited(&r) || r.status().is_server_error()) && !last => {
                    let wait = retry_delay(&r, attempt);
                    tokio::time::sleep(wait).await;
                }
                Ok(r) => {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    let snippet: String = body.chars().take(300).collect();
                    return Err(format!(
                        "llm request failed with status {code}: {snippet}",
                        code = status.as_u16()
                    ));
                }
                Err(e) if is_transient_send(&e) && !last => {
                    tokio::time::sleep(backoff(attempt)).await;
                }
                Err(e) => return Err(format!("llm request failed: {e}")),
            }
        }
    };
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        return Err(format!(
            "llm request failed with status {code}: {snippet}",
            code = status.as_u16()
        ));
    }

    // Chunk framing mirrors the old blocking line reader exactly: complete
    // `\n`-terminated lines are processed in order, a trailing partial line
    // is processed at EOF, and undecodable bytes end the stream.
    let mut pending: Vec<u8> = Vec::new();
    let mut acc = ToolCallAccumulator::default();
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut served_model: Option<String> = None;

    loop {
        match resp.chunk().await {
            Ok(Some(bytes)) => pending.extend_from_slice(&bytes),
            // EOF, or a mid-stream read error (the old reader treated both
            // as end-of-stream).
            Ok(None) | Err(_) => break,
        }
        let mut done = false;
        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = pending.drain(..=pos).collect();
            if handle_stream_line(
                &raw,
                run_id,
                &mut acc,
                &mut content,
                &mut reasoning,
                &mut served_model,
                emit,
            ) {
                done = true;
                break;
            }
        }
        if done {
            break;
        }
    }
    if !pending.is_empty() {
        handle_stream_line(
            &pending,
            run_id,
            &mut acc,
            &mut content,
            &mut reasoning,
            &mut served_model,
            emit,
        );
    }

    Ok(StreamOutcome {
        content,
        reasoning,
        tool_calls: acc.calls,
        model: served_model,
    })
}

/// Process one raw stream line. Returns true when the stream is complete
/// (`[DONE]` or undecodable bytes, mirroring the old blocking reader).
fn handle_stream_line(
    raw: &[u8],
    run_id: &str,
    acc: &mut ToolCallAccumulator,
    content: &mut String,
    reasoning: &mut String,
    served_model: &mut Option<String>,
    emit: &mut (dyn FnMut(AgentEvent) + Send),
) -> bool {
    let Ok(line) = std::str::from_utf8(raw) else {
        return true;
    };
    let l = line.trim();
    let Some(data) = l.strip_prefix("data:") else {
        return false;
    };
    let data = data.trim();
    if data == "[DONE]" {
        return true;
    }
    if data.is_empty() {
        return false;
    }
    let chunk = parse_delta(data, acc);
    if let Some(m) = chunk.model {
        if served_model.is_none() {
            *served_model = Some(m);
        }
    }
    for r in chunk.reasoning {
        reasoning.push_str(&r);
        emit(AgentEvent::Reasoning {
            run_id: run_id.to_string(),
            delta: r,
        });
    }
    if !chunk.content.is_empty() {
        emit(AgentEvent::Token {
            run_id: run_id.to_string(),
            delta: chunk.content.clone(),
        });
        content.push_str(&chunk.content);
    }
    false
}

/// Per-message wire budget for model context. Old tool results are the
/// usual bloat; truncating them keeps long debugging sessions within token
/// budgets without touching the recent turns that carry current state.
const MODEL_MSG_BUDGET: usize = 6_000;

fn compact_for_model(m: &ChatMessage) -> ChatMessage {
    let Some(content) = m.content.as_ref() else {
        return m.clone();
    };
    let char_len = content.chars().count();
    if char_len <= MODEL_MSG_BUDGET {
        return m.clone();
    }
    let head: String = content.chars().take(MODEL_MSG_BUDGET / 2).collect();
    let tail: String = {
        let skip = char_len - MODEL_MSG_BUDGET / 4;
        content.chars().skip(skip).collect()
    };
    let mut c = m.clone();
    c.content = Some(format!(
        "{head}\n...[truncated {mid} chars]...\n{tail}",
        mid = char_len - MODEL_MSG_BUDGET / 2 - MODEL_MSG_BUDGET / 4
    ));
    c
}

/// One-shot, non-streaming chat completion (used to generate session titles).
pub async fn complete_http(
    endpoint: &str,
    api_key: &str,
    model: &str,
    messages: &[ChatMessage],
) -> Result<String, String> {
    let model = if model.is_empty() {
        DEFAULT_MODEL
    } else {
        model
    };
    let body = serde_json::json!({
        "model": model,
        "messages": messages,
    });
    let resp = http_client()
        .post(endpoint)
        .bearer_auth(api_key)
        .header("X-Title", "Recurse")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("llm request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let snippet: String = body.chars().take(300).collect();
        return Err(format!(
            "llm request failed with status {code}: {snippet}",
            code = status.as_u16()
        ));
    }
    let value: Value = resp.json().await.map_err(|e| e.to_string())?;
    value["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "llm returned no content".into())
}

/// Generate a short, descriptive session title from the user's request (like
/// ChatGPT). Falls back to a truncated version of the message when the LLM is
/// unavailable.
pub async fn generate_title(config: &LlmConfig, user: &str) -> String {
    let fallback = |u: &str| -> String {
        let joined: String = u.split_whitespace().collect::<Vec<_>>().join(" ");
        let t: String = joined.chars().take(48).collect();
        if t.is_empty() {
            "New session".to_string()
        } else {
            t
        }
    };
    let Some(key) = config.api_key.as_ref().filter(|k| !k.is_empty()) else {
        return fallback(user);
    };
    let messages = vec![
        ChatMessage::system(
            "You are a title generator for a binary reverse-engineering assistant. \
             Given the user's request, write a short descriptive session title of at \
             most 8 words. Reply with ONLY the title and no quotes or punctuation.",
        ),
        ChatMessage::user(user),
    ];
    match complete_http(&config.endpoint, key, &config.model, &messages).await {
        Ok(t) => {
            let t = t.trim().trim_matches('"').trim();
            if t.is_empty() {
                fallback(user)
            } else {
                t.chars().take(64).collect()
            }
        }
        Err(_) => fallback(user),
    }
}

/// One tool result as seen in the trace: id + name + full result text.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceToolResult {
    pub id: String,
    pub name: String,
    pub result: String,
}

/// Exact record of a single model turn: the input the model saw
/// (post-compaction, reasoning stripped — byte-identical to the wire
/// payload minus the tool schemas), plus everything it returned.
/// Recorded only when the debug flag is on; zero cost otherwise.
///
/// The request is stored as indices into [`Trace::messages`] rather than as a
/// copy of the messages. Turns are cumulative, so copying would write the same
/// message once per turn it was present in: measured at ~8x duplication and
/// 1.5MB for a 23-turn task, growing with the square of the turn count.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TurnTrace {
    pub run_id: String,
    /// 1-based iteration index within the run.
    pub turn: usize,
    /// Model that served this turn, as reported by the endpoint. Differs from
    /// the configured id when a router is used (`openrouter/auto`,
    /// `openrouter/free`), where it names the model that actually answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Indices into [`Trace::messages`] giving the exact `messages` array sent
    /// for this turn, in order. Resolve with `trace.request_messages(turn)`.
    pub request: Vec<usize>,
    /// Number of tool schemas sent alongside the request.
    pub tools_sent: usize,
    /// Model text output for the turn (may be empty on tool-only turns).
    pub content: String,
    /// Model thinking trace (never sent back to the model).
    pub reasoning: String,
    pub tool_calls: Vec<ToolCall>,
    pub tool_results: Vec<TraceToolResult>,
    /// Rough token counts (chars / 4 over request/response text).
    pub est_input_tokens: u64,
    pub est_output_tokens: u64,
}

/// Everything captured for a run: the system prompt, a deduplicated pool of
/// every message that was ever sent, and one entry per model turn.
///
/// Messages are pooled because turns are cumulative — storing each turn's full
/// request verbatim repeats a message once per subsequent turn. The pool keeps
/// the trace exact (a turn resolves to the identical messages) while staying
/// proportional to the number of distinct messages rather than turns squared.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Trace {
    /// Built once per run and prepended to every turn's request, so it is
    /// stored here instead of repeated in each turn.
    pub system_prompt: String,
    /// Every distinct message ever sent, in first-seen order.
    pub messages: Vec<ChatMessage>,
    pub turns: Vec<TurnTrace>,
}

impl Trace {
    /// The exact messages sent for `turn` (1-based), system prompt first.
    pub fn request_messages(&self, turn: usize) -> Vec<ChatMessage> {
        let mut out = vec![ChatMessage::system(&self.system_prompt)];
        if let Some(t) = self.turns.iter().find(|t| t.turn == turn) {
            out.extend(
                t.request
                    .iter()
                    .filter_map(|i| self.messages.get(*i))
                    .cloned(),
            );
        }
        out
    }
}

/// The agent: holds conversation history. LLM config and tool execution are
/// supplied per run so the caller controls session/project access.
pub struct Agent {
    messages: Vec<ChatMessage>,
    /// Cooperative cancel flag for the in-flight run. The Tauri command
    /// layer flips it from the UI; `run` checks between iterations and tool
    /// calls so a stop lands within one step, never mid-LLM-stream.
    pub cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    debug: bool,
    trace: Trace,
    /// Message -> pool index, for deduplication while recording.
    trace_index: std::collections::HashMap<String, usize>,
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            debug: false,
            trace: Trace::default(),
            trace_index: std::collections::HashMap::new(),
        }
    }

    /// Request cancellation of the current run (no-op when idle).
    pub fn request_cancel(&self) {
        self.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Replace history (used to restore a persisted conversation).
    pub fn load(&mut self, messages: Vec<ChatMessage>) {
        self.messages = messages;
    }

    pub fn messages(&self) -> &[ChatMessage] {
        &self.messages
    }

    pub fn reset(&mut self) {
        self.messages.clear();
    }

    /// Enable per-turn tracing. When on, every model turn records its exact
    /// input messages, reasoning, tool calls and results (see [`TurnTrace`]).
    /// Off by default; no cloning overhead when off. The trace survives
    /// [`Agent::reset`] — use [`Agent::clear_trace`] to drop it.
    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    pub fn clear_trace(&mut self) {
        self.trace = Trace::default();
        self.trace_index.clear();
    }

    /// Whole run as pretty JSON: the message pool, per-turn traces, and the
    /// final conversation. Useful for eval reports and post-mortems.
    pub fn trace_json(&self) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "system_prompt": self.trace.system_prompt,
            "messages": self.trace.messages,
            "turns": self.trace.turns,
            "conversation": self.messages,
        }))
        .unwrap_or_else(|_| "{}".to_string())
    }

    /// Write [`Agent::trace_json`] to a file (async fs, like the rest of
    /// the library's storage-agnostic IO — the caller picks the path).
    pub async fn save_trace(&self, path: &std::path::Path) -> Result<(), String> {
        let json = self.trace_json();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
        tokio::fs::write(path, json)
            .await
            .map_err(|e| e.to_string())
    }

    #[allow(clippy::too_many_arguments)] // one cohesive trace record
    fn record_turn(
        &mut self,
        run_id: &str,
        turn: usize,
        model: Option<&str>,
        request: Option<Vec<ChatMessage>>,
        tools_len: usize,
        content: &str,
        reasoning: &str,
        tool_calls: &[ToolCall],
        tool_results: Vec<TraceToolResult>,
    ) {
        let Some(request) = request else {
            return;
        };
        let est_input_tokens: u64 = request
            .iter()
            .filter_map(|m| m.content.as_ref())
            .map(|c| c.chars().count() as u64 / 4)
            .sum();
        let est_output_tokens = (content.chars().count() + reasoning.chars().count()) as u64 / 4;
        // `full` is the system prompt followed by the history; intern the rest
        // into the pool so each distinct message is stored exactly once.
        let mut indices = Vec::with_capacity(request.len());
        for msg in request.into_iter().skip(1) {
            let key = serde_json::to_string(&msg).unwrap_or_default();
            let idx = match self.trace_index.get(&key) {
                Some(i) => *i,
                None => {
                    let i = self.trace.messages.len();
                    self.trace.messages.push(msg);
                    self.trace_index.insert(key, i);
                    i
                }
            };
            indices.push(idx);
        }
        self.trace.turns.push(TurnTrace {
            run_id: run_id.to_string(),
            turn,
            model: model.map(|m| m.to_string()),
            request: indices,
            tools_sent: tools_len,
            content: content.to_string(),
            reasoning: reasoning.to_string(),
            tool_calls: tool_calls.to_vec(),
            tool_results,
            est_input_tokens,
            est_output_tokens,
        });
    }

    /// Run one user turn to completion: stream the reply, execute any tool
    /// calls the model requests, feed results back, and loop until the model
    /// produces a final answer. There is no hard iteration cap; a runaway run
    /// is stopped via the cooperative cancel flag (`request_cancel`).
    ///
    /// `exec` runs a tool call (name + JSON arguments) against the live tool
    /// backends and returns its result text. It is generic over the returned
    /// future so hosts can pass `async` closures without boxing; the future
    /// must be `Send` because turns run on the async runtime.
    #[allow(clippy::too_many_arguments)] // one cohesive run context
    pub async fn run<E, F>(
        &mut self,
        run_id: &str,
        config: &LlmConfig,
        target: &PromptTarget,
        user: &str,
        tools: &[Value],
        exec: &mut E,
        emit: &mut (dyn FnMut(AgentEvent) + Send),
    ) -> Result<(), String>
    where
        E: FnMut(&ToolCall) -> F + Send,
        F: Future<Output = Result<String, String>> + Send,
    {
        self.run_limited(run_id, config, target, user, tools, usize::MAX, exec, emit)
            .await
    }

    /// Same as [`Agent::run`], but stops with an error after `max_turns`
    /// model calls. Eval harnesses use this to bound cost on stuck runs;
    /// interactive hosts pass `usize::MAX` (via [`Agent::run`]).
    #[allow(clippy::too_many_arguments)] // one cohesive run context
    pub async fn run_limited<E, F>(
        &mut self,
        run_id: &str,
        config: &LlmConfig,
        target: &PromptTarget,
        user: &str,
        tools: &[Value],
        max_turns: usize,
        exec: &mut E,
        emit: &mut (dyn FnMut(AgentEvent) + Send),
    ) -> Result<(), String>
    where
        E: FnMut(&ToolCall) -> F + Send,
        F: Future<Output = Result<String, String>> + Send,
    {
        let system = system_prompt(target);
        if self.debug {
            self.trace.system_prompt = system.clone();
        }
        self.messages.push(ChatMessage::user(user));

        let configured = config
            .api_key
            .as_ref()
            .map(|k| !k.is_empty())
            .unwrap_or(false);

        if !configured {
            let reply = echo_reply(user);
            emit(AgentEvent::Token {
                run_id: run_id.to_string(),
                delta: reply.clone(),
            });
            emit(AgentEvent::Done {
                run_id: run_id.to_string(),
                content: reply.clone(),
            });
            self.messages
                .push(ChatMessage::assistant(Some(reply), None));
            return Ok(());
        }

        let mut empty_final_retries = 0u8;
        let mut continuation_nudge: Option<ChatMessage> = None;
        let mut turn: usize = 0;
        loop {
            if self.cancel.load(std::sync::atomic::Ordering::SeqCst) {
                self.cancel
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                return Err("run cancelled".into());
            }
            if turn >= max_turns {
                return Err(format!("turn budget exhausted after {turn} turns"));
            }
            turn += 1;
            let mut full = vec![ChatMessage::system(&system)];
            full.extend(
                self.messages
                    .iter()
                    .map(compact_for_model)
                    .map(|m| m.without_reasoning()),
            );
            if let Some(nudge) = continuation_nudge.take() {
                full.push(nudge);
            }

            let request_snapshot = self.debug.then(|| full.clone());
            let tools_len = tools.len();
            let outcome = stream_http(run_id, config, &full, tools, emit).await?;

            if !outcome.tool_calls.is_empty() {
                // Persist the assistant's tool request, then run each tool.
                let content = if outcome.content.is_empty() {
                    None
                } else {
                    Some(outcome.content.clone())
                };
                self.messages.push(
                    ChatMessage::assistant(content, Some(outcome.tool_calls.clone()))
                        .with_reasoning(Some(outcome.reasoning.clone())),
                );

                let mut tool_records: Vec<TraceToolResult> = Vec::new();
                for tc in &outcome.tool_calls {
                    if self.cancel.load(std::sync::atomic::Ordering::SeqCst) {
                        self.cancel
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                        // Keep the transcript valid: the assistant message
                        // above already requested tools, so every id needs a
                        // tool reply before the next request.
                        let mut cancelled = false;
                        for tc in &outcome.tool_calls {
                            let content = if cancelled {
                                "cancelled".into()
                            } else {
                                "cancelled before execution".into()
                            };
                            cancelled = true;
                            self.messages
                                .push(ChatMessage::tool(tc.id.clone(), content));
                        }
                        return Err("run cancelled".into());
                    }
                    emit(AgentEvent::ToolCall {
                        run_id: run_id.to_string(),
                        id: tc.id.clone(),
                        name: tc.function.name.clone(),
                        arguments: tc.function.arguments.clone(),
                    });
                    let result = exec(tc)
                        .await
                        .unwrap_or_else(|e| format!("tool error: {e}"));
                    // An empty tool result is legal in the OpenAI wire format but
                    // not portable: Cohere (reached through OpenRouter) rejects
                    // `tool_results` entries without an `outputs` property, which
                    // is what an empty string translates to. A successful command
                    // that prints nothing is common (`grep` with no match, `cd`,
                    // `2>/dev/null`), so substitute a placeholder rather than
                    // poisoning the rest of the conversation with a 400.
                    let result = if result.trim().is_empty() {
                        "(no output)".to_string()
                    } else {
                        result
                    };
                    emit(AgentEvent::ToolResult {
                        run_id: run_id.to_string(),
                        id: tc.id.clone(),
                        name: tc.function.name.clone(),
                        result: result.clone(),
                    });
                    tool_records.push(TraceToolResult {
                        id: tc.id.clone(),
                        name: tc.function.name.clone(),
                        result: result.clone(),
                    });
                    self.messages.push(ChatMessage::tool(tc.id.clone(), result));
                }
                self.record_turn(
                    run_id,
                    turn,
                    outcome.model.as_deref(),
                    request_snapshot,
                    tools_len,
                    &outcome.content,
                    &outcome.reasoning,
                    &outcome.tool_calls,
                    tool_records,
                );
                continue;
            }

            // Some models emit an empty text response after a tool result. It
            // is not a valid completion for an action-oriented agent: keep the
            // turn alive and transiently ask for the next action instead of
            // persisting an empty answer and stopping.
            if outcome.content.trim().is_empty() {
                empty_final_retries += 1;
                if empty_final_retries > 2 {
                    return Err("model returned an empty answer three times; the agent did not complete the task".into());
                }
                self.record_turn(
                    run_id,
                    turn,
                    outcome.model.as_deref(),
                    request_snapshot,
                    tools_len,
                    &outcome.content,
                    &outcome.reasoning,
                    &outcome.tool_calls,
                    Vec::new(),
                );
                continuation_nudge = Some(ChatMessage::user(
                    "Continue the task. Do not finish with an empty answer. Use the next highest-value action now; for reverse engineering, run bash with targeted r2/Python and write or verify the solver.",
                ));
                continue;
            }

            // Final answer.
            self.record_turn(
                run_id,
                turn,
                outcome.model.as_deref(),
                request_snapshot,
                tools_len,
                &outcome.content,
                &outcome.reasoning,
                &outcome.tool_calls,
                Vec::new(),
            );
            emit(AgentEvent::Done {
                run_id: run_id.to_string(),
                content: outcome.content.clone(),
            });
            self.messages.push(
                ChatMessage::assistant(Some(outcome.content.clone()), None)
                    .with_reasoning(Some(outcome.reasoning.clone())),
            );
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn normalize_endpoint_accepts_base_url_or_full_route() {
        // The common case: a provider's base URL, as copied from its docs.
        assert_eq!(
            normalize_endpoint("https://openrouter.ai/api/v1"),
            "https://openrouter.ai/api/v1/chat/completions"
        );
        assert_eq!(
            normalize_endpoint("https://api.openai.com/v1/"),
            "https://api.openai.com/v1/chat/completions"
        );
        // Already a completions route: untouched, no doubled suffix.
        assert_eq!(
            normalize_endpoint("https://openrouter.ai/api/v1/chat/completions"),
            "https://openrouter.ai/api/v1/chat/completions"
        );
        // Surrounding whitespace (a `.env` value with trailing spaces) is noise.
        assert_eq!(
            normalize_endpoint("  https://host/v1  "),
            "https://host/v1/chat/completions"
        );
        // Empty must never yield a relative URL.
        assert_eq!(normalize_endpoint(""), OPENROUTER_MODELS);
        assert_eq!(normalize_endpoint("   "), OPENROUTER_MODELS);
    }

    #[test]
    fn llm_config_normalizes_endpoint() {
        let cfg = LlmConfig::new(
            "https://openrouter.ai/api/v1".into(),
            Some("k".into()),
            "m".into(),
        );
        assert_eq!(
            cfg.endpoint,
            "https://openrouter.ai/api/v1/chat/completions"
        );
    }
}
