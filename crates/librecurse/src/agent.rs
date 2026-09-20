use std::io::BufRead;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const OPENROUTER_MODELS: &str = "https://openrouter.ai/api/v1/chat/completions";
const OPENROUTER_MODELS_LIST: &str = "https://openrouter.ai/api/v1/models";
const DEFAULT_MODEL: &str = "openrouter/auto";

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
    /// Explicit construction from resolved values.
    pub fn new(endpoint: String, api_key: Option<String>, model: String) -> Self {
        Self {
            endpoint,
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

/// A model entry returned by OpenRouter's `/models` endpoint.
#[derive(Clone, Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
    pub context_length: u64,
    pub prompt_price: String,
    pub free: bool,
}

#[derive(Deserialize)]
struct OrResponse {
    data: Vec<OrModel>,
}

#[derive(Deserialize)]
struct OrModel {
    id: String,
    name: String,
    #[serde(default)]
    context_length: Option<u64>,
    #[serde(default)]
    pricing: Option<OrPricing>,
    #[serde(default)]
    architecture: Option<OrArchitecture>,
}

#[derive(Deserialize, Default)]
struct OrArchitecture {
    #[serde(default)]
    input_modalities: Vec<String>,
    #[serde(default)]
    output_modalities: Vec<String>,
}

#[derive(Deserialize, Default)]
struct OrPricing {
    #[serde(default)]
    prompt: String,
}

/// Text-only models: accept text on input (may also accept other modalities)
/// but produce text-only output. This drops image/video/audio output models
/// (VLMs, TTS, etc.).
fn is_text_model(m: &OrModel) -> bool {
    match m.architecture.as_ref() {
        Some(a) => {
            let input_has_text = a.input_modalities.iter().any(|x| x == "text");
            let output_text_only =
                a.output_modalities.len() == 1 && a.output_modalities[0] == "text";
            input_has_text && output_text_only
        }
        None => true,
    }
}

/// Fetch the full OpenRouter model catalog (public, unauthenticated).
pub fn fetch_models() -> Result<Vec<ModelInfo>, String> {
    let resp: OrResponse = ureq::get(OPENROUTER_MODELS_LIST)
        .call()
        .map_err(|e| format!("models request failed: {e}"))?
        .into_json()
        .map_err(|e| format!("models parse failed: {e}"))?;

    let models = resp
        .data
        .into_iter()
        .filter(is_text_model)
        .map(|m| {
            let prompt_price = m
                .pricing
                .as_ref()
                .map(|p| p.prompt.clone())
                .unwrap_or_default();
            ModelInfo {
                id: m.id,
                name: m.name,
                context_length: m.context_length.unwrap_or(0),
                free: prompt_price == "0",
                prompt_price,
            }
        })
        .collect();
    Ok(models)
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
         Rules: You MUST be action-first and concise (<4 lines text). The first tool call MUST be bash.\n\
         Workflow (do not deviate): 1) bash immediately with `file`, `ls`, and targeted r2 (`r2 -AA -q -c 'izz; iz; afl~main; p8 32 @ 0x140005160; ps @ 0x140005000; px 32 @ 0x1400051a0'`). 2) bash Python with capstone/unicorn/numba (`uv run --with capstone --with unicorn --with numba` or `uv venv`) to decode probe physics and brute-force. 3) write/edit keygen to /tmp/keygen.py (read first, then write/edit). 4) bash verify the keygen.\n\
         Tools: bash for r2/python/uv; read/write/edit for files. If bash output is truncated, rerun a narrower r2 command.\n\
         Anti-loop: doom_loop fires after 3 identical tool:args. Batch independent calls in parallel. Verify via bash before finishing.",
        if kind.contains("pe") || kind.contains("mach0") || arch.contains("x86") && kind.contains("pe") { "PE/Mach-O on Linux — static bash+r2 analysis" } else { kind }
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
}

/// Parse one SSE `data:` payload, extracting content/reasoning and
/// accumulating tool-call fragments into `acc`.
fn parse_delta(data: &str, acc: &mut ToolCallAccumulator) -> DeltaChunk {
    let mut chunk = DeltaChunk {
        content: String::new(),
        reasoning: Vec::new(),
    };
    let value: Value = match serde_json::from_str(data) {
        Ok(v) => v,
        Err(_) => return chunk,
    };
    let Some(choices) = value["choices"].as_array() else {
        return chunk;
    };
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
fn stream_http(
    run_id: &str,
    config: &LlmConfig,
    messages: &[ChatMessage],
    tools: &[Value],
    emit: &mut dyn FnMut(AgentEvent),
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
    // Transient network errors get exactly one retry; HTTP-status errors do
    // not (a 401 will not fix itself), and we never retry mid-stream.
    #[allow(clippy::result_large_err)] // ureq's error type; retried once
    let resp = {
        let send = || {
            ureq::post(&config.endpoint)
                .set("Authorization", &format!("Bearer {key}"))
                .set("X-Title", "Recurse")
                .send_json(&body)
        };
        match send() {
            Ok(r) => r,
            Err(ureq::Error::Transport(_)) => {
                std::thread::sleep(std::time::Duration::from_millis(500));
                send().map_err(map_http_error)?
            }
            Err(e) => return Err(map_http_error(e)),
        }
    };

    let reader = resp.into_reader();
    let mut buf = std::io::BufReader::new(reader);
    let mut line = String::new();
    let mut acc = ToolCallAccumulator::default();
    let mut content = String::new();
    let mut reasoning = String::new();

    loop {
        line.clear();
        match buf.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let l = line.trim();
        let Some(data) = l.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data == "[DONE]" {
            break;
        }
        if data.is_empty() {
            continue;
        }
        let chunk = parse_delta(data, &mut acc);
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
    }

    Ok(StreamOutcome {
        content,
        reasoning,
        tool_calls: acc.calls,
    })
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
pub fn complete_http(
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
    let resp = ureq::post(endpoint)
        .set("Authorization", &format!("Bearer {api_key}"))
        .set("X-Title", "Recurse")
        .send_json(&body)
        .map_err(map_http_error)?;
    let value: Value = resp.into_json().map_err(|e| e.to_string())?;
    value["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "llm returned no content".into())
}

/// Generate a short, descriptive session title from the user's request (like
/// ChatGPT). Falls back to a truncated version of the message when the LLM is
/// unavailable.
pub fn generate_title(config: &LlmConfig, user: &str) -> String {
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
    match complete_http(&config.endpoint, key, &config.model, &messages) {
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

fn map_http_error(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(300).collect();
            format!("llm request failed with status {code}: {snippet}")
        }
        other => format!("llm request failed: {other}"),
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

    /// Run one user turn to completion: stream the reply, execute any tool
    /// calls the model requests, feed results back, and loop until the model
    /// produces a final answer. There is no hard iteration cap; a runaway run
    /// is stopped via the cooperative cancel flag (`request_cancel`).
    ///
    /// `exec` runs a tool call (name + JSON arguments) against the live tool
    /// backends and returns its result text.
    #[allow(clippy::too_many_arguments)] // one cohesive run context
    pub fn run(
        &mut self,
        run_id: &str,
        config: &LlmConfig,
        target: &PromptTarget,
        user: &str,
        tools: &[Value],
        exec: &mut dyn FnMut(&ToolCall) -> Result<String, String>,
        emit: &mut dyn FnMut(AgentEvent),
    ) -> Result<(), String> {
        let system = system_prompt(target);
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
        loop {
            if self.cancel.load(std::sync::atomic::Ordering::SeqCst) {
                self.cancel
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                return Err("run cancelled".into());
            }
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

            let outcome = stream_http(run_id, config, &full, tools, emit)?;

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
                    let result = exec(tc).unwrap_or_else(|e| format!("tool error: {e}"));
                    emit(AgentEvent::ToolResult {
                        run_id: run_id.to_string(),
                        id: tc.id.clone(),
                        name: tc.function.name.clone(),
                        result: result.clone(),
                    });
                    self.messages.push(ChatMessage::tool(tc.id.clone(), result));
                }
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
                continuation_nudge = Some(ChatMessage::user(
                    "Continue the task. Do not finish with an empty answer. Use the next highest-value action now; for reverse engineering, run bash with targeted r2/Python and write or verify the solver.",
                ));
                continue;
            }

            // Final answer.
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
    use std::io::{BufRead, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Tiny in-process SSE server that serves one queued body per connection.
    struct MockSse {
        addr: String,
        _bodies: Arc<Mutex<Vec<String>>>,
    }

    impl MockSse {
        fn new(bodies: Vec<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            let bodies = Arc::new(Mutex::new(bodies));
            let shared = bodies.clone();
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(mut sock) = conn else { break };
                    let mut line = String::new();
                    let mut reader = std::io::BufReader::new(sock.try_clone().unwrap());
                    let mut content_length = 0usize;
                    loop {
                        line.clear();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            break;
                        }
                        let l = line.trim_end();
                        if l.is_empty() {
                            break;
                        }
                        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }
                    // Drain the request body: closing a socket with unread data
                    // sends RST (not FIN), which can wipe the response before the
                    // client reads it.
                    if content_length > 0 {
                        let mut body = vec![0u8; content_length];
                        let _ = reader.read_exact(&mut body);
                    }
                    let body = {
                        let mut q = shared.lock().unwrap();
                        if q.is_empty() {
                            break;
                        }
                        q.remove(0)
                    };
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    sock.write_all(header.as_bytes()).unwrap();
                    sock.write_all(body.as_bytes()).unwrap();
                    sock.flush().unwrap();
                }
            });
            MockSse {
                addr,
                _bodies: bodies,
            }
        }
    }

    fn content_body(text: &str) -> String {
        let obj = serde_json::json!({
            "id": "x",
            "choices": [{ "delta": { "content": text } }]
        });
        format!("data: {obj}\n\ndata: [DONE]\n\n")
    }

    fn tool_body(name: &str, args: &str) -> String {
        let obj = serde_json::json!({
            "id": "x",
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": name, "arguments": args }
                    }]
                }
            }]
        });
        format!("data: {obj}\n\ndata: [DONE]\n\n")
    }

    fn reasoned_body(text: &str, reasoning: &str) -> String {
        let obj = serde_json::json!({
            "id": "x",
            "choices": [{
                "delta": { "reasoning": reasoning, "content": text }
            }]
        });
        format!("data: {obj}\n\ndata: [DONE]\n\n")
    }

    fn test_target() -> PromptTarget {
        PromptTarget {
            path: "/tmp/b".into(),
            arch: "x86".into(),
            bits: 64,
            kind: "elf".into(),
            memory: String::new(),
        }
    }

    fn run_with(
        bodies: Vec<String>,
    ) -> (
        Result<(), String>,
        Vec<AgentEvent>,
        Vec<String>,
        Vec<ChatMessage>,
    ) {
        let mock = MockSse::new(bodies);
        let config = LlmConfig {
            endpoint: mock.addr,
            api_key: Some("k".into()),
            model: "m".into(),
        };
        let mut agent = Agent::new();
        let target = test_target();
        let mut events: Vec<AgentEvent> = Vec::new();
        let mut exec = |_tc: &ToolCall| -> Result<String, String> { Ok("rip=0x1234".into()) };
        let mut emit = |ev: AgentEvent| events.push(ev);
        let res = agent.run(
            "run-1",
            &config,
            &target,
            "hello",
            &[],
            &mut exec,
            &mut emit,
        );
        let content: String = events
            .iter()
            .filter_map(|e| match e {
                AgentEvent::Token { delta, .. } => Some(delta.clone()),
                _ => None,
            })
            .collect();
        (res, events, vec![content], agent.messages().to_vec())
    }

    #[test]
    fn system_prompt_covers_target_and_memory() {
        let target = PromptTarget {
            memory: "prefers unicorn".into(),
            ..test_target()
        };
        let prompt = system_prompt(&target);
        assert!(prompt.contains("/tmp/b"), "prompt names the target");
        assert!(prompt.contains("x86"), "prompt carries the arch");
        assert!(
            prompt.contains("Previously saved memory"),
            "memory section header present"
        );
        assert!(prompt.contains("prefers unicorn"), "memory is appended");
        let bare = system_prompt(&test_target());
        assert!(
            !bare.contains("Previously saved memory"),
            "empty memory adds no section"
        );
    }

    #[test]
    fn streams_content_and_emits_done() {
        let (res, events, content, _) = run_with(vec![content_body("Hello, world!")]);
        assert!(res.is_ok(), "run failed: {res:?}");
        assert_eq!(content[0], "Hello, world!");
        assert!(events.iter().any(|e| matches!(e, AgentEvent::Done { .. })));
    }

    #[test]
    fn empty_model_response_is_retried_before_completion() {
        let (res, events, content, messages) =
            run_with(vec![content_body(""), content_body("continued")]);
        assert!(res.is_ok(), "run failed: {res:?}");
        assert_eq!(content[0], "continued");
        assert!(events
            .iter()
            .any(|e| matches!(e, AgentEvent::Done { content, .. } if content == "continued")));
        assert!(!messages.iter().any(|m| m.role == "user" && m.content.as_deref() == Some("Continue the task. Do not finish with an empty answer. Use the next highest-value action now; for reverse engineering, run bash with targeted r2/Python and write or verify the solver.")));
    }

    #[test]
    fn executes_tool_loop_then_final_answer() {
        let (res, events, content, _) = run_with(vec![
            tool_body("bash", "{}"),
            content_body("registers dumped."),
        ]);
        assert!(res.is_ok(), "run failed: {res:?}");
        assert!(events
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolCall { name, .. } if name == "bash")));
        assert!(events
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolResult { result, .. } if result == "rip=0x1234")));
        assert!(events.iter().any(|e| matches!(e, AgentEvent::Done { .. })));
        assert_eq!(content[0], "registers dumped.");
    }

    #[test]
    fn reasoning_is_streamed_and_persisted() {
        let (res, events, _, messages) = run_with(vec![reasoned_body(
            "Answer.",
            "Let me think about this carefully.",
        )]);
        assert!(res.is_ok(), "run failed: {res:?}");
        assert!(events.iter().any(
            |e| matches!(e, AgentEvent::Reasoning { delta, .. } if delta == "Let me think about this carefully.")
        ));
        assert!(events.iter().any(|e| matches!(e, AgentEvent::Done { .. })));
        // The assistant message persists the reasoning trace.
        let assistant = messages
            .iter()
            .find(|m| m.role == "assistant")
            .expect("assistant message present");
        assert_eq!(
            assistant.reasoning.as_deref(),
            Some("Let me think about this carefully.")
        );
    }

    #[test]
    fn cancel_between_tool_calls_stops_run() {
        let mock = MockSse::new(vec![
            tool_body("bash", "{}"),
            tool_body("bash", "{}"),
            content_body("never reached"),
        ]);
        let config = LlmConfig {
            endpoint: mock.addr,
            api_key: Some("k".into()),
            model: "m".into(),
        };
        let mut agent = Agent::new();
        // Cancel after the first tool result comes back (shared flag so the
        // closure does not borrow the agent).
        let cancel_flag = agent.cancel.clone();
        let mut exec = |_tc: &ToolCall| -> Result<String, String> {
            cancel_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok("ok".into())
        };
        let mut events = Vec::new();
        let mut emit = |ev: AgentEvent| events.push(ev);
        let res = agent.run(
            "run-c",
            &config,
            &test_target(),
            "go",
            &[],
            &mut exec,
            &mut emit,
        );
        assert_eq!(res.unwrap_err(), "run cancelled");
        // Transcript stays protocol-valid: every requested tool id got a reply.
        let tool_replies = agent.messages().iter().filter(|m| m.role == "tool").count();
        assert_eq!(tool_replies, 1);
        assert!(
            !events.iter().any(|e| matches!(e, AgentEvent::Done { .. })),
            "no Done after cancellation"
        );
        assert!(agent.messages().last().unwrap().role == "tool");
    }

    #[test]
    fn compact_for_model_truncates_huge_tool_results() {
        let big = "x".repeat(50_000);
        let m = ChatMessage::tool("t1".into(), big);
        let c = compact_for_model(&m);
        let len = c.content.as_ref().unwrap().chars().count();
        assert!(
            len <= MODEL_MSG_BUDGET + 200,
            "compacted length {len} within budget+marker"
        );
        assert!(c.content.as_ref().unwrap().contains("[truncated"));
        // Small messages pass through untouched.
        let small = ChatMessage::tool("t2".into(), "short".into());
        assert_eq!(compact_for_model(&small).content, Some("short".into()));
    }

    #[test]
    fn echo_path_when_no_key() {
        let config = LlmConfig {
            endpoint: "http://127.0.0.1:1".into(),
            api_key: None,
            model: "m".into(),
        };
        let mut agent = Agent::new();
        let target = test_target();
        let mut events: Vec<AgentEvent> = Vec::new();
        let mut exec = |_tc: &ToolCall| -> Result<String, String> { Ok(String::new()) };
        let mut emit = |ev: AgentEvent| events.push(ev);
        let res = agent.run(
            "run-e",
            &config,
            &target,
            "hello",
            &[],
            &mut exec,
            &mut emit,
        );
        assert!(res.is_ok(), "echo run failed: {res:?}");
        assert!(events.iter().any(|e| matches!(e, AgentEvent::Token { .. })));
        assert!(events.iter().any(|e| matches!(e, AgentEvent::Done { .. })));
    }
}
