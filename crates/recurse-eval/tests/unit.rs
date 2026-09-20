//! Fast eval self-tests: no API key, no network, no r2.
//! Covers config parsing, selection over dataset fields, grading, target
//! mapping, and the debug trace against a scripted mock LLM.

use std::collections::HashMap;
use std::path::PathBuf;

use librecurse::agent::{Agent, LlmConfig, ToolCall};
use recurse_eval::config::EvalConfig;
use recurse_eval::select::{select_tasks, DatasetRecord};
use recurse_eval::{contains_token, grade_flag, prompt_target_for, Task};

fn rec(
    hexid: &str,
    difficulty: f64,
    platform: &str,
    arch: &str,
    flag: Option<&str>,
) -> DatasetRecord {
    DatasetRecord {
        hexid: hexid.into(),
        name: hexid.into(),
        difficulty: Some(difficulty),
        quality: Some(4.0),
        platform: platform.into(),
        arch: arch.into(),
        language: "C/C++".into(),
        nbsolutions: Some(10.0),
        flag: flag.map(|s| s.into()),
        has_unique_flag: Some(true),
        url: String::new(),
        obfuscation_classes: Vec::new(),
    }
}

#[test]
fn config_parses_and_defaults() {
    let yaml = r#"
tier: easy-10
select:
  difficulty_max: 1.5
  platforms: [linux]
  count: 5
  seed: 7
run:
  max_turns: 20
"#;
    let cfg: EvalConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.tier, "easy-10");
    assert_eq!(cfg.select.difficulty_max, Some(1.5));
    assert_eq!(cfg.select.platforms, vec!["linux".to_string()]);
    assert_eq!(cfg.select.count, 5);
    assert_eq!(cfg.select.seed, 7);
    assert!(cfg.select.require_flag, "flag grading on by default");
    assert_eq!(cfg.run.max_turns, 20);
    assert_eq!(cfg.run.timeout_secs, 480, "run default kept");
    assert!(cfg.dataset.jsonl_url.contains("crackmes_dataset.jsonl"));
}

#[test]
fn shipped_easy_config_selects_current_ten() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("evals/easy.yaml");
    let cfg = EvalConfig::load(&path).expect("load easy.yaml");
    assert_eq!(cfg.select.hexids.len(), 10);
    assert_eq!(cfg.binaries.len(), 10);
    // Every binary hint points at a tier hexid (no stale entries).
    let ids: std::collections::HashSet<&str> =
        cfg.select.hexids.iter().map(|s| s.as_str()).collect();
    for key in cfg.binaries.keys() {
        assert!(ids.contains(key.as_str()), "stale binary hint {key}");
    }
}

#[test]
fn selection_filters_all_fields() {
    let records = vec![
        rec("a", 1.0, "Unix/linux etc.", "x86-64", Some("flag-a")),
        rec("b", 1.0, "Windows", "x86", Some("flag-b")),
        rec("c", 3.0, "Unix/linux etc.", "x86", Some("flag-c")),
        rec("d", 1.0, "Unix/linux etc.", "ARM", None),
    ];
    // Difficulty + platform + flag filters compose.
    let select = recurse_eval::config::SelectConfig {
        difficulty_max: Some(1.5),
        platforms: vec!["linux".to_string()],
        count: 1,
        ..Default::default()
    };
    let tasks = select_tasks(&records, &select, &HashMap::new()).expect("select");
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].hexid, "a");
    assert_eq!(tasks[0].flag, "flag-a");
}

#[test]
fn selection_count_overflow_errors() {
    let records = vec![rec("a", 1.0, "Unix", "x86", Some("flag-a"))];
    let select = recurse_eval::config::SelectConfig {
        count: 5,
        ..Default::default()
    };
    let err = select_tasks(&records, &select, &HashMap::new()).expect_err("must fail");
    assert!(err.contains("need 5"), "actionable message: {err}");
}

#[test]
fn selection_is_deterministic_per_seed() {
    let records: Vec<DatasetRecord> = (0..20)
        .map(|i| rec(&format!("id-{i:02}"), 1.0, "Unix", "x86", Some("flag-x")))
        .collect();
    let select = recurse_eval::config::SelectConfig {
        count: 10,
        seed: 7,
        ..Default::default()
    };
    let first = select_tasks(&records, &select, &HashMap::new()).expect("select");
    let second = select_tasks(&records, &select, &HashMap::new()).expect("select");
    assert_eq!(
        first.iter().map(|t| &t.hexid).collect::<Vec<_>>(),
        second.iter().map(|t| &t.hexid).collect::<Vec<_>>(),
        "same seed, same set in same order"
    );
}

#[test]
fn explicit_hexids_win_exactly() {
    let records = vec![
        rec("a", 1.0, "Unix", "x86", Some("flag-a")),
        rec("b", 5.0, "Windows", "ARM", Some("flag-b")),
    ];
    let mut select = recurse_eval::config::SelectConfig {
        hexids: vec!["b".into(), "nope".into()],
        ..Default::default()
    };
    let err = select_tasks(&records, &select, &HashMap::new()).expect_err("missing id");
    assert!(err.contains("nope"), "names the missing id: {err}");
    select.hexids = vec!["b".into(), "a".into()];
    let mut hints = HashMap::new();
    hints.insert("b".to_string(), "b.exe".to_string());
    let tasks = select_tasks(&records, &select, &hints).expect("select");
    assert_eq!(tasks.len(), 2);
    assert_eq!(tasks[0].hexid, "b", "order kept");
    assert_eq!(tasks[0].binary, "b.exe", "hint threaded through");
    assert_eq!(tasks[1].binary, "", "no hint, magic fallback later");
}

#[test]
fn grading_boundaries() {
    assert!(grade_flag("serial 73313 works", "73313"));
    assert!(!grade_flag("x733134", "73313"), "longer numeric run");
    assert!(grade_flag("FLAG: P455w0rd", "P455w0rd"));
    assert!(!grade_flag("p455w0rd", "P455w0rd"), "case-sensitive");
    assert!(grade_flag("got d00r1$m@licious today", "d00r1$m@licious"));
    assert!(!grade_flag("anything", ""), "empty flag never grades");
    assert!(!grade_flag("short", "a"), "single-char flag never grades");
    assert!(contains_token("a PuL-sAr-001!", "PuL-sAr-001"));
    assert!(
        !contains_token("xxPuL-sAr-001", "PuL-sAr-001"),
        "left boundary"
    );
}

#[test]
fn target_mapping() {
    let task = Task {
        hexid: "h".into(),
        name: "n".into(),
        difficulty: 1.0,
        quality: 4.0,
        platform: "Windows".into(),
        arch: "x86".into(),
        language: "Assembler".into(),
        nbsolutions: 1,
        flag: "f".into(),
        binary: "b".into(),
        url: String::new(),
        tags: Vec::new(),
    };
    let t = prompt_target_for(&task, "C:\\x.exe");
    assert_eq!(t.kind, "pe");
    assert_eq!(t.bits, 32);
    let mut arm = task.clone();
    arm.platform = "Unix/linux etc.".into();
    arm.arch = "ARM".into();
    let t = prompt_target_for(&arm, "/tmp/x");
    assert_eq!(t.kind, "elf");
    assert_eq!(t.arch, "arm");
}

#[tokio::test]
async fn echo_path_records_no_model_turns() {
    // No API key: the agent answers from the echo fallback without any
    // model call, so the trace stays empty while history still works.
    let mut agent = Agent::new();
    agent.set_debug(true);
    let config = LlmConfig::new("http://127.0.0.1:9".into(), None, "m".into());
    let target = librecurse::agent::PromptTarget {
        path: "/tmp/x".into(),
        arch: "x86".into(),
        bits: 64,
        kind: "elf".into(),
        memory: String::new(),
    };
    let tools = librecurse::tools::schema();
    let mut exec = |_: &ToolCall| async { Ok("".to_string()) };
    let mut emit = |_: librecurse::agent::AgentEvent| {};
    agent
        .run("t", &config, &target, "hi", &tools, &mut exec, &mut emit)
        .await
        .expect("echo run");
    assert_eq!(agent.messages().len(), 2);
    assert!(agent.trace().is_empty());
}

// ---------------------------------------------------------------------------
// Scripted mock LLM: canned SSE over a real TCP socket. Deterministic
// full-loop test (tool call -> exec -> result -> final answer) plus the
// exact per-turn trace a human would inspect after an eval.
// ---------------------------------------------------------------------------

fn sse_tool_call(id: &str, name: &str, args_json: &str) -> String {
    let payload = serde_json::json!({
        "choices": [{
            "delta": {
                "tool_calls": [{
                    "index": 0,
                    "id": id,
                    "function": {"name": name, "arguments": args_json},
                }],
            },
        }],
    });
    format!("data: {payload}\n\ndata: [DONE]\n\n")
}

fn sse_text(text: &str) -> String {
    let payload = serde_json::json!({
        "choices": [{"delta": {"content": text}}],
    });
    format!("data: {payload}\n\ndata: [DONE]\n\n")
}

/// Serve `bodies` as one SSE response per incoming POST. Returns the endpoint
/// URL; the server task ends after the last body (further accepts ignored).
async fn mock_llm(bodies: Vec<String>) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock llm");
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("addr")
    );
    let handle = tokio::spawn(async move {
        for body in bodies {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Consume the request (headers + body) so the client never blocks.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let header_end = loop {
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
                            break p + 4;
                        }
                    }
                }
            };
            let content_len = String::from_utf8_lossy(&buf[..header_end])
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    (k.trim().eq_ignore_ascii_case("content-length"))
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buf.len() < header_end + content_len {
                match sock.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        }
    });
    (endpoint, handle)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[tokio::test]
async fn mock_loop_records_exact_turns() {
    let (endpoint, _server) = mock_llm(vec![
        sse_tool_call("call_1", "bash", r#"{"command":"echo mock-hi"}"#),
        sse_text("done FLAG: mock-hi"),
    ])
    .await;
    let config = LlmConfig::new(endpoint, Some("test".into()), "mock".into());
    let target = librecurse::agent::PromptTarget {
        path: "/tmp/x".into(),
        arch: "x86".into(),
        bits: 64,
        kind: "elf".into(),
        memory: String::new(),
    };
    let tools = librecurse::tools::schema();
    let mut agent = Agent::new();
    agent.set_debug(true);
    let mut exec = |tc: &ToolCall| {
        let tc = tc.clone();
        async move { librecurse::tools::execute(&tc).await }
    };
    let mut emit = |_: librecurse::agent::AgentEvent| {};
    agent
        .run_limited(
            "mock-run",
            &config,
            &target,
            "recover the key",
            &tools,
            5,
            &mut exec,
            &mut emit,
        )
        .await
        .expect("mock run");

    // Two model turns: tool call, then final answer.
    let trace = agent.trace();
    assert_eq!(trace.len(), 2);
    let first = &trace[0];
    assert_eq!(first.run_id, "mock-run");
    assert_eq!(first.turn, 1);
    assert_eq!(first.request[0].role, "system");
    assert!(
        first.request.iter().any(|m| m
            .content
            .as_deref()
            .unwrap_or("")
            .contains("recover the key")),
        "user task visible in turn-1 input"
    );
    assert!(first.tools_sent >= 4, "tool schemas counted");
    assert_eq!(first.tool_calls.len(), 1);
    assert_eq!(first.tool_calls[0].function.name, "bash");
    assert_eq!(first.tool_results.len(), 1);
    assert!(
        first.tool_results[0].result.contains("mock-hi"),
        "exact tool result captured: {}",
        first.tool_results[0].result
    );
    assert!(first.est_input_tokens > 0);
    let second = &trace[1];
    assert_eq!(second.turn, 2);
    assert_eq!(second.content, "done FLAG: mock-hi");
    assert!(second.tool_calls.is_empty());

    // Trace persists to disk as inspectable JSON.
    let path = std::env::temp_dir().join(format!("recurse-eval-unit-{}.json", std::process::id()));
    agent.save_trace(&path).await.expect("save trace");
    let text = std::fs::read_to_string(&path).expect("read trace");
    let value: serde_json::Value = serde_json::from_str(&text).expect("trace is JSON");
    assert_eq!(value["turns"].as_array().map(|a| a.len()), Some(2));
    assert!(value["conversation"]
        .as_array()
        .is_some_and(|a| !a.is_empty()));
    let _ = std::fs::remove_file(&path);
}
