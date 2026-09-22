//! A standalone [MCP](https://modelcontextprotocol.io) server exposing
//! Recurse's backend-neutral `analyze` tool over stdio JSON-RPC 2.0 — the
//! direct answer to "IDA Pro MCP": no IDA seat, no Python bridge, no GUI.
//! `recurse-agent`'s bundled chat panel is one client of
//! `recurse_static::engine::Engine`; this crate is another, generic one, so
//! any MCP-capable agent (Claude Code, Cursor, Claude Desktop, …) can drive
//! the exact same native (or r2) engine directly.
//!
//! This module is pure protocol logic — parsing/dispatching already-decoded
//! JSON-RPC [`Value`]s against a [`dyn Engine`](Engine) — so it is testable
//! without a real stdio loop or a real binary. [`crate`]'s `main.rs` (the
//! `recurse-mcp` binary) is the thin part: parse argv, open an engine, read
//! newline-delimited JSON-RPC from stdin, call [`handle_request`], write the
//! response (if any) to stdout.
//!
//! Scope: one binary per process, matching how `idalib`/most MCP RE servers
//! work (a client that wants to compare two binaries runs two servers, or
//! reopens). `tools/list` always reports exactly one tool — `analyze`,
//! Recurse's own single backend-neutral tool (see
//! `crates/recurse-static/src/engine.rs`) — never a tool-per-op menagerie.

use recurse_static::engine::{self, Engine};
use serde_json::{json, Value};

/// The MCP protocol version this server speaks.
pub const PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "recurse-mcp";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Convert Recurse's OpenAI-style tool schema
/// (`{"type":"function","function":{name,description,parameters}}`, shared
/// with `recurse-agent`'s own tool runtime) into an MCP tool definition
/// (`{"name","description","inputSchema"}`).
pub fn mcp_tool_def(openai_schema: &Value) -> Value {
    let f = &openai_schema["function"];
    json!({
        "name": f["name"],
        "description": f["description"],
        "inputSchema": f["parameters"],
    })
}

/// Handle one already-parsed JSON-RPC request against `engine`, returning
/// the response to write (as compact JSON) — or `None` for a notification
/// (no `id`: JSON-RPC never expects a reply to those, success or error).
pub fn handle_request(engine: &dyn Engine, request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let empty = Value::Null;
    let params = request.get("params").unwrap_or(&empty);

    if method.starts_with("notifications/") {
        // Client-to-server notifications (`initialized`, `cancelled`, …)
        // never get a response, regardless of whether `id` happens to be
        // present.
        return None;
    }

    let result = dispatch(engine, method, params);
    let id = id?;
    Some(match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err((code, message)) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    })
}

/// JSON-RPC error code for "the method does not exist / is not available".
const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC error code for "invalid method parameter(s)".
const INVALID_PARAMS: i64 = -32602;

fn dispatch(engine: &dyn Engine, method: &str, params: &Value) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
        })),
        "ping" => Ok(json!({})),
        "tools/list" => {
            let schema = engine::tool_schema(engine.capabilities());
            Ok(json!({ "tools": [mcp_tool_def(&schema)] }))
        }
        "tools/call" => handle_tool_call(engine, params),
        other => Err((METHOD_NOT_FOUND, format!("method not found: {other}"))),
    }
}

fn handle_tool_call(engine: &dyn Engine, params: &Value) -> Result<Value, (i64, String)> {
    let name = params.get("name").and_then(Value::as_str).ok_or((
        INVALID_PARAMS,
        "tools/call requires a string \"name\"".to_string(),
    ))?;
    let empty_args = json!({});
    let arguments = params.get("arguments").unwrap_or(&empty_args);

    let normalized = engine::op_args(name, arguments)
        .ok_or_else(|| (METHOD_NOT_FOUND, format!("unknown tool: {name}")))?;

    // A tool-call failure (bad address, unsupported op on this backend, …)
    // is reported to the model as tool content with `isError`, per the MCP
    // spec — not as a JSON-RPC protocol error, which is reserved for
    // malformed requests the *client* got wrong.
    match engine::execute_tool(engine, &normalized) {
        Ok(text) => Ok(json!({ "content": [{ "type": "text", "text": text }] })),
        Err(message) => Ok(json!({
            "content": [{ "type": "text", "text": message }],
            "isError": true,
        })),
    }
}

/// A JSON-RPC parse-error response for input that was not valid JSON at
/// all — the one case [`handle_request`] can never be reached for, since it
/// needs an already-parsed [`Value`].
pub fn parse_error_response(message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": { "code": -32700, "message": format!("parse error: {message}") },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use recurse_static::engine::{
        BackendKind, Capabilities, Decompilation, Disassembly, FunctionGraph, FunctionInfo, Import,
        StringRef, Target, Xref, XrefDirection,
    };
    use std::path::{Path, PathBuf};

    /// A minimal in-memory `Engine`, enough to exercise the protocol layer
    /// without opening a real binary.
    struct StubEngine {
        capabilities: Capabilities,
        path: PathBuf,
    }

    impl Engine for StubEngine {
        fn backend(&self) -> BackendKind {
            BackendKind::Native
        }
        fn capabilities(&self) -> Capabilities {
            self.capabilities
        }
        fn path(&self) -> &Path {
            &self.path
        }
        fn analyze(&self) -> Result<(), String> {
            Ok(())
        }
        fn summary(&self) -> Result<Value, String> {
            Ok(json!({}))
        }
        fn info(&self) -> Result<Value, String> {
            Ok(json!({}))
        }
        fn functions(&self) -> Result<Vec<FunctionInfo>, String> {
            Ok(vec![FunctionInfo {
                addr: 0x1000,
                name: "main".into(),
                size: Some(16),
                nbbs: None,
                edges: None,
                signature: None,
            }])
        }
        fn function_at(&self, _addr: u64) -> Result<Option<FunctionInfo>, String> {
            Ok(None)
        }
        fn disassemble(&self, _t: &Target, _c: Option<usize>) -> Result<Disassembly, String> {
            Ok(Disassembly {
                addr: 0x1000,
                name: "main".into(),
                size: None,
                ops: vec![],
            })
        }
        fn function_disasm(&self, _addr: u64) -> Result<Disassembly, String> {
            Ok(Disassembly {
                addr: 0x1000,
                name: "main".into(),
                size: None,
                ops: vec![],
            })
        }
        fn function_graph(&self, _addr: u64) -> Result<FunctionGraph, String> {
            Ok(FunctionGraph {
                addr: 0x1000,
                name: "main".into(),
                blocks: vec![],
            })
        }
        fn strings(&self) -> Result<Vec<StringRef>, String> {
            Ok(vec![])
        }
        fn imports(&self) -> Result<Vec<Import>, String> {
            Ok(vec![])
        }
        fn xrefs(&self, _t: &Target, _d: XrefDirection) -> Result<Vec<Xref>, String> {
            Ok(vec![])
        }
        fn decompile(&self, _addr: u64) -> Result<Decompilation, String> {
            Err("no decompiler".to_string())
        }
        fn raw(&self, _cmd: &str) -> Result<Value, String> {
            Err("no console".to_string())
        }
        fn resolve(&self, _name: &str) -> Result<Option<u64>, String> {
            Ok(None)
        }
    }

    fn engine(capabilities: Capabilities) -> StubEngine {
        StubEngine {
            capabilities,
            path: PathBuf::from("/bin/true"),
        }
    }

    fn request(id: i64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    #[test]
    fn initialize_reports_protocol_version_and_server_info() {
        let e = engine(Capabilities::none());
        let response = handle_request(&e, &request(1, "initialize", json!({}))).expect("response");
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(response["result"]["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(response["id"], 1);
    }

    #[test]
    fn notifications_never_get_a_response() {
        let e = engine(Capabilities::none());
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_request(&e, &notification).is_none());

        // Even a notification naming an unknown method stays silent — a
        // JSON-RPC notification has no id to reply to, error or not.
        let unknown_notification = json!({ "jsonrpc": "2.0", "method": "notifications/whatever" });
        assert!(handle_request(&e, &unknown_notification).is_none());
    }

    #[test]
    fn tools_list_exposes_exactly_one_backend_neutral_tool() {
        let e = engine(Capabilities::all());
        let response = handle_request(&e, &request(2, "tools/list", json!({}))).expect("response");
        let tools = response["result"]["tools"].as_array().expect("tools array");
        assert_eq!(
            tools.len(),
            1,
            "one tool, not a tool-per-op menagerie: {tools:?}"
        );
        assert_eq!(tools[0]["name"], "analyze");
        assert!(tools[0]["inputSchema"]["properties"]["op"].is_object());
    }

    #[test]
    fn tools_list_hides_ops_the_backend_cannot_serve() {
        let e = engine(Capabilities {
            decompile: false,
            raw: false,
            graph: true,
            xrefs_from: true,
        });
        let response = handle_request(&e, &request(3, "tools/list", json!({}))).expect("response");
        let ops = response["result"]["tools"][0]["inputSchema"]["properties"]["op"]["enum"]
            .as_array()
            .expect("op enum");
        assert!(!ops.iter().any(|v| v == "decompile"));
        assert!(!ops.iter().any(|v| v == "raw"));
        assert!(ops.iter().any(|v| v == "functions"));
    }

    #[test]
    fn tools_call_dispatches_to_the_engine_and_wraps_text_content() {
        let e = engine(Capabilities::all());
        let call = request(
            4,
            "tools/call",
            json!({ "name": "analyze", "arguments": { "op": "functions" } }),
        );
        let response = handle_request(&e, &call).expect("response");
        let content = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        let envelope: Value = serde_json::from_str(content).expect("tool output is JSON");
        assert_eq!(envelope["op"], "functions");
        assert_eq!(envelope["count"], 1);
        assert!(response["result"]["isError"].is_null());
    }

    #[test]
    fn tools_call_accepts_the_op_name_directly_like_the_native_tool_runtime_does() {
        let e = engine(Capabilities::all());
        let call = request(
            5,
            "tools/call",
            json!({ "name": "functions", "arguments": {} }),
        );
        let response = handle_request(&e, &call).expect("response");
        let content = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(content.contains("\"op\":\"functions\""));
    }

    #[test]
    fn tools_call_failure_is_reported_as_tool_content_not_a_protocol_error() {
        let e = engine(Capabilities::none());
        let call = request(
            6,
            "tools/call",
            json!({ "name": "analyze", "arguments": { "op": "decompile", "addr": 0 } }),
        );
        let response = handle_request(&e, &call).expect("response");
        assert!(
            response.get("error").is_none(),
            "not a JSON-RPC error: {response}"
        );
        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("decompiler"));
    }

    #[test]
    fn tools_call_with_an_unknown_tool_name_is_a_protocol_error() {
        let e = engine(Capabilities::all());
        let call = request(
            7,
            "tools/call",
            json!({ "name": "not_a_real_tool", "arguments": {} }),
        );
        let response = handle_request(&e, &call).expect("response");
        assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn unknown_top_level_method_is_a_protocol_error_with_the_request_id_echoed() {
        let e = engine(Capabilities::none());
        let response =
            handle_request(&e, &request(42, "not/a/method", json!({}))).expect("response");
        assert_eq!(response["id"], 42);
        assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn ping_round_trips() {
        let e = engine(Capabilities::none());
        let response = handle_request(&e, &request(8, "ping", json!({}))).expect("response");
        assert_eq!(response["result"], json!({}));
    }
}
