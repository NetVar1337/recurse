//! The agent `debug` tool: one tool, an `op` vocabulary, compact JSON results.
//!
//! The host appends [`tool_schema`] to the agent's tools and routes matching
//! calls to [`execute_tool`] — exactly how the memory tools are wired, so
//! `librecurse` never depends on this crate.

use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::model::{BreakAt, LaunchOptions, StepKind};
use crate::session::Debugger;

/// The tool name the agent calls.
pub const TOOL_NAME: &str = "debug";

/// Ops the debugger serves.
pub const OPS: &[&str] = &[
    "launch",
    "attach",
    "continue",
    "step",
    "break",
    "unbreak",
    "breakpoints",
    "regs",
    "read",
    "write",
    "backtrace",
    "threads",
    "status",
    "detach",
    "kill",
];

/// Largest memory read served to the agent, in bytes.
const MAX_READ: usize = 4096;

/// True when `name` is a debugger op.
///
/// ```
/// assert!(recurse_debug::tool::is_op("break"));
/// assert!(!recurse_debug::tool::is_op("disasm"));
/// ```
pub fn is_op(name: &str) -> bool {
    OPS.contains(&name)
}

/// The JSON schema for the `debug` tool.
///
/// ```
/// let schema = recurse_debug::tool::tool_schema();
/// assert_eq!(schema["function"]["name"], "debug");
/// ```
pub fn tool_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": TOOL_NAME,
            "description": format!(
                "Run and inspect the target under a debugger to confirm behaviour \
                 (set a breakpoint, run to it, read registers/memory, step, backtrace). \
                 Ops: {}. Addresses accept a number, `0x` hex, or a symbol name. \
                 Results are compact JSON.",
                OPS.join(", ")
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "op": { "type": "string", "enum": OPS },
                    "path": { "type": "string", "description": "For `launch`: executable path." },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "For `launch`: command-line arguments."
                    },
                    "pid": { "type": "integer", "description": "For `attach`: process id." },
                    "addr": {
                        "type": ["string", "integer"],
                        "description": "Target address or symbol name (for `break`, `read`, `write`)."
                    },
                    "symbol": { "type": "string", "description": "For `break`: symbol name." },
                    "kind": {
                        "type": "string",
                        "enum": ["into", "over", "out"],
                        "description": "For `step`: step kind (default `into`)."
                    },
                    "id": { "type": "integer", "description": "For `unbreak`: breakpoint id." },
                    "thread": { "type": "integer", "description": "Optional thread id." },
                    "len": { "type": "integer", "description": "For `read`: byte count." },
                    "bytes": { "type": "string", "description": "For `write`: hex bytes." },
                    "format": {
                        "type": "string",
                        "enum": ["hex", "ascii", "u64"],
                        "description": "For `read`: how to render the bytes (default `hex`)."
                    }
                },
                "required": ["op"]
            }
        }
    })
}

/// Execute one `debug` op against `dbg`, returning compact JSON.
///
/// # Errors
/// [`Error::Message`] for a malformed argument or an unknown op, or the
/// underlying session error.
pub fn execute_tool(dbg: &Debugger, op: &str, args: &Value) -> Result<String> {
    let value = match op {
        "launch" => {
            let path = args
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::msg("launch: `path` is required"))?
                .to_string();
            let opts = LaunchOptions {
                path,
                args: string_list(args.get("args")),
                cwd: args.get("cwd").and_then(Value::as_str).map(str::to_string),
                env: Default::default(),
            };
            to_json(&dbg.launch(&opts)?)?
        }
        "attach" => {
            let pid = args
                .get("pid")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::msg("attach: `pid` is required"))?;
            to_json(&dbg.attach(pid as u32)?)?
        }
        "continue" => to_json(&dbg.resume()?)?,
        "step" => {
            let kind = match args.get("kind").and_then(Value::as_str) {
                Some("over") => StepKind::Over,
                Some("out") => StepKind::Out,
                _ => StepKind::Into,
            };
            to_json(&dbg.step(kind)?)?
        }
        "break" => {
            let at = if let Some(sym) = args.get("symbol").and_then(Value::as_str) {
                BreakAt::Symbol {
                    name: sym.to_string(),
                }
            } else {
                let addr = args
                    .get("addr")
                    .and_then(parse_addr)
                    .ok_or_else(|| Error::msg("break: `addr` or `symbol` is required"))?;
                BreakAt::Addr { addr }
            };
            to_json(&dbg.add_breakpoint(&at)?)?
        }
        "unbreak" => {
            let id = args
                .get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::msg("unbreak: `id` is required"))?;
            dbg.remove_breakpoint(id)?;
            json!({})
        }
        "breakpoints" => to_json(&dbg.breakpoints()?)?,
        "regs" => to_json(&dbg.registers(args.get("thread").and_then(Value::as_u64))?)?,
        "read" => {
            let addr = args
                .get("addr")
                .and_then(parse_addr)
                .ok_or_else(|| Error::msg("read: `addr` is required"))?;
            let len = args
                .get("len")
                .and_then(Value::as_u64)
                .unwrap_or(64)
                .min(MAX_READ as u64) as usize;
            let bytes = dbg.read_memory(addr, len)?;
            render_bytes(addr, &bytes, args.get("format").and_then(Value::as_str))
        }
        "write" => {
            let addr = args
                .get("addr")
                .and_then(parse_addr)
                .ok_or_else(|| Error::msg("write: `addr` is required"))?;
            let hex = args
                .get("bytes")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::msg("write: `bytes` is required"))?;
            let bytes = parse_hex(hex)?;
            dbg.write_memory(addr, &bytes)?;
            json!({ "written": bytes.len() })
        }
        "backtrace" => to_json(&dbg.backtrace(args.get("thread").and_then(Value::as_u64))?)?,
        "threads" => to_json(&dbg.threads()?)?,
        "status" => to_json(&dbg.status()?)?,
        "detach" => {
            dbg.detach()?;
            json!({})
        }
        "kill" => {
            dbg.kill()?;
            json!({})
        }
        other => return Err(Error::msg(format!("unknown debug op `{other}`"))),
    };
    serde_json::to_string(&value).map_err(|e| Error::msg(e.to_string()))
}

/// Serialise any model value to a [`serde_json::Value`].
fn to_json<T: serde::Serialize>(value: &T) -> Result<Value> {
    serde_json::to_value(value).map_err(|e| Error::msg(e.to_string()))
}

/// Coerce a JSON value to an address (number, or `0x`/decimal string).
fn parse_addr(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                s.parse::<u64>().ok()
            }
        }
        _ => None,
    }
}

/// Extract a list of strings from a JSON array.
fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Parse an optionally space-separated hex string into bytes.
fn parse_hex(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(Error::msg("hex string must have an even number of digits"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| Error::msg(e.to_string()))?;
        out.push(u8::from_str_radix(pair, 16).map_err(|e| Error::msg(e.to_string()))?);
        i += 2;
    }
    Ok(out)
}

/// Render memory bytes in the requested format.
fn render_bytes(addr: u64, bytes: &[u8], format: Option<&str>) -> Value {
    match format {
        Some("ascii") => {
            let text: String = bytes
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            json!({ "addr": addr, "len": bytes.len(), "ascii": text })
        }
        Some("u64") => {
            let words: Vec<u64> = bytes
                .chunks(8)
                .map(|c| {
                    let mut buf = [0u8; 8];
                    buf[..c.len()].copy_from_slice(c);
                    u64::from_ne_bytes(buf)
                })
                .collect();
            json!({ "addr": addr, "words": words })
        }
        _ => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            json!({ "addr": addr, "len": bytes.len(), "hex": hex })
        }
    }
}
