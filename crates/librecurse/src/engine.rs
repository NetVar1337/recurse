//! Backend-agnostic binary-analysis engine.
//!
//! Recurse originally spoke radare2 directly: the agent tool sent r2 command
//! strings and the UI consumed r2's JSON shapes. That couples the whole
//! product to one LGPL tool for *analysis* even though only some installs want
//! it. This module defines the seam instead:
//!
//! * [`Engine`] — one trait with a method per analysis operation (info,
//!   functions, disassembly, CFG, strings, imports, xrefs, decompilation,
//!   raw console). Every method returns owned, backend-neutral results.
//! * Canonical result types ([`FunctionInfo`], [`Instruction`], [`Xref`], …)
//!   whose JSON field names match what the UI already renders, so swapping the
//!   backend does not ripple into the frontend.
//! * [`BackendKind`] — which implementation to build. `r2` shells out to the
//!   radare2 executable; `native` is a pure-Rust parser/disassembler with no
//!   external process and no copyleft dependency.
//! * [`tool_schema`] / [`execute_tool`] — a single backend-neutral agent tool
//!   (`analyze`) with a small, structured `op` vocabulary instead of raw r2
//!   syntax. `op:"raw"` remains for backend-specific console commands.
//!
//! Hosts own the concrete engine (it needs a target path and, for r2, a child
//! process) and hand a `&dyn Engine` to the tool runtime. Everything here is
//! pure data and pure functions, unit-tested without either backend installed.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Name of the backend-neutral analysis tool the agent calls.
pub const TOOL_NAME: &str = "analyze";

/// Which analysis implementation to instantiate.
///
/// Selected at runtime from `RECURSE_BACKEND` (or the host's config store).
/// The default is [`BackendKind::Native`]: the in-process, permissive,
/// multi-architecture backend. Opt into radare2 with `RECURSE_BACKEND=r2` or
/// the stored config.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// The radare2 executable, driven over its `-q0` pipe.
    R2,
    /// Pure-Rust ELF/PE/Mach-O parsing and disassembly.
    Native,
}

impl Default for BackendKind {
    /// The native backend: in-process, permissive, no external tool.
    ///
    /// ```
    /// use librecurse::engine::BackendKind;
    /// assert_eq!(BackendKind::default(), BackendKind::Native);
    /// std::env::remove_var("RECURSE_BACKEND");
    /// assert_eq!(BackendKind::from_env(), BackendKind::Native);
    /// ```
    fn default() -> Self {
        Self::Native
    }
}

impl BackendKind {
    /// Parse a backend name. Accepts `r2`/`radare2` and `native`.
    ///
    /// ```
    /// use librecurse::engine::BackendKind;
    /// assert_eq!(BackendKind::parse("r2"), Some(BackendKind::R2));
    /// assert_eq!(BackendKind::parse("radare2"), Some(BackendKind::R2));
    /// assert_eq!(BackendKind::parse("Native"), Some(BackendKind::Native));
    /// assert_eq!(BackendKind::parse("ghidra"), None);
    /// ```
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "r2" | "radare2" => Some(Self::R2),
            "native" | "rust" => Some(Self::Native),
            _ => None,
        }
    }

    /// Resolve the backend from the `RECURSE_BACKEND` environment variable,
    /// falling back to [`BackendKind::default`] (native). Unknown values are
    /// ignored rather than fatal: a typo must never make the app unusable.
    ///
    /// ```
    /// use librecurse::engine::BackendKind;
    /// std::env::remove_var("RECURSE_BACKEND");
    /// assert_eq!(BackendKind::from_env(), BackendKind::default());
    /// std::env::set_var("RECURSE_BACKEND", "r2");
    /// assert_eq!(BackendKind::from_env(), BackendKind::R2);
    /// std::env::remove_var("RECURSE_BACKEND");
    /// ```
    pub fn from_env() -> Self {
        std::env::var("RECURSE_BACKEND")
            .ok()
            .and_then(|v| Self::parse(&v))
            .unwrap_or_default()
    }

    /// Stable lowercase label for logs, the UI, and the database.
    ///
    /// ```
    /// use librecurse::engine::BackendKind;
    /// assert_eq!(BackendKind::R2.as_str(), "r2");
    /// assert_eq!(BackendKind::Native.as_str(), "native");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::R2 => "r2",
            Self::Native => "native",
        }
    }
}

/// What a backend can actually do. Backends advertise this so the host can
/// hide UI affordances (the decompiler button) and the tool layer can answer
/// `op:"decompile"` with a precise message instead of a generic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// In-process decompilation (r2 + r2ghidra; the native backend does not).
    pub decompile: bool,
    /// A raw, backend-specific console passthrough.
    pub raw: bool,
    /// Control-flow graph reconstruction.
    pub graph: bool,
    /// References pointing *from* an address (not just to it).
    pub xrefs_from: bool,
}

impl Capabilities {
    /// Conservative default: no optional features at all.
    ///
    /// ```
    /// use librecurse::engine::Capabilities;
    /// let c = Capabilities::none();
    /// assert!(!c.decompile);
    /// assert!(!c.raw);
    /// ```
    pub fn none() -> Self {
        Self {
            decompile: false,
            raw: false,
            graph: false,
            xrefs_from: false,
        }
    }
}

/// An analysis target: a concrete address or a symbol to resolve first. The
/// tool layer accepts both so the model can write `main` or `0x401000`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A numeric virtual address.
    Addr(u64),
    /// A name to resolve through the backend's symbol table.
    Symbol(String),
}

impl Target {
    /// Parse an address argument that may be a JSON number, a `0x`/decimal
    /// string, or a symbol name. `null`/missing yields `None`.
    ///
    /// ```
    /// use librecurse::engine::Target;
    /// use serde_json::json;
    /// assert_eq!(Target::from_json(&json!(4198400)), Some(Target::Addr(0x401000)));
    /// assert_eq!(Target::from_json(&json!("0x401000")), Some(Target::Addr(0x401000)));
    /// assert_eq!(Target::from_json(&json!("main")), Some(Target::Symbol("main".into())));
    /// assert_eq!(Target::from_json(&json!(null)), None);
    /// ```
    pub fn from_json(value: &Value) -> Option<Self> {
        match value {
            Value::Number(n) => n.as_u64().map(Target::Addr),
            Value::String(s) => {
                let t = s.trim();
                if t.is_empty() {
                    None
                } else if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok().map(Target::Addr)
                } else if let Ok(dec) = t.parse::<u64>() {
                    Some(Target::Addr(dec))
                } else {
                    Some(Target::Symbol(t.to_string()))
                }
            }
            _ => None,
        }
    }

    /// The concrete address when this target is already numeric.
    ///
    /// ```
    /// use librecurse::engine::Target;
    /// assert_eq!(Target::Addr(7).to_u64(), Some(7));
    /// assert_eq!(Target::Symbol("main".into()).to_u64(), None);
    /// ```
    pub fn to_u64(&self) -> Option<u64> {
        match self {
            Self::Addr(a) => Some(*a),
            Self::Symbol(_) => None,
        }
    }
}

/// Direction of a cross-reference query.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XrefDirection {
    /// References that point *at* the address (callers, data readers).
    To,
    /// References that point *from* the address (callees, data written).
    From,
}

/// A function as the UI and agent see it. Field names match the r2 JSON the
/// frontend already renders (`addr`, `name`, `size`, `signature`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FunctionInfo {
    pub addr: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbbs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// One disassembled instruction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Instruction {
    pub addr: u64,
    pub disasm: String,
    /// Instruction category (`call`, `jmp`, `ret`, `cjmp`, …) when known.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Direct branch/call destination, when statically known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump: Option<u64>,
    /// Fall-through destination for a conditional branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<u64>,
}

/// A function's disassembly.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Disassembly {
    pub addr: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub ops: Vec<Instruction>,
}

/// One basic block inside a control-flow graph.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BasicBlock {
    pub addr: u64,
    pub ninstr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<u64>,
    pub ops: Vec<Instruction>,
}

/// A function's control-flow graph.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FunctionGraph {
    pub addr: u64,
    pub name: String,
    pub blocks: Vec<BasicBlock>,
}

/// One string recovered from the binary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StringRef {
    #[serde(rename = "vaddr")]
    pub addr: u64,
    pub string: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// One imported symbol.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Import {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// One cross-reference.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Xref {
    pub from: u64,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcn_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcode: Option<String>,
}

/// Decompiler output for one function.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Decompilation {
    pub addr: u64,
    pub name: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<Value>,
}

/// The analysis engine contract. Implementations are `Send + Sync` so a host
/// can hold one behind a lock and drive it from either the UI thread or the
/// async agent runtime. Methods take `&self`; implementations use interior
/// mutability for their own process/state.
pub trait Engine: Send + Sync {
    /// Which implementation this is.
    fn backend(&self) -> BackendKind;

    /// Features this backend actually supports.
    fn capabilities(&self) -> Capabilities;

    /// The analysed binary's path.
    fn path(&self) -> &Path;

    /// Run the backend's analysis pass. Idempotent.
    fn analyze(&self) -> Result<(), String>;

    /// Full binary summary, shaped for the UI
    /// (`{path, info:{bin:{...}}, function_count, string_count}`).
    fn summary(&self) -> Result<Value, String>;

    /// Raw backend metadata (`ij` on r2), shaped for the UI.
    fn info(&self) -> Result<Value, String>;

    /// All discovered functions.
    fn functions(&self) -> Result<Vec<FunctionInfo>, String>;

    /// The function containing `addr`, if any.
    fn function_at(&self, addr: u64) -> Result<Option<FunctionInfo>, String>;

    /// Disassemble `count` instructions starting at `target` (following the
    /// function when `count` is `None`).
    fn disassemble(&self, target: &Target, count: Option<usize>) -> Result<Disassembly, String>;

    /// Disassemble the whole function containing `addr`.
    fn function_disasm(&self, addr: u64) -> Result<Disassembly, String>;

    /// Reconstruct the control-flow graph of the function containing `addr`.
    fn function_graph(&self, addr: u64) -> Result<FunctionGraph, String>;

    /// Recover strings referenced by the binary.
    fn strings(&self) -> Result<Vec<StringRef>, String>;

    /// List imported symbols.
    fn imports(&self) -> Result<Vec<Import>, String>;

    /// Cross-references to/from `target`.
    fn xrefs(&self, target: &Target, direction: XrefDirection) -> Result<Vec<Xref>, String>;

    /// Decompile the function containing `addr`.
    fn decompile(&self, addr: u64) -> Result<Decompilation, String>;

    /// Backend-specific console passthrough (r2 command syntax on r2). Returns
    /// the backend's structured or textual output unchanged.
    fn raw(&self, cmd: &str) -> Result<Value, String>;

    /// Resolve a symbol name to an address, if the backend knows it.
    fn resolve(&self, name: &str) -> Result<Option<u64>, String>;

    /// Child process id for interrupt/teardown; 0 when the backend is
    /// in-process or unknown.
    fn pid(&self) -> u32 {
        0
    }

    /// Best-effort interrupt of a blocked operation. Returns false when the
    /// backend has no interruptible process.
    fn interrupt(&self) -> bool {
        false
    }

    /// Last-resort kill of a wedged backend process. Returns false when there
    /// is nothing to kill.
    fn force_kill(&self) -> bool {
        false
    }
}

/// JSON schema for the single backend-neutral analysis tool.
///
/// One tool with a structured `op` keeps the schema small (it is re-sent with
/// every request) while staying independent of any backend's command syntax.
/// `op:"raw"` is the documented escape hatch for backend-specific consoles.
///
/// ```
/// use librecurse::engine::tool_schema;
/// let schema = tool_schema();
/// assert_eq!(schema["function"]["name"], "analyze");
/// assert!(schema["function"]["parameters"]["properties"]["op"].is_object());
/// ```
pub fn tool_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": TOOL_NAME,
            "description": "Inspect the loaded binary through the active analysis backend. \
                This is the primary way to examine the target: prefer it over shelling out. \
                Analysis state persists, so call `analyze` once and then query. \
                Ops: `analyze` run analysis; `functions` list functions; \
                `disasm` disassemble (give `addr` and optional `count`); \
                `graph` control-flow graph of a function; `decompile` pseudocode of a function; \
                `xrefs` cross-references (`direction` \"to\" or \"from\"); `strings`; \
                `imports`; `info` binary metadata; `raw` a backend console command (radare2 syntax when the r2 backend is active). \
                `addr` accepts a number, `0x` hex, or a symbol name. Results are compact JSON.",
            "parameters": {
                "type": "object",
                "properties": {
                    "op": {
                        "type": "string",
                        "enum": ["analyze", "functions", "disasm", "graph", "decompile", "xrefs", "strings", "imports", "info", "raw"]
                    },
                    "addr": {
                        "type": ["string", "integer"],
                        "description": "Target address or symbol name (hex, decimal, or name)."
                    },
                    "count": {
                        "type": "integer",
                        "description": "For `disasm`: number of instructions. Omit to use the whole function."
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["to", "from"],
                        "description": "For `xrefs`: which way the references point (default \"to\")."
                    },
                    "query": {
                        "type": "string",
                        "description": "Substring filter applied to `functions`, `strings`, or `imports`."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max items returned (default 60)."
                    },
                    "cmd": {
                        "type": "string",
                        "description": "For `raw`: the backend console command."
                    }
                },
                "required": ["op"]
            }
        }
    })
}

/// Hard ceiling on returned items, so a huge binary cannot blow the context.
pub const MAX_LIMIT: usize = 500;

/// Default items per list, matching the historical r2 tool.
pub const DEFAULT_LIMIT: usize = 60;

/// Serialize an envelope compactly. Minified on purpose: whitespace in a
/// 60-item envelope is paid for on every later turn.
///
/// ```
/// use librecurse::engine::compact;
/// use serde_json::json;
/// assert_eq!(compact(json!({"a": 1})), r#"{"a":1}"#);
/// ```
pub fn compact(value: Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Keep at most `limit` items, reporting how many were dropped.
///
/// ```
/// use librecurse::engine::take;
/// let v = vec![1, 2, 3, 4];
/// let (kept, dropped) = take(&v, 2);
/// assert_eq!(kept, vec![&1, &2]);
/// assert_eq!(dropped, 2);
/// ```
pub fn take<T>(items: &[T], limit: usize) -> (Vec<&T>, usize) {
    let kept = items.iter().take(limit).collect::<Vec<_>>();
    (kept, items.len().saturating_sub(limit))
}

/// Filter items with a case-insensitive substring match against one or more
/// candidate fields. An empty/whitespace query keeps everything.
fn matches_query(query: &str, candidates: &[&str]) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    candidates.iter().any(|c| c.to_lowercase().contains(&q))
}

/// Build a `{op, count, showing, items, truncated?, hint?}` envelope.
fn list_envelope(op: &str, total: usize, showing: usize, items: Value) -> Value {
    let mut env = json!({
        "op": op,
        "count": total,
        "showing": showing,
        "items": items,
    });
    if total > showing {
        env["truncated"] = json!(true);
        env["hint"] = json!(format!(
            "{total} items total; raise `limit` or narrow the query"
        ));
    }
    env
}

/// Execute one `analyze` tool call against an engine and return the compact
/// JSON result the model reads.
///
/// This is the single routing point between the backend-neutral tool schema
/// and whichever [`Engine`] the host selected, so the agent never encodes r2
/// (or native) specifics in its own logic.
///
/// ```
/// use librecurse::engine::{execute_tool, BackendKind, Capabilities};
/// use librecurse::engine::{Disassembly, Engine, FunctionGraph, FunctionInfo};
/// use librecurse::engine::{Import, StringRef, Target, Xref, XrefDirection};
/// use serde_json::{json, Value};
/// use std::path::Path;
///
/// struct Stub;
/// impl Engine for Stub {
///     fn backend(&self) -> BackendKind { BackendKind::Native }
///     fn capabilities(&self) -> Capabilities { Capabilities::none() }
///     fn path(&self) -> &Path { Path::new("/bin/true") }
///     fn analyze(&self) -> Result<(), String> { Ok(()) }
///     fn summary(&self) -> Result<Value, String> { Ok(json!({})) }
///     fn info(&self) -> Result<Value, String> { Ok(json!({})) }
///     fn functions(&self) -> Result<Vec<FunctionInfo>, String> {
///         Ok(vec![FunctionInfo { addr: 1, name: "main".into(), size: None, nbbs: None, edges: None, signature: None }])
///     }
///     fn function_at(&self, _a: u64) -> Result<Option<FunctionInfo>, String> { Ok(None) }
///     fn disassemble(&self, _t: &Target, _c: Option<usize>) -> Result<Disassembly, String> {
///         Ok(Disassembly { addr: 1, name: "main".into(), size: None, ops: vec![] })
///     }
///     fn function_disasm(&self, _a: u64) -> Result<Disassembly, String> {
///         Ok(Disassembly { addr: 1, name: "main".into(), size: None, ops: vec![] })
///     }
///     fn function_graph(&self, _a: u64) -> Result<FunctionGraph, String> {
///         Ok(FunctionGraph { addr: 1, name: "main".into(), blocks: vec![] })
///     }
///     fn strings(&self) -> Result<Vec<StringRef>, String> { Ok(vec![]) }
///     fn imports(&self) -> Result<Vec<Import>, String> { Ok(vec![]) }
///     fn xrefs(&self, _t: &Target, _d: XrefDirection) -> Result<Vec<Xref>, String> { Ok(vec![]) }
///     fn decompile(&self, _a: u64) -> Result<librecurse::engine::Decompilation, String> {
///         Err("unsupported".into())
///     }
///     fn raw(&self, _c: &str) -> Result<Value, String> { Err("unsupported".into()) }
///     fn resolve(&self, _n: &str) -> Result<Option<u64>, String> { Ok(None) }
/// }
///
/// let out = execute_tool(&Stub, &json!({"op": "functions"})).unwrap();
/// let env: Value = serde_json::from_str(&out).unwrap();
/// assert_eq!(env["op"], "functions");
/// assert_eq!(env["count"], 1);
/// ```
pub fn execute_tool(engine: &dyn Engine, args: &Value) -> Result<String, String> {
    let op = args
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing string argument 'op'".to_string())?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);
    let query = args.get("query").and_then(Value::as_str).unwrap_or("");

    match op {
        "analyze" => {
            engine.analyze()?;
            Ok(compact(json!({ "op": "analyze", "ok": true })))
        }
        "info" => {
            let info = engine.info()?;
            Ok(compact(json!({ "op": "info", "info": info })))
        }
        "functions" => {
            let all = engine.functions()?;
            let filtered: Vec<&FunctionInfo> = all
                .iter()
                .filter(|f| matches_query(query, &[f.name.as_str()]))
                .collect();
            let (kept, _) = take(&filtered, limit);
            let items = serde_json::to_value(kept).map_err(|e| e.to_string())?;
            Ok(compact(list_envelope(
                "functions",
                filtered.len(),
                items.as_array().map(Vec::len).unwrap_or(0),
                items,
            )))
        }
        "disasm" => {
            let target = required_target(args)?;
            let count = args
                .get("count")
                .and_then(Value::as_u64)
                .map(|v| v as usize);
            let dis = engine.disassemble(&target, count)?;
            let total = dis.ops.len();
            let (kept, _) = take(&dis.ops, limit);
            let items = serde_json::to_value(kept).map_err(|e| e.to_string())?;
            let mut env = list_envelope(
                "disasm",
                total,
                items.as_array().map(Vec::len).unwrap_or(0),
                items,
            );
            env["name"] = json!(dis.name);
            env["addr"] = json!(dis.addr);
            Ok(compact(env))
        }
        "graph" => {
            let addr = required_addr(engine, args)?;
            let graph = engine.function_graph(addr)?;
            Ok(compact(
                serde_json::to_value(graph).map_err(|e| e.to_string())?,
            ))
        }
        "decompile" => {
            let addr = required_addr(engine, args)?;
            if !engine.capabilities().decompile {
                return Err(format!(
                    "the {} backend has no decompiler; install radare2 + r2ghidra and set RECURSE_BACKEND=r2",
                    engine.backend().as_str()
                ));
            }
            let dec = engine.decompile(addr)?;
            Ok(compact(
                serde_json::to_value(dec).map_err(|e| e.to_string())?,
            ))
        }
        "xrefs" => {
            let target = required_target(args)?;
            let direction = match args.get("direction").and_then(Value::as_str) {
                Some("from") => XrefDirection::From,
                _ => XrefDirection::To,
            };
            let all = engine.xrefs(&target, direction)?;
            let filtered: Vec<&Xref> = all
                .iter()
                .filter(|x| {
                    matches_query(
                        query,
                        &[
                            x.fcn_name.as_deref().unwrap_or(""),
                            x.opcode.as_deref().unwrap_or(""),
                        ],
                    )
                })
                .collect();
            let (kept, _) = take(&filtered, limit);
            let items = serde_json::to_value(kept).map_err(|e| e.to_string())?;
            Ok(compact(list_envelope(
                "xrefs",
                filtered.len(),
                items.as_array().map(Vec::len).unwrap_or(0),
                items,
            )))
        }
        "strings" => {
            let all = engine.strings()?;
            let filtered: Vec<&StringRef> = all
                .iter()
                .filter(|s| matches_query(query, &[s.string.as_str()]))
                .collect();
            let (kept, _) = take(&filtered, limit);
            let items = serde_json::to_value(kept).map_err(|e| e.to_string())?;
            Ok(compact(list_envelope(
                "strings",
                filtered.len(),
                items.as_array().map(Vec::len).unwrap_or(0),
                items,
            )))
        }
        "imports" => {
            let all = engine.imports()?;
            let filtered: Vec<&Import> = all
                .iter()
                .filter(|i| matches_query(query, &[i.name.as_str()]))
                .collect();
            let (kept, _) = take(&filtered, limit);
            let items = serde_json::to_value(kept).map_err(|e| e.to_string())?;
            Ok(compact(list_envelope(
                "imports",
                filtered.len(),
                items.as_array().map(Vec::len).unwrap_or(0),
                items,
            )))
        }
        "raw" => {
            let cmd = args
                .get("cmd")
                .and_then(Value::as_str)
                .ok_or_else(|| "op `raw` requires a `cmd` string".to_string())?;
            let out = engine.raw(cmd)?;
            Ok(compact(json!({ "op": "raw", "cmd": cmd, "result": out })))
        }
        other => Err(format!("unknown op: {other}")),
    }
}

/// Parse the required `addr` argument into a [`Target`].
fn required_target(args: &Value) -> Result<Target, String> {
    args.get("addr")
        .and_then(Target::from_json)
        .ok_or_else(|| "this op requires an `addr` (number, hex string, or symbol)".to_string())
}

/// Resolve the required `addr` argument to a concrete address, using the
/// backend's symbol table for names.
fn required_addr(engine: &dyn Engine, args: &Value) -> Result<u64, String> {
    let target = required_target(args)?;
    match target {
        Target::Addr(a) => Ok(a),
        Target::Symbol(name) => engine
            .resolve(&name)?
            .ok_or_else(|| format!("could not resolve symbol `{name}`")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn backend_names_parse_and_default() {
        assert_eq!(BackendKind::parse("r2"), Some(BackendKind::R2));
        assert_eq!(BackendKind::parse("RADARE2"), Some(BackendKind::R2));
        assert_eq!(BackendKind::parse("native"), Some(BackendKind::Native));
        assert_eq!(BackendKind::parse("ida"), None);
        assert_eq!(BackendKind::R2.as_str(), "r2");
    }

    #[test]
    fn default_backend_is_native() {
        assert_eq!(BackendKind::default(), BackendKind::Native);
    }

    #[test]
    fn target_parsing_accepts_all_forms() {
        assert_eq!(
            Target::from_json(&json!(0x1149)),
            Some(Target::Addr(0x1149))
        );
        assert_eq!(
            Target::from_json(&json!("0x1149")),
            Some(Target::Addr(0x1149))
        );
        assert_eq!(Target::from_json(&json!("4437")), Some(Target::Addr(4437)));
        assert_eq!(
            Target::from_json(&json!("sym.main")),
            Some(Target::Symbol("sym.main".into()))
        );
        assert_eq!(Target::from_json(&json!("   ")), None);
        assert_eq!(Target::from_json(&json!(true)), None);
    }

    #[test]
    fn schema_is_one_neutral_tool() {
        let schema = tool_schema();
        assert_eq!(schema["function"]["name"], TOOL_NAME);
        let variants = schema["function"]["parameters"]["properties"]["op"]["enum"]
            .as_array()
            .unwrap();
        for op in ["decompile", "xrefs", "functions", "raw"] {
            assert!(variants.iter().any(|v| v == op), "{op} missing");
        }
    }
}
