//! Native radare2 access for the agent.
//!
//! One tool ([`TOOL_NAME`]) instead of steering the model through `bash` plus
//! `r2 -q -c`, which cost roughly half of every run's input tokens:
//!
//! * **One persistent session** per target. `r2 -q0` is spawned once and driven
//!   over its NUL-framed pipe, so analysis state survives between calls. The
//!   bash path re-ran `aa`/`aaa` on every invocation because each call was a
//!   fresh process.
//! * **JSON-first.** Commands are upgraded to their `j` twin ([`jsonify`]),
//!   parsed, and projected onto the fields that matter ([`normalize`]). `aflj`
//!   carries ~30 keys per function and `pdfj` ~17 per instruction, almost none
//!   of which the model reads.
//! * **Colour-free.** ANSI escapes measured at 48% of all tool output (258KB of
//!   539KB, ~287k tokens cumulatively). The session disables colour and
//!   [`strip_ansi`] removes escapes from any output regardless of source.
//! * **Deduplicated.** Repeating a call returns a short pointer rather than a
//!   second copy of the same bytes.
//!
//! Hosts own the session: it needs a target path and a child process. They route
//! the `r2` tool call into [`Session::call`]. Everything else here is a pure
//! function over r2's output and is unit-tested without radare2 installed.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Map, Value};

/// Tool name hosts must route to [`Session::call`].
pub const TOOL_NAME: &str = "r2";

/// Items kept per list command unless the caller asks for more.
const DEFAULT_LIMIT: usize = 60;

/// Hard ceiling on items, so a huge binary cannot blow the context window.
const MAX_LIMIT: usize = 500;

/// Budget for free-form (non-JSON) output.
const MAX_TEXT_CHARS: usize = 3_000;

/// Budget for a structured envelope. `pdfj` on a large function can still be
/// tens of KB, so items are dropped from the tail until it fits.
const MAX_ENVELOPE_CHARS: usize = 6_000;

/// Ceiling on a single raw response from r2.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// The single binary-analysis tool.
///
/// One tool rather than a family of `r2_disasm`/`r2_xref`/`r2_strings` tools:
/// analysis is one permission and one UI affordance, and a lone `cmd` string
/// keeps the schema small (the schema is re-sent with every request) while
/// letting the model use the r2 vocabulary it already knows.
///
/// ```
/// use librecurse::r2::tool_schema;
/// let schema = tool_schema();
/// assert_eq!(schema["function"]["name"], "r2");
/// assert!(schema["function"]["description"]
///     .as_str()
///     .unwrap()
///     .contains("do NOT call r2 through bash"));
/// ```
pub fn tool_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": TOOL_NAME,
            "description": "Run a radare2 command against the loaded binary and get structured JSON back. \
                This is the only way to inspect the binary: do NOT call r2 through bash. \
                Analysis state persists between calls, so analyse once (`aaa`) and then query. \
                Commands: `aaa` analyse; `afl` functions; `pdf @ <addr|name>` disassemble a function; \
                `pd <n> @ <addr>` disassemble n instructions; `axt @ <addr>` xrefs to an address; \
                `izz` strings; `iij` imports; `ij` binary info; `s <addr>` seek; `px <n> @ <addr>` hexdump. \
                Chain related commands with `;` in one call. Output is a compact envelope: \
                {cmd, count, items:[...]} with irrelevant fields dropped. \
                A repeated identical command returns {cached:true} instead of the same data again.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cmd": {
                        "type": "string",
                        "description": "r2 command, optionally chained with `;` and located with `@ addr`, e.g. `pdf @ main`"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max items/lines returned (default 60). Use a different limit to force a fresh result for a cached command."
                    }
                },
                "required": ["cmd"]
            }
        }
    })
}

/// Remove ANSI escape sequences (CSI/SGR, OSC, and two-byte escapes).
///
/// r2 emits one sequence per token of coloured disassembly, which measured as
/// 48% of all tool output before this existed.
///
/// ```
/// use librecurse::r2::strip_ansi;
/// let coloured = "\u{1b}[38;2;193;156;0m0x1149\u{1b}[0m  mov eax, 1";
/// assert_eq!(strip_ansi(coloured), "0x1149  mov eax, 1");
/// assert_eq!(strip_ansi("\u{1b}]0;title\u{7}ok"), "ok");
/// assert_eq!(strip_ansi("plain"), "plain");
/// ```
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('[') => {
                chars.next();
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                while let Some(c) = chars.next() {
                    if c == '\u{7}' {
                        break;
                    }
                    if c == '\u{1b}' {
                        let _ = chars.next();
                        break;
                    }
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

/// True for r2 progress chatter that is noise inside a tool result.
///
/// Analysis progress and relocation warnings appear once per command in the
/// bash path and carry no information for the model. Errors are kept: they are
/// how the model learns a command failed.
///
/// ```
/// use librecurse::r2::is_noise;
/// assert!(is_noise("INFO: Analyze all flags starting with sym. and entry0 (aa)"));
/// assert!(is_noise("WARN: Relocs has not been applied"));
/// assert!(!is_noise("ERROR: Cannot find function at 0x401000"));
/// assert!(!is_noise("0x1149  push rbp"));
/// ```
pub fn is_noise(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("INFO: ")
        || t.starts_with("WARN: Relocs has not been applied")
        || t.starts_with("WARN: Cannot find function")
        || t.starts_with("WARN: Invalid address")
}

/// Strip colour, drop progress chatter, and trim trailing blank lines.
///
/// ```
/// use librecurse::r2::tidy;
/// let raw = "INFO: analyzing\n\u{1b}[32m0x1149\u{1b}[0m  push rbp\n\n";
/// assert_eq!(tidy(raw), "0x1149  push rbp");
/// ```
pub fn tidy(raw: &str) -> String {
    let plain = strip_ansi(raw);
    let mut lines: Vec<&str> = plain.lines().filter(|l| !is_noise(l)).collect();
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

/// Which projection to apply, inferred from the r2 command.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Family {
    /// Function lists (`afl`).
    Functions,
    /// Disassembly and control-flow graphs (`pd`, `pdf`, `agfj`).
    Disasm,
    /// Cross references (`axt`, `axf`).
    Xrefs,
    /// Strings (`iz`, `izz`).
    Strings,
    /// Imports, symbols, exports (`ii`, `il`, `is`).
    Symbols,
    /// Binary metadata (`i`, `ij`).
    Info,
    /// Anything unrecognised: kept whole, capped by limit.
    Other,
}

/// Classify a command so [`normalize`] knows which fields to keep.
///
/// Any command in a `;`-chain can name the family, because the analysis
/// preamble (`aaa; aflj`) produces no output of its own. The JSON suffix is
/// stripped from the command token, which sits before its arguments.
///
/// ```
/// use librecurse::r2::{family, Family};
/// assert_eq!(family("aflj"), Family::Functions);
/// assert_eq!(family("aaa; aflj"), Family::Functions);
/// assert_eq!(family("pdfj @ 0x1149"), Family::Disasm);
/// assert_eq!(family("izz"), Family::Strings);
/// assert_eq!(family("aeim"), Family::Other);
/// ```
pub fn family(cmd: &str) -> Family {
    for part in cmd.split(';') {
        let token = part.split_whitespace().next().unwrap_or("");
        let stem = token.trim_end_matches('j');
        match stem {
            "afl" | "aflm" | "afll" => return Family::Functions,
            "pdf" | "pd" | "pD" | "pdb" | "pdc" | "pdg" => return Family::Disasm,
            // CFG commands wrap their instructions the same way disassembly does.
            "agf" | "agfj" | "agc" => return Family::Disasm,
            "axt" | "axf" | "axtg" | "afx" | "afxi" => return Family::Xrefs,
            "iz" | "izz" | "izq" => return Family::Strings,
            "ii" | "il" | "is" | "iE" | "iS" => return Family::Symbols,
            "i" | "ij" => return Family::Info,
            _ => continue,
        }
    }
    Family::Other
}

/// Fields worth keeping per family. Everything else r2 emits is noise for the
/// model: `esil`, `family`, `type_num`, `paddr`, `ordinal`, checksums, and so on.
///
/// ```
/// use librecurse::r2::{family, keep_fields};
/// assert!(keep_fields(family("aflj")).contains(&"signature"));
/// assert!(!keep_fields(family("aflj")).contains(&"esil"));
/// ```
pub fn keep_fields(f: Family) -> &'static [&'static str] {
    match f {
        Family::Functions => &["addr", "name", "size", "nbbs", "edges", "signature"],
        Family::Disasm => &["addr", "disasm", "type"],
        Family::Xrefs => &["from", "type", "fcn_name", "refname", "opcode"],
        Family::Strings => &["vaddr", "string", "type"],
        Family::Symbols => &["name", "plt", "bind", "type"],
        // `ij` keys inside its `bin` sub-object that are actually useful.
        Family::Info => &[
            "arch", "bits", "bintype", "os", "endian", "stripped", "class",
        ],
        Family::Other => &[],
    }
}

/// Take at most `limit` items, stopping early if the encoded items would blow
/// the envelope budget. Returns the kept items, how many were dropped, and
/// whether anything was left out.
///
/// ```
/// use librecurse::r2::take_items;
/// use serde_json::json;
/// let items = vec![json!({"addr": 1, "junk": "x"}), json!({"addr": 2, "junk": "y"})];
/// let (kept, dropped, truncated) = take_items(items.iter(), &["addr"], 10);
/// assert_eq!(kept.len(), 2);
/// assert_eq!(dropped, 0);
/// assert!(!truncated);
/// assert!(kept[0].get("junk").is_none());
/// ```
pub fn take_items<'a, I>(items: I, fields: &[&str], limit: usize) -> (Vec<Value>, usize, bool)
where
    I: Iterator<Item = &'a Value>,
{
    let mut kept = Vec::new();
    let mut used = 0usize;
    let mut total = 0usize;
    for item in items {
        total += 1;
        if kept.len() >= limit {
            continue;
        }
        let projected = project_item(item, fields);
        let size = serde_json::to_string(&projected)
            .map(|s| s.len())
            .unwrap_or(0);
        if used + size > MAX_ENVELOPE_CHARS && !kept.is_empty() {
            continue;
        }
        used += size;
        kept.push(projected);
    }
    let dropped = total - kept.len();
    (kept, dropped, dropped > 0)
}

/// Keep only `fields` from an object; pass non-objects through unchanged.
///
/// An empty `fields` means "keep everything", which is how unrecognised
/// commands are handled.
///
/// ```
/// use librecurse::r2::project_item;
/// use serde_json::json;
/// let item = json!({"addr": 4144, "name": "main", "esil": "junk"});
/// let projected = project_item(&item, &["addr", "name"]);
/// assert_eq!(projected, json!({"addr": 4144, "name": "main"}));
/// assert_eq!(project_item(&json!(7), &["addr"]), json!(7));
/// ```
pub fn project_item(item: &Value, fields: &[&str]) -> Value {
    let Value::Object(map) = item else {
        return item.clone();
    };
    if fields.is_empty() {
        return item.clone();
    }
    let mut out = Map::new();
    for f in fields {
        if let Some(v) = map.get(*f) {
            out.insert((*f).to_string(), v.clone());
        }
    }
    Value::Object(out)
}

/// Project the object shapes r2's JSON commands actually return, instead of
/// handing back every field r2 happens to emit:
///
/// * `pdfj` gives `{name, ops: [...]}`
/// * `agfj` gives `{addr, blocks: [{addr, ninstr, ops: [...]}]}`
/// * `ij` gives `{bin: {...}}`
///
/// Shape is checked before command name, so a command that is not in the family
/// table still gets projected correctly.
///
/// ```
/// use librecurse::r2::project_object;
/// use serde_json::{json, Map};
/// let raw = json!({"name": "main", "ops": [{"addr": 4550, "disasm": "push rbp", "esil": "junk"}]});
/// let map: Map<String, serde_json::Value> = raw.as_object().unwrap().clone();
/// let env = project_object("pdf @ main", &map, &["addr", "disasm"], 60);
/// assert_eq!(env["name"], "main");
/// assert_eq!(env["items"][0]["disasm"], "push rbp");
/// assert!(env["items"][0].get("esil").is_none());
/// ```
pub fn project_object(cmd: &str, map: &Map<String, Value>, fields: &[&str], limit: usize) -> Value {
    if let Some(Value::Array(ops)) = map.get("ops") {
        let op_fields: &[&str] = if fields.is_empty() {
            &["addr", "disasm", "type"]
        } else {
            fields
        };
        let (items, dropped, truncated) = take_items(ops.iter(), op_fields, limit);
        let mut env = json!({
            "cmd": cmd,
            "count": ops.len(),
            "showing": items.len(),
            "items": items,
        });
        if let Some(name) = map.get("name") {
            env["name"] = name.clone();
        }
        if truncated {
            env["truncated"] = json!(true);
            env["hint"] = json!(format!(
                "{dropped} instructions omitted; use `pd <n> @ <addr>` for a window"
            ));
        }
        return env;
    }
    if let Some(Value::Array(blocks)) = map.get("blocks") {
        let projected: Vec<Value> = blocks
            .iter()
            .take(limit)
            .map(|b| {
                let mut out = Map::new();
                for k in ["addr", "ninstr", "jump", "fail"] {
                    if let Some(v) = b.get(k) {
                        out.insert(k.to_string(), v.clone());
                    }
                }
                if let Some(Value::Array(ops)) = b.get("ops") {
                    let (items, _, _) = take_items(ops.iter(), &["addr", "disasm"], limit);
                    out.insert("ops".to_string(), Value::Array(items));
                }
                Value::Object(out)
            })
            .collect();
        let truncated = blocks.len() > projected.len();
        let mut env = json!({
            "cmd": cmd,
            "count": blocks.len(),
            "showing": projected.len(),
            "blocks": projected,
        });
        if truncated {
            env["truncated"] = json!(true);
        }
        return env;
    }
    if let Some(Value::Object(bin)) = map.get("bin") {
        let projected = project_item(&Value::Object(bin.clone()), fields);
        return json!({ "cmd": cmd, "info": { "bin": projected } });
    }
    // Wrapper shapes nest the interesting object one level down:
    // `agfj` returns `{count: 1, items: [{addr, blocks: [...]}]}`.
    if let Some(Value::Array(items)) = map.get("items") {
        if let [Value::Object(inner)] = items.as_slice() {
            if inner.contains_key("blocks") || inner.contains_key("ops") {
                return project_object(cmd, inner, fields, limit);
            }
        }
    }
    json!({ "cmd": cmd, "count": map.len(), "items": [Value::Object(map.clone())] })
}

/// Structure one r2 response into a compact JSON envelope.
///
/// Lists become `{cmd, count, showing, items, truncated}`; a single object is
/// compacted; anything else is capped text. The envelope is deliberately small
/// and shape-stable so the model reads structure rather than prose.
///
/// ```
/// use librecurse::r2::normalize;
/// use serde_json::Value;
/// let raw = r#"[{"addr":4224,"name":"main","esil":"","nlocals":2}]"#;
/// let env: Value = serde_json::from_str(&normalize("afl", raw, 60)).unwrap();
/// assert_eq!(env["count"], 1);
/// assert_eq!(env["items"][0]["name"], "main");
/// assert!(env["items"][0].get("esil").is_none());
///
/// // Empty output still yields a readable envelope rather than silence.
/// let empty: Value = serde_json::from_str(&normalize("afl", "INFO: nothing\n", 60)).unwrap();
/// assert_eq!(empty["count"], 0);
/// ```
pub fn normalize(cmd: &str, raw: &str, limit: usize) -> String {
    let limit = limit.clamp(1, MAX_LIMIT);
    let text = tidy(raw);
    if text.trim().is_empty() {
        return compact(json!({
            "cmd": cmd,
            "count": 0,
            "items": [],
            "note": "command produced no output",
        }));
    }

    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        let fields = keep_fields(family(cmd));
        match value {
            Value::Array(items) => {
                // Shape-first: CFG/disasm payloads wrap their data in an object
                // even when the top level is a list (`agfj` returns
                // `[{addr, blocks: [...]}]`), so dispatch on shape rather than
                // on a registry of command names.
                let nested = items.iter().any(|i| {
                    matches!(i, Value::Object(m) if m.contains_key("blocks") || m.contains_key("ops"))
                });
                if nested {
                    let projected: Vec<Value> = items
                        .iter()
                        .take(limit)
                        .map(|i| match i {
                            Value::Object(m) => project_object(cmd, m, fields, limit),
                            other => other.clone(),
                        })
                        .collect();
                    let truncated = items.len() > projected.len();
                    let mut env = json!({
                        "cmd": cmd,
                        "count": items.len(),
                        "showing": projected.len(),
                        "items": projected,
                    });
                    if truncated {
                        env["truncated"] = json!(true);
                    }
                    return compact(env);
                }
                let total = items.len();
                let (shown, _dropped, truncated) = take_items(items.iter(), fields, limit);
                let mut env = json!({
                    "cmd": cmd,
                    "count": total,
                    "showing": shown.len(),
                    "items": shown,
                });
                if truncated {
                    env["truncated"] = json!(true);
                    env["hint"] = json!(format!(
                        "{total} items total; raise `limit` or narrow the command"
                    ));
                }
                return compact(env);
            }
            Value::Object(map) => return compact(project_object(cmd, &map, fields, limit)),
            other => return compact(json!({ "cmd": cmd, "value": other })),
        }
    }

    // Not JSON: cap lines and characters rather than dumping a whole disassembly.
    let all: Vec<&str> = text.lines().collect();
    let total = all.len();
    let take = all.len().min(limit);
    let mut body = all[..take].join("\n");
    let mut truncated = total > take;
    if body.len() > MAX_TEXT_CHARS {
        let mut cut = MAX_TEXT_CHARS;
        while !body.is_char_boundary(cut) {
            cut -= 1;
        }
        body.truncate(cut);
        truncated = true;
    }
    let mut env = json!({ "cmd": cmd, "lines": total, "text": body });
    if truncated {
        env["truncated"] = json!(true);
        env["hint"] = json!("output capped; narrow the command or use its `j` form");
    }
    compact(env)
}

/// Serialize an envelope compactly.
///
/// Minified on purpose: whitespace in a 60-item envelope is paid for on every
/// later turn.
///
/// ```
/// use librecurse::r2::compact;
/// use serde_json::json;
/// assert_eq!(compact(json!({"a": 1})), r#"{"a":1}"#);
/// ```
pub fn compact(value: Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
}

/// Normalise a tool result regardless of which tool produced it.
///
/// `bash` output is colour-stripped and capped the same way as r2 output, so an
/// escape sequence cannot reach the model from any path. Small outputs pass
/// through untouched.
///
/// ```
/// use librecurse::r2::normalize_bash;
/// assert_eq!(normalize_bash("\u{1b}[1mbold\u{1b}[0m"), "bold");
/// let big = "x".repeat(9_000);
/// let capped = normalize_bash(&big);
/// assert!(capped.len() < big.len());
/// assert!(capped.contains("truncated"));
/// ```
pub fn normalize_bash(raw: &str) -> String {
    let text = tidy(raw);
    if text.len() <= MAX_TEXT_CHARS {
        return text;
    }
    let mut cut = MAX_TEXT_CHARS;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}\n[... {} chars truncated]",
        &text[..cut],
        text.len() - cut
    )
}

/// Commands with a JSON twin: same data, structured, and far smaller once
/// projected.
const JSON_TWINS: &[&str] = &[
    "afl", "afll", "aflm", "afi", "afij", "afv", "afvd", "pdf", "pd", "pD", "pdb", "pdc", "pdg",
    "px", "ps", "izz", "iz", "iij", "ii", "il", "is", "iE", "iS", "axt", "axf", "axtg", "agf",
    "ij", "i",
];

/// Upgrade a command to its JSON twin: `pdf @ main` becomes `pdfj @ main`.
///
/// The model writes the human form, so the tool upgrades it rather than relying
/// on the model to remember the suffix. Measured: 69 of 82 analysis calls came
/// back as capped text without this, and the projection never ran.
///
/// Returns `None` when there is no twin, it already requests JSON, or the
/// command is shaped by a filter or redirect where the twin would change what
/// was asked for.
///
/// ```
/// use librecurse::r2::jsonify;
/// assert_eq!(jsonify("pdf @ main").as_deref(), Some("pdfj @ main"));
/// assert_eq!(jsonify("izz").as_deref(), Some("izzj"));
/// assert_eq!(jsonify("pdfj @ main"), None);
/// assert_eq!(jsonify("afl~main"), None);
/// assert_eq!(jsonify("s main"), None);
/// ```
pub fn jsonify(part: &str) -> Option<String> {
    let trimmed = part.trim();
    if trimmed.is_empty()
        || trimmed.contains('~')
        || trimmed.contains('>')
        || trimmed.starts_with('#')
    {
        return None;
    }
    let mut fields = trimmed.splitn(2, char::is_whitespace);
    let token = fields.next().unwrap_or("");
    let rest = fields.next().unwrap_or("");
    if token.ends_with('j') || !JSON_TWINS.contains(&token) {
        return None;
    }
    Some(if rest.is_empty() {
        format!("{token}j")
    } else {
        format!("{token}j {rest}")
    })
}

/// Split an r2 `;`-chain into its parts.
///
/// Each part is run and structured separately, so a chain yields labelled parts
/// instead of several JSON arrays concatenated into one unparseable blob.
///
/// ```
/// use librecurse::r2::split_parts;
/// assert_eq!(split_parts("aaa; afl; izz"), vec!["aaa", "afl", "izz"]);
/// assert_eq!(split_parts("afl;"), vec!["afl"]);
/// assert!(split_parts("   ").is_empty());
/// ```
pub fn split_parts(cmd: &str) -> Vec<String> {
    cmd.split(';')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// True when an envelope carries no data, which is how a JSON twin that found
/// nothing is detected so the original command can be retried.
///
/// ```
/// use librecurse::r2::{is_empty_env, normalize};
/// assert!(is_empty_env(&normalize("afl", "INFO: nothing\n", 60)));
/// assert!(!is_empty_env(&normalize("afl", r#"[{"addr":1,"name":"main"}]"#, 60)));
/// ```
pub fn is_empty_env(env: &str) -> bool {
    serde_json::from_str::<Value>(env)
        .ok()
        .map(|v| {
            v.get("count").and_then(Value::as_u64) == Some(0)
                && v.get("items")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        })
        .unwrap_or(true)
}

/// Cache key for a `(command, limit)` pair.
///
/// A non-cryptographic hash is right here: the cache is per-session and only
/// guards against repeating an identical call.
///
/// ```
/// use librecurse::r2::result_key;
/// assert_eq!(result_key("afl", 60), result_key("afl", 60));
/// assert_ne!(result_key("afl", 60), result_key("afl", 10));
/// ```
pub fn result_key(cmd: &str, limit: usize) -> u64 {
    let mut h = DefaultHasher::new();
    cmd.hash(&mut h);
    limit.hash(&mut h);
    h.finish()
}

/// A persistent radare2 process driven over its NUL-framed `-q0` pipe.
///
/// Owned by the host, which supplies the target path. Cheap enough to open per
/// task: spawning takes milliseconds, while the analysis it preserves does not.
pub struct Session {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Normalised results already returned, keyed by [`result_key`].
    cache: HashMap<u64, String>,
}

impl Session {
    /// Spawn r2 with colour and interaction disabled.
    ///
    /// A tool result never needs escapes, and turning them off at the source is
    /// cheaper than stripping them. stderr is nulled because r2 writes analysis
    /// chatter there: piping it without reading risks stalling the child.
    ///
    /// ```no_run
    /// use librecurse::r2::Session;
    /// let session = Session::open(std::path::Path::new("/bin/true")).unwrap();
    /// assert!(session.pid() > 0);
    /// ```
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut command = Command::new("r2");
        command
            .arg("-q0")
            .args(["-e", "scr.color=0"])
            .args(["-e", "scr.utf8=false"])
            .args(["-e", "scr.interactive=false"])
            .args(["-e", "bin.cache=true"])
            .arg(path);
        // Own process group: lets interrupt/teardown signal r2 and any
        // children it spawns without touching unrelated processes. The group
        // id equals the child's pid on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to spawn radare2: {e}"))?;

        let stdin = child.stdin.take().ok_or("r2 stdin unavailable")?;
        let mut stdout = child.stdout.take().ok_or("r2 stdout unavailable")?;

        // The protocol opens with one NUL byte once r2 is ready.
        let mut nul = [0u8; 1];
        stdout
            .read_exact(&mut nul)
            .map_err(|e| format!("r2 did not initialize: {e}"))?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            cache: HashMap::new(),
        })
    }

    /// Run one command and return its raw output, escapes and all.
    ///
    /// ```no_run
    /// use librecurse::r2::Session;
    /// let mut session = Session::open(std::path::Path::new("/bin/true")).unwrap();
    /// let raw = session.run("ij").unwrap();
    /// assert!(raw.contains("bintype"));
    /// ```
    pub fn run(&mut self, cmd: &str) -> Result<String, String> {
        self.stdin
            .write_all(format!("{cmd}\n").as_bytes())
            .map_err(|e| format!("r2 write failed: {e}"))?;
        self.stdin.flush().ok();
        let mut res: Vec<u8> = Vec::new();
        loop {
            let mut chunk = [0u8; 4096];
            let n = self
                .stdout
                .read(&mut chunk)
                .map_err(|e| format!("r2 read failed: {e}"))?;
            if n == 0 {
                return Err("radare2 closed the pipe".into());
            }
            if let Some(pos) = chunk[..n].iter().position(|&b| b == 0) {
                res.extend_from_slice(&chunk[..pos]);
                break;
            }
            res.extend_from_slice(&chunk[..n]);
            if res.len() > MAX_RESPONSE_BYTES {
                return Err(format!("response exceeded {MAX_RESPONSE_BYTES} bytes"));
            }
        }
        String::from_utf8(res).map_err(|e| format!("invalid utf-8 from radare2: {e}"))
    }

    /// Run a command and return the structured envelope, deduplicating repeats.
    ///
    /// Chains are split so each part is structured on its own. A repeat of the
    /// same `(cmd, limit)` returns a pointer to the earlier result instead of a
    /// second copy.
    ///
    /// ```no_run
    /// use librecurse::r2::Session;
    /// let mut session = Session::open(std::path::Path::new("/bin/true")).unwrap();
    /// let first = session.call("ij", None).unwrap();
    /// let again = session.call("ij", None).unwrap();
    /// assert!(again.contains(r#""cached":true"#));
    /// assert!(first.contains(r#""items""#));
    /// ```
    pub fn call(&mut self, cmd: &str, limit: Option<usize>) -> Result<String, String> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let key = result_key(cmd, limit);
        if let Some(previous) = self.cache.get(&key) {
            let count = serde_json::from_str::<Value>(previous)
                .ok()
                .and_then(|v| v.get("count").and_then(Value::as_u64));
            let mut env = json!({
                "cmd": cmd,
                "cached": true,
                "note": "identical to an earlier call; result unchanged. Use a different limit to force a refresh.",
            });
            if let Some(c) = count {
                env["count"] = json!(c);
            }
            return Ok(compact(env));
        }
        let parts = split_parts(cmd);
        let normalized = match parts.len() {
            0 => normalize(cmd, "", limit),
            1 => {
                let part = parts.first().map(String::as_str).unwrap_or(cmd);
                self.run_part(part, limit)?
            }
            _ => {
                let mut envelopes = Vec::with_capacity(parts.len());
                for part in &parts {
                    let env = self.run_part(part, limit)?;
                    envelopes.push(serde_json::from_str::<Value>(&env).unwrap_or(Value::Null));
                }
                compact(json!({ "cmd": cmd, "parts": envelopes }))
            }
        };
        self.cache.insert(key, normalized.clone());
        Ok(normalized)
    }

    /// Run one command, preferring its JSON twin and falling back to the form
    /// the model wrote if the twin yields nothing.
    ///
    /// ```no_run
    /// use librecurse::r2::Session;
    /// let mut session = Session::open(std::path::Path::new("/bin/true")).unwrap();
    /// let env = session.run_part("pdf @ main", 60).unwrap();
    /// assert!(env.starts_with('{'));
    /// ```
    pub fn run_part(&mut self, part: &str, limit: usize) -> Result<String, String> {
        if let Some(json_form) = jsonify(part) {
            let raw = self.run(&json_form)?;
            let env = normalize(part, &raw, limit);
            if !is_empty_env(&env) {
                return Ok(env);
            }
        }
        let raw = self.run(part)?;
        Ok(normalize(part, &raw, limit))
    }

    /// Analyse once at startup so function names and xrefs exist for later
    /// queries. Output is discarded: it is progress chatter, not an answer.
    ///
    /// ```no_run
    /// use librecurse::r2::Session;
    /// let mut session = Session::open(std::path::Path::new("/bin/true")).unwrap();
    /// session.warm_up().unwrap();
    /// let funcs = session.call("afl", None).unwrap();
    /// assert!(funcs.contains("sym."));
    /// ```
    pub fn warm_up(&mut self) -> Result<(), String> {
        self.run("aa; aac").map(|_| ())
    }

    /// Process id of the r2 child, for host-side interrupt or teardown.
    ///
    /// ```no_run
    /// use librecurse::r2::Session;
    /// let session = Session::open(std::path::Path::new("/bin/true")).unwrap();
    /// assert_ne!(session.pid(), 0);
    /// ```
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Session {
    /// Quit r2 and reap the child.
    ///
    /// `q!` stops it immediately; the `wait` reaps it, so a dropped session
    /// never leaves a zombie process behind.
    ///
    /// ```no_run
    /// use librecurse::r2::Session;
    /// let session = Session::open(std::path::Path::new("/bin/true")).unwrap();
    /// drop(session); // child is quit and reaped here
    /// ```
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"q!\n");
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn strips_colour_and_other_escapes() {
        // The exact shape r2 emits for coloured disassembly.
        let raw = "\u{1b}[38;2;193;156;0m0x1149\u{1b}[0m  mov eax, 1";
        assert_eq!(strip_ansi(raw), "0x1149  mov eax, 1");
        // OSC title, two-byte escapes, and plain text survive correctly.
        assert_eq!(strip_ansi("\u{1b}]0;title\u{7}ok"), "ok");
        assert_eq!(strip_ansi("\u{1b}7plain\u{1b}8"), "plain");
        assert_eq!(strip_ansi("no escapes"), "no escapes");
    }

    #[test]
    fn tidy_drops_progress_chatter_but_keeps_errors() {
        let raw = "INFO: Analyze all flags starting with sym. and entry0 (aa)\n\
                   WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true`\n\
                   ERROR: Cannot find function at 0x401000\n\
                   real output";
        let out = tidy(raw);
        assert_eq!(out, "ERROR: Cannot find function at 0x401000\nreal output");
    }

    #[test]
    fn functions_are_projected_onto_useful_fields() {
        // aflj carries ~30 keys per function; almost none are read by the model.
        let raw = r#"[{"addr":4224,"name":"main","size":57,"nbbs":3,"edges":3,
            "signature":"int main(int argc, char **argv)","esil":"","family":"cpu",
            "type_num":0,"realsz":57,"stackframe":24,"is-pure":false,"nlocals":2}]"#;
        let env: Value = serde_json::from_str(&normalize("afl", raw, 60)).unwrap();
        assert_eq!(env["count"], 1);
        let item = &env["items"][0];
        assert_eq!(item["name"], "main");
        assert_eq!(item["signature"], "int main(int argc, char **argv)");
        for dropped in [
            "esil",
            "family",
            "type_num",
            "realsz",
            "stackframe",
            "is-pure",
        ] {
            assert!(item.get(dropped).is_none(), "{dropped} should be dropped");
        }
    }

    #[test]
    fn disassembly_keeps_address_and_text_only() {
        let raw = r#"[{"addr":4224,"disasm":"push rbp","bytes":"55","esil":"",
             "family":"cpu","type":"push","type_num":0,"size":1,"opcode":"push rbp"}]"#;
        let env: Value = serde_json::from_str(&normalize("pd 20 @ main", raw, 60)).unwrap();
        let op = &env["items"][0];
        assert_eq!(op["addr"], 4224);
        assert_eq!(op["disasm"], "push rbp");
        assert!(
            op.get("bytes").is_none(),
            "byte dumps are re-derivable and bulky"
        );
        assert!(op.get("esil").is_none());
        assert!(op.get("opcode").is_none(), "duplicate of disasm");
    }

    #[test]
    fn list_commands_are_capped_with_a_hint() {
        let items: Vec<String> = (0..200)
            .map(|i| format!("{{\"vaddr\":{i},\"string\":\"s{i}\",\"paddr\":9,\"ordinal\":{i}}}"))
            .collect();
        let raw = format!("[{}]", items.join(","));
        let env: Value = serde_json::from_str(&normalize("izz", &raw, 50)).unwrap();
        assert_eq!(env["count"], 200);
        assert_eq!(env["showing"], 50);
        assert_eq!(env["truncated"], true);
        assert!(env["hint"].as_str().unwrap().contains("200 items total"));
        assert!(env["items"][0].get("paddr").is_none(), "strings projected");
        assert!(env["items"][0].get("ordinal").is_none());
    }

    #[test]
    fn text_output_is_capped_not_dumped() {
        let raw = (0..500)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let env: Value = serde_json::from_str(&normalize("some textcmd", &raw, 40)).unwrap();
        assert_eq!(env["lines"], 500);
        assert_eq!(env["truncated"], true);
        assert!(env["text"].as_str().unwrap().lines().count() == 40);
    }

    #[test]
    fn empty_output_is_an_envelope_not_silence() {
        let env: Value = serde_json::from_str(&normalize("afl", "INFO: nothing\n", 60)).unwrap();
        assert_eq!(env["count"], 0);
        assert!(env["items"].as_array().is_some_and(|a| a.is_empty()));
        assert!(env["note"]
            .as_str()
            .is_some_and(|n| n.contains("no output")));
    }

    #[test]
    fn bash_output_is_colour_stripped_and_bounded() {
        let raw = format!("\u{1b}[32mok\u{1b}[0m\n{}", "x".repeat(9_000));
        let out = normalize_bash(&raw);
        assert!(out.starts_with("ok\n"));
        assert!(!out.contains('\u{1b}'));
        assert!(
            out.len() < 3_100,
            "capped to the text budget: {}",
            out.len()
        );
        assert!(out.contains("truncated"));
        // Small outputs pass through untouched.
        assert_eq!(normalize_bash("\u{1b}[1mbold\u{1b}[0m"), "bold");
    }

    #[test]
    fn family_detection_handles_chains_and_json_suffixes() {
        assert_eq!(family("aflj"), Family::Functions);
        assert_eq!(family("aaa; aflj"), Family::Functions);
        assert_eq!(family("pdf @ main"), Family::Disasm);
        assert_eq!(family("pdfj @ 0x1149"), Family::Disasm);
        assert_eq!(family("izzj"), Family::Strings);
        assert_eq!(family("aeim"), Family::Other);
    }

    #[test]
    fn commands_are_upgraded_to_their_json_twin() {
        // The model writes the human form; the tool upgrades it, because
        // measured, 69 of 82 analysis calls came back as capped text otherwise.
        assert_eq!(jsonify("pdf @ main").as_deref(), Some("pdfj @ main"));
        assert_eq!(jsonify("afl").as_deref(), Some("aflj"));
        assert_eq!(jsonify("pd 40 @ main").as_deref(), Some("pdj 40 @ main"));
        assert_eq!(jsonify("izz").as_deref(), Some("izzj"));
        // Already JSON, or no twin: leave alone.
        assert_eq!(jsonify("pdfj @ main"), None);
        assert_eq!(jsonify("aaa"), None);
        assert_eq!(jsonify("s main"), None);
        // Filters and redirects shape the output; the JSON form would not.
        assert_eq!(jsonify("afl~main"), None);
        assert_eq!(jsonify("pdf > /tmp/x"), None);
    }

    #[test]
    fn chains_split_into_parts() {
        assert_eq!(split_parts("aaa; afl; izz"), vec!["aaa", "afl", "izz"]);
        assert_eq!(split_parts("afl;"), vec!["afl"], "empty tail dropped");
        assert_eq!(split_parts("  "), Vec::<String>::new());
        assert_eq!(split_parts("pdf @ main"), vec!["pdf @ main"]);
    }

    #[test]
    fn binary_info_is_projected_not_dumped() {
        // `ij` nests a large object under `bin` full of checksums and build
        // metadata the model never reads.
        let raw = r#"{"bin":{"arch":"x86","bits":64,"bintype":"elf","os":"linux",
            "checksums":{},"compiled":"","class":"ELF64","stripped":true,
            "binsz":15725,"lang":"c"},"core":{"type":"Executable file"}}"#;
        let env: Value = serde_json::from_str(&normalize("ij", raw, 60)).unwrap();
        let bin = &env["info"]["bin"];
        assert_eq!(bin["arch"], "x86");
        assert_eq!(bin["bits"], 64);
        assert_eq!(bin["bintype"], "elf");
        for dropped in ["checksums", "compiled", "binsz", "lang"] {
            assert!(bin.get(dropped).is_none(), "{dropped} should be dropped");
        }
    }

    #[test]
    fn empty_envelope_detection_drives_the_fallback() {
        let empty = normalize("afl", "INFO: nothing here\n", 60);
        assert!(
            is_empty_env(&empty),
            "no output means try the original form"
        );
        let data = normalize("afl", r#"[{"addr":1,"name":"main"}]"#, 60);
        assert!(!is_empty_env(&data));
    }

    #[test]
    fn pdfj_style_objects_have_their_ops_projected() {
        // `pdfj` returns {name, ops:[...]} — ops carry ~17 keys each, and this
        // was the single worst case: unprojected, a real `pdf @ main` came back
        // as 24KB of esil/bytes/opcode noise.
        let raw = r#"{"addr":4550,"name":"main","size":552,"ops":[
            {"addr":4550,"disasm":"push rbp","bytes":"55","esil":"rbp,8,rsp,-,=[8]",
             "family":"cpu","fcn_addr":4550,"fcn_last":5102,"flags":["main"],
             "opcode":"push rbp","size":1,"type":"push","type_num":0}]}"#;
        let env: Value = serde_json::from_str(&normalize("pdf @ main", raw, 60)).unwrap();
        assert_eq!(env["name"], "main");
        assert_eq!(env["count"], 1);
        let op = &env["items"][0];
        assert_eq!(op["addr"], 4550);
        assert_eq!(op["disasm"], "push rbp");
        for dropped in [
            "bytes", "esil", "family", "fcn_addr", "fcn_last", "flags", "opcode",
        ] {
            assert!(op.get(dropped).is_none(), "{dropped} should be dropped");
        }
    }

    #[test]
    fn cfg_blocks_are_projected() {
        let raw = r#"{"blocks":[{"addr":4096,"ninstr":2,"jump":4200,"fail":4150,
            "ops":[{"addr":4096,"disasm":"push rbp","bytes":"55","esil":""}],
            "ninstr2":9,"dummy":true}]}"#;
        let env: Value = serde_json::from_str(&normalize("agfj @ main", raw, 60)).unwrap();
        let block = &env["blocks"][0];
        assert_eq!(block["addr"], 4096);
        assert_eq!(block["jump"], 4200);
        assert!(block.get("dummy").is_none());
        assert_eq!(block["ops"][0]["disasm"], "push rbp");
        assert!(block["ops"][0].get("bytes").is_none());
    }

    #[test]
    fn cfg_wrapped_in_items_is_projected_too() {
        // Real `agfj` shape: {count, items:[{addr, blocks:[...]}]} — the blocks
        // sit one level deeper than the plain form, and missing that left a
        // 25KB unprojected envelope in a live run.
        let raw = r#"{"count":1,"items":[{"addr":4550,"blocks":[
            {"addr":4550,"ninstr":2,"jump":5064,"fail":5050,
             "ops":[{"addr":4550,"disasm":"push rbp","bytes":"55","esil":"rbp"}]}]}]}"#;
        let env: Value = serde_json::from_str(&normalize("agfj @ main", raw, 60)).unwrap();
        assert_eq!(env["count"], 1);
        let block = &env["blocks"][0];
        assert_eq!(block["addr"], 4550);
        assert_eq!(block["ops"][0]["disasm"], "push rbp");
        assert!(block["ops"][0].get("esil").is_none());
    }

    #[test]
    fn a_large_envelope_is_cut_to_budget() {
        // A big function must not hand back a 20KB envelope: items are dropped
        // from the tail until it fits.
        let ops: Vec<String> = (0..400)
            .map(|i| {
                format!(
                    "{{\"addr\":{},\"disasm\":\"mov rax, qword [rbp - 0x{:x}] ; some long comment\",\"esil\":\"{}\"}}",
                    i,
                    i,
                    "x".repeat(80)
                )
            })
            .collect();
        let raw = format!("{{\"name\":\"big\",\"ops\":[{}]}}", ops.join(","));
        let env_text = normalize("pdf @ big", &raw, 500);
        assert!(
            env_text.len() <= MAX_ENVELOPE_CHARS + 400,
            "envelope {} bytes",
            env_text.len()
        );
        let env: Value = serde_json::from_str(&env_text).unwrap();
        assert_eq!(env["count"], 400);
        assert_eq!(env["truncated"], true);
        assert!(env["showing"].as_u64().unwrap() < 400);
    }

    #[test]
    fn array_wrapped_cfg_is_projected() {
        // Real `agfj` output is a top-level list whose item holds the blocks.
        // Unprojected this was 25KB in a live run.
        let raw = r#"[{"addr":4550,"name":"main","nargs":0,"blocks":[
            {"addr":4550,"ninstr":1,"jump":5064,"fail":5050,"size":4,
             "ops":[{"addr":4550,"disasm":"push rbp","bytes":"55","esil":"rbp,8,rsp,-,=[8]"}]}]}]"#;
        let env: Value = serde_json::from_str(&normalize("agfj @ main", raw, 60)).unwrap();
        let entry = &env["items"][0];
        let block = &entry["blocks"][0];
        assert_eq!(block["addr"], 4550);
        assert_eq!(block["jump"], 5064);
        assert_eq!(block["ops"][0]["disasm"], "push rbp");
        assert!(block["ops"][0].get("esil").is_none(), "op fields projected");
        assert!(
            entry.get("nargs").is_none(),
            "function header fields dropped"
        );
    }

    #[test]
    fn schema_is_one_tool_and_names_itself() {
        let schema = tool_schema();
        assert_eq!(schema["function"]["name"], TOOL_NAME);
        assert!(schema["function"]["parameters"]["properties"]["cmd"].is_object());
        // The description must steer away from the bash path explicitly.
        let desc = schema["function"]["description"].as_str().unwrap();
        assert!(desc.contains("do NOT call r2 through bash"));
    }
}
