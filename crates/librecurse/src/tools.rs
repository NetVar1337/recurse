use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

use crate::agent::ToolCall;

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

/// Minimal agent schema: one backend-neutral binary-analysis tool
/// (`analyze`, see [`crate::engine::tool_schema`]), a shell for scripts
/// (`bash`), files (`read`/`write`/`edit`). Memory tools are appended by the
/// host from [`crate::memory::memory_tool_schema`].
///
/// Analysis goes through the `analyze` tool rather than `bash`: the host
/// serves it from the selected engine (native or radare2), keeps one analysed
/// session, returns projected JSON instead of coloured text, and caps what it
/// hands back. The tool vocabulary itself is backend-independent, and
/// `capabilities` filters out ops the backend cannot serve (e.g. `decompile`
/// and `raw` on the native backend) so the model never sees them.
pub fn schema(capabilities: crate::engine::Capabilities) -> Vec<Value> {
    vec![
        crate::engine::tool_schema(capabilities),
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

async fn bash_execute_simple(
    command: &str,
    workdir: Option<String>,
    timeout: Option<u64>,
) -> Result<String, String> {
    // tokio timeout around wait_with_output. kill_on_drop means a timeout
    // kills the child instead of leaking it (the old thread-based version
    // left timed-out processes running); the error text is unchanged.
    let workdir = workdir.unwrap_or_else(|| ".".to_string());
    let dur = Duration::from_millis(timeout.unwrap_or(120_000));
    let child = tokio::process::Command::new("bash")
        .arg("-lc")
        .arg(command)
        .current_dir(&workdir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("bash spawn failed: {e}"))?;
    let out = tokio::time::timeout(dur, child.wait_with_output())
        .await
        .map_err(|_| format!("command timed out after {}ms: {command}", dur.as_millis()))?
        .map_err(|e| format!("bash wait failed: {e}"))?;
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

async fn read_path(
    file_path: &str,
    offset: Option<u64>,
    limit: Option<u64>,
) -> Result<Value, String> {
    let path = Path::new(file_path);
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|_| format!("File not found: {file_path}"))?;
    if meta.is_dir() {
        let mut dir = tokio::fs::read_dir(path).await.map_err(|e| e.to_string())?;
        let mut entries = Vec::new();
        while let Some(entry) = dir.next_entry().await.map_err(|e| e.to_string())? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                entries.push(format!("{name}/"));
            } else {
                entries.push(name);
            }
        }
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
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("failed to read {file_path}: {e}"))?;
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

async fn write_path(file_path: &str, content: &str) -> Result<Value, String> {
    let path = Path::new(file_path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("failed to create dirs for {file_path}: {e}"))?;
        }
    }
    tokio::fs::write(path, content)
        .await
        .map_err(|e| format!("failed to write {file_path}: {e}"))?;
    Ok(json!({ "wrote": file_path, "bytes": content.len() }))
}

async fn edit_path(
    file_path: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> Result<Value, String> {
    if old_string == new_string {
        return Err("oldString and newString are identical".into());
    }
    let path = Path::new(file_path);
    if !tokio::fs::try_exists(path).await.unwrap_or(false) {
        return Err(format!("File not found: {file_path}"));
    }
    if tokio::fs::metadata(path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Err(format!("Path is a directory, not a file: {file_path}"));
    }
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| format!("failed to read {file_path}: {e}"))?;
    if old_string.is_empty() {
        return Err("oldString cannot be empty".into());
    }
    let count = content.matches(old_string).count();
    if count > 0 {
        if !replace_all && count > 1 {
            return Err("Found multiple matches for oldString. Provide more surrounding lines to make it unique or use replaceAll=true".into());
        }
        let new_content = if replace_all {
            content.replace(old_string, new_string)
        } else {
            content.replacen(old_string, new_string, 1)
        };
        tokio::fs::write(path, &new_content)
            .await
            .map_err(|e| format!("failed to write {file_path}: {e}"))?;
        return Ok(
            json!({ "edited": file_path, "replacements": if replace_all { count } else { 1 } }),
        );
    }

    // Exact match failed — fall back to Levenshtein fuzzy matching over
    // same-sized line windows so small drift (whitespace, typos) still lands.
    let (start, end, score, candidate) = best_fuzzy_match(&content, old_string)
        .ok_or_else(|| "oldString not found in content".to_string())?;
    if score < FUZZY_THRESHOLD {
        return Err(format!(
            "oldString not found. Closest match ({:.0}% similar):\n{candidate}",
            score * 100.0
        ));
    }
    let lines: Vec<&str> = content.lines().collect();
    let trailing_newline = content.ends_with('\n');
    let mut out = String::with_capacity(content.len() + new_string.len());
    let mut replacements = 0usize;
    if replace_all {
        // Replace every window scoring above threshold.
        let mut i = 0usize;
        while i < lines.len() {
            let wend = (i + (end - start)).min(lines.len());
            if wend > i && similarity(&lines[i..wend].join("\n"), old_string) >= FUZZY_THRESHOLD {
                out.push_str(new_string);
                ensure_trailing_newline(&mut out, new_string, wend < lines.len());
                replacements += 1;
                i = wend;
            } else {
                out.push_str(lines[i]);
                if i + 1 < lines.len() || trailing_newline {
                    out.push('\n');
                }
                i += 1;
            }
        }
    } else {
        for line in lines.iter().take(start) {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(new_string);
        ensure_trailing_newline(&mut out, new_string, end < lines.len() || trailing_newline);
        replacements = 1;
        for i in end..lines.len() {
            out.push_str(lines[i]);
            if i + 1 < lines.len() || trailing_newline {
                out.push('\n');
            }
        }
    }
    tokio::fs::write(path, &out)
        .await
        .map_err(|e| format!("failed to write {file_path}: {e}"))?;
    Ok(json!({ "edited": file_path, "replacements": replacements, "fuzzy": true }))
}

/// Keep the replacement glued to the following lines without doubling up on
/// newlines when new_string already ends with one.
fn ensure_trailing_newline(out: &mut String, new_string: &str, more_lines_follow: bool) {
    if more_lines_follow && !new_string.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
}

// --- Levenshtein fuzzy matching -------------------------------------------

/// Minimum similarity (1.0 - distance/max_len) for a fuzzy edit to apply.
const FUZZY_THRESHOLD: f64 = 0.9;

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

fn similarity(a: &str, b: &str) -> f64 {
    let (a, b) = (strip_all_ws(a), strip_all_ws(b));
    let max = a.chars().count().max(b.chars().count());
    if max == 0 {
        return 1.0;
    }
    1.0 - (levenshtein(&a, &b) as f64) / (max as f64)
}

/// Remove all whitespace before comparing: indentation and spacing drift are
/// noise for edit matching and shouldn't consume the similarity budget.
fn strip_all_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Slide a window of old_string's line count over the content and return the
/// (start_line, end_line_exclusive, score, text) of the closest match.
fn best_fuzzy_match(content: &str, old_string: &str) -> Option<(usize, usize, f64, String)> {
    let lines: Vec<&str> = content.lines().collect();
    let want: Vec<&str> = old_string.lines().collect();
    if want.is_empty() || lines.is_empty() || want.len() > lines.len() {
        return None;
    }
    let mut best: Option<(usize, f64, String)> = None;
    for start in 0..=(lines.len() - want.len()) {
        let window = lines[start..start + want.len()].join("\n");
        let score = similarity(&window, old_string);
        if best.as_ref().is_none_or(|(_, s, _)| score > *s) {
            best = Some((start, score, window));
        }
    }
    best.map(|(start, score, text)| (start, start + want.len(), score, text))
}

/// Execute a single tool call against the live sessions and return its result
/// text (truncated for the token budget).
pub async fn execute(tc: &ToolCall) -> Result<String, String> {
    let args: Value = serde_json::from_str(&tc.function.arguments).unwrap_or(Value::Null);

    let result: Result<Value, String> = match tc.function.name.as_str() {
        // -- opencode parity --
        "bash" => {
            let command = get_str(&args, "command")?;
            let workdir = get_str_opt(&args, "workdir");
            let timeout = args.get("timeout").and_then(|v| v.as_u64());
            let out = bash_execute_simple(&command, workdir, timeout).await?;
            // Colour escapes and runaway dumps cost tokens on every later turn,
            // exactly like r2 output: filter shell results the same way.
            Ok(Value::String(crate::r2::normalize_bash(&out)))
        }
        "read" => {
            let file_path = get_str(&args, "filePath")?;
            let offset = args.get("offset").and_then(|v| v.as_u64());
            let limit = args.get("limit").and_then(|v| v.as_u64());
            read_path(&file_path, offset, limit).await
        }
        "write" => {
            let file_path = get_str(&args, "filePath")?;
            let content = get_str(&args, "content")?;
            write_path(&file_path, &content).await
        }
        "edit" => {
            let file_path = get_str(&args, "filePath")?;
            let old_string = get_str(&args, "oldString")?;
            let new_string = get_str(&args, "newString")?;
            let replace_all = get_bool_opt(&args, "replaceAll", false);
            edit_path(&file_path, &old_string, &new_string, replace_all).await
        }
        // Analysis is host-owned (it needs a live engine for the target). The
        // model sometimes names the op as the tool; recognise both.
        name if crate::engine::is_op(name) => Err(format!(
            "the `{}` tool is served by the host, not this runtime",
            crate::engine::TOOL_NAME
        )),
        other => Err(format!("unknown tool: {other}")),
    };

    result.map(|v| truncate(&render(v)))
}
