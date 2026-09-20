use serde_json::{json, Value};

use crate::session::R2Session;

/// Typed wrappers over radare2 commands. The heavy lifting (parsing, analysis,
/// disassembly, xrefs, decompilation) all lives inside r2 itself — we only
/// marshal commands and results across the pipe.
pub fn info(s: &R2Session) -> Value {
    s.info.clone()
}

/// Full binary summary (used when a file is opened).
///
/// Lightweight by design: uses `aflc` / `izzc` count commands instead of
/// pulling the full `aflj` / `izzj` arrays. On a large Rust binary (e.g.
/// youki, 7.8 MiB, 113k strings) the full dumps cost tens of megabytes of
/// JSON just to display two numbers — and `open` runs pre-analysis, so the
/// function count is 0 anyway until `analyze` runs.
/// Full arrays are fetched explicitly by `functions` / `strings` after
/// analysis completes.
///
/// Count commands return plain text (not JSON), so `run` wraps them as
/// `Value::String`; parse generously and fall back to 0.
fn parse_count(v: Result<Value, String>) -> usize {
    match v {
        Ok(Value::Number(n)) => n.as_u64().unwrap_or(0) as usize,
        Ok(Value::String(s)) => s.trim().parse::<usize>().unwrap_or(0),
        _ => 0,
    }
}

pub fn function_count(s: &R2Session) -> usize {
    // `aflc` prints the function count; fall back to `aflj` length if the
    // count command is unavailable on an older r2.
    let n = parse_count(s.run("aflc"));
    if n > 0 {
        return n;
    }
    functions(s)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0)
}

pub fn string_count(s: &R2Session) -> usize {
    // `izzc` prints the string count without dumping 100k+ entries.
    let n = parse_count(s.run("izzc"));
    if n > 0 {
        return n;
    }
    strings(s)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0)
}

pub fn summary(s: &R2Session) -> Value {
    json!({
        "path": s.path.to_string_lossy(),
        "info": s.info,
        "function_count": function_count(s),
        "string_count": string_count(s),
    })
}

/// `aflj` — all analyzed functions.
pub fn functions(s: &R2Session) -> Result<Value, String> {
    s.run("aflj")
}

/// `afij @ addr` — info about the function containing `addr`.
pub fn function_at(s: &R2Session, addr: u64) -> Result<Value, String> {
    s.run(&format!("afij @ {addr:#x}"))
}

/// `pdj <count> @ addr` — disassemble `count` instructions at `addr`.
pub fn disassemble(s: &R2Session, addr: u64, count: u64) -> Result<Value, String> {
    s.run(&format!("pdj {count} @ {addr:#x}"))
}

/// `pdfj @ addr` — full disassembly of the function containing `addr`.
pub fn function_disasm(s: &R2Session, addr: u64) -> Result<Value, String> {
    s.run(&format!("pdfj @ {addr:#x}"))
}

/// `agfj @ addr` — JSON control-flow graph (basic blocks with per-block
/// disassembly, plus each block's `jump`/`fail` edges) for the function
/// containing `addr`. Rendered as an interactive graph in the UI.
pub fn function_graph(s: &R2Session, addr: u64) -> Result<Value, String> {
    s.run(&format!("agfj @ {addr:#x}"))
}

/// `izzj` — all strings referenced in the binary.
pub fn strings(s: &R2Session) -> Result<Value, String> {
    s.run("izzj")
}

/// `iij` — imported symbols.
pub fn imports(s: &R2Session) -> Result<Value, String> {
    s.run("iij")
}

/// `axtj @ addr` — references pointing to `addr`.
pub fn xrefs_to(s: &R2Session, addr: u64) -> Result<Value, String> {
    s.run(&format!("axtj @ {addr:#x}"))
}

/// `pdgj @ addr` — Ghidra p-code decompilation via r2ghidra (if installed).
pub fn decompile(s: &R2Session, addr: u64) -> Result<Value, String> {
    s.run(&format!("pdgj @ {addr:#x}"))
}

/// Escape hatch: pass any raw r2 command through to the live session.
pub fn raw(s: &R2Session, cmd: &str) -> Result<Value, String> {
    s.run(cmd)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::session::R2Session;

    fn r2() -> bool {
        std::process::Command::new("r2")
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn every_wrapper_talks_to_a_live_session() {
        if !r2() {
            eprintln!("skipping: radare2 not on PATH");
            return;
        }
        let s = R2Session::open("/bin/true").expect("session");
        assert!(info(&s).is_object());
        // summary counts zero functions pre-analysis but must not error.
        let sum = summary(&s);
        assert!(sum.is_object());
        assert!(functions(&s).is_ok());
        assert!(function_at(&s, 0x401000).is_ok());
        assert!(disassemble(&s, 0x401000, 4).is_ok());
        assert!(strings(&s).is_ok());
        assert!(imports(&s).is_ok());
        assert!(xrefs_to(&s, 0x401000).is_ok());
        // decompile needs r2ghidra; accept either outcome, never a hang.
        let _ = decompile(&s, 0x401000);
        assert!(raw(&s, "f").is_ok());
        // function_disasm/graph need an analyzed function; run aa first.
        s.analyze().ok();
        s.analyze().ok();
        let _ = function_disasm(&s, 0x401000);
        let _ = function_graph(&s, 0x401000);
    }
}
