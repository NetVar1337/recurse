//! WebAssembly module decoding.
//!
//! WebAssembly is a structured, stack-based bytecode. This engine parses the
//! binary with `wasmparser` (imports, data segments, function count) and renders
//! function bodies to the canonical WebAssembly text form with `wasmprinter`,
//! exposing them through the same [`Engine`] surface as native code: functions
//! are wasm functions, "instructions" are text-format operators, imports and
//! data-segment strings are reported directly.
//!
//! It is intentionally read-only and has no decompiler or console; its
//! capabilities advertise that so the agent and UI never offer them.

use std::path::{Path, PathBuf};

use serde_json::json;
use wasmparser::{Parser, Payload};

use crate::engine::{
    BackendKind, Capabilities, Decompilation, Disassembly, Engine, FunctionGraph, FunctionInfo,
    Import, Instruction, StringRef, Target, Xref, XrefDirection,
};

/// Synthetic address of the first instruction of a function: each function owns
/// a `ADDR_STRIDE`-wide band so per-function addresses never collide.
const ADDR_STRIDE: u64 = 1_000_000;

/// A decoded WebAssembly module.
struct Module {
    functions: Vec<WasmFunction>,
    imports: Vec<Import>,
    strings: Vec<StringRef>,
    stripped: bool,
}

struct WasmFunction {
    index: u64,
    name: String,
    ops: Vec<Instruction>,
}

/// The in-process WebAssembly [`Engine`].
pub struct WasmEngine {
    path: PathBuf,
    module: Module,
}

impl WasmEngine {
    /// Parse a `.wasm` module. Fails fast when the header or sections are
    /// malformed.
    ///
    /// ```no_run
    /// use librecurse::native::wasm::WasmEngine;
    /// use librecurse::engine::Engine;
    /// let e = WasmEngine::open(std::path::Path::new("module.wasm")).unwrap();
    /// assert!(e.summary().unwrap()["function_count"].as_u64().unwrap() > 0);
    /// ```
    pub fn open(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let module = parse(&bytes)?;
        Ok(Self {
            path: path.to_path_buf(),
            module,
        })
    }

    /// True when `bytes` starts with the WebAssembly magic.
    ///
    /// ```
    /// use librecurse::native::wasm::is_wasm;
    /// assert!(is_wasm(b"\0asm\x01\0\0\0"));
    /// assert!(!is_wasm(b"\x7fELF"));
    /// ```
    pub fn matches(bytes: &[u8]) -> bool {
        is_wasm(bytes)
    }

    fn function(&self, addr: u64) -> Option<&WasmFunction> {
        self.module.functions.iter().find(|f| f.index == addr)
    }
}

/// The WebAssembly magic (`\0asm`).
pub fn is_wasm(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\0asm")
}

impl Engine for WasmEngine {
    fn backend(&self) -> BackendKind {
        BackendKind::Native
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            decompile: false,
            raw: false,
            graph: false,
            xrefs_from: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn analyze(&self) -> Result<(), String> {
        Ok(())
    }

    fn summary(&self) -> Result<serde_json::Value, String> {
        Ok(json!({
            "path": self.path.to_string_lossy(),
            "info": self.info()?,
            "function_count": self.module.functions.len(),
            "string_count": self.module.strings.len(),
        }))
    }

    fn info(&self) -> Result<serde_json::Value, String> {
        Ok(json!({
            "bin": {
                "arch": "wasm",
                "bits": 32,
                "type": "wasm",
                "bintype": "wasm",
                "os": "wasm",
                "endian": "little",
                "stripped": self.module.stripped,
                "class": "wasm",
            },
            "core": { "type": "webassembly module" },
        }))
    }

    fn functions(&self) -> Result<Vec<FunctionInfo>, String> {
        Ok(self
            .module
            .functions
            .iter()
            .map(|f| FunctionInfo {
                addr: f.index,
                name: f.name.clone(),
                size: Some(f.ops.len() as u64),
                nbbs: None,
                edges: None,
                signature: None,
            })
            .collect())
    }

    fn function_at(&self, addr: u64) -> Result<Option<FunctionInfo>, String> {
        Ok(self.function(addr).map(|f| FunctionInfo {
            addr: f.index,
            name: f.name.clone(),
            size: Some(f.ops.len() as u64),
            nbbs: None,
            edges: None,
            signature: None,
        }))
    }

    fn disassemble(&self, target: &Target, count: Option<usize>) -> Result<Disassembly, String> {
        let index = match target {
            Target::Addr(a) => *a,
            Target::Symbol(name) => self
                .resolve(name)?
                .ok_or_else(|| format!("could not resolve function `{name}`"))?,
        };
        self.function_disasm_with(index, count)
    }

    fn function_disasm(&self, addr: u64) -> Result<Disassembly, String> {
        self.function_disasm_with(addr, None)
    }

    fn function_graph(&self, _addr: u64) -> Result<FunctionGraph, String> {
        Err("the WebAssembly engine does not build control-flow graphs".to_string())
    }

    fn strings(&self) -> Result<Vec<StringRef>, String> {
        Ok(self.module.strings.clone())
    }

    fn imports(&self) -> Result<Vec<Import>, String> {
        Ok(self.module.imports.clone())
    }

    fn xrefs(&self, _target: &Target, _direction: XrefDirection) -> Result<Vec<Xref>, String> {
        Ok(Vec::new())
    }

    fn decompile(&self, _addr: u64) -> Result<Decompilation, String> {
        Err("the WebAssembly engine has no decompiler".to_string())
    }

    fn raw(&self, _cmd: &str) -> Result<serde_json::Value, String> {
        Err("the WebAssembly engine has no console".to_string())
    }

    fn resolve(&self, name: &str) -> Result<Option<u64>, String> {
        let bare = name.trim_start_matches('$');
        Ok(self
            .module
            .functions
            .iter()
            .find(|f| f.name == name || f.name == bare || f.name == format!("${bare}"))
            .map(|f| f.index))
    }
}

impl WasmEngine {
    fn function_disasm_with(
        &self,
        index: u64,
        count: Option<usize>,
    ) -> Result<Disassembly, String> {
        let f = self
            .function(index)
            .ok_or_else(|| format!("no function at {index}"))?;
        let ops = match count {
            Some(n) => f.ops.iter().take(n).cloned().collect(),
            None => f.ops.clone(),
        };
        Ok(Disassembly {
            addr: f.index,
            name: f.name.clone(),
            size: Some(f.ops.len() as u64),
            ops,
        })
    }
}

/// Parse a WebAssembly module into the canonical model.
fn parse(bytes: &[u8]) -> Result<Module, String> {
    let mut imported_functions = 0usize;
    let mut function_count = 0usize;
    let mut imports: Vec<Import> = Vec::new();
    let mut strings: Vec<StringRef> = Vec::new();
    let mut stripped = true;

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|e| format!("invalid WebAssembly: {e}"))? {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.map_err(|e| e.to_string())?;
                    if matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                        imported_functions += 1;
                    }
                    imports.push(Import {
                        name: format!("{}::{}", import.module, import.name),
                        plt: None,
                        bind: Some(import.module.to_string()),
                        kind: Some("import".to_string()),
                    });
                }
            }
            Payload::FunctionSection(reader) => {
                function_count = reader.count() as usize;
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    let data = data.map_err(|e| e.to_string())?;
                    for (addr, s, kind) in scan_ascii(data.data) {
                        strings.push(StringRef {
                            addr,
                            string: s,
                            kind: Some(kind),
                        });
                    }
                }
            }
            Payload::CustomSection(reader) if reader.name() == "name" => {
                stripped = false;
            }
            _ => {}
        }
    }
    // `FunctionSection` covers only defined functions; the total is that plus
    // imported functions. `function_count` is the defined count here.
    let _ = function_count;

    let wat = print_linear(bytes)?;
    let defined = split_functions(&wat);
    let stripped = stripped && defined.iter().all(|(name, _)| name.is_empty());

    let functions = defined
        .into_iter()
        .enumerate()
        .map(|(i, (name, body))| {
            let index = (imported_functions + i) as u64;
            let name = if name.is_empty() {
                format!("func_{index}")
            } else {
                name
            };
            let ops = body
                .into_iter()
                .enumerate()
                .map(|(j, disasm)| Instruction {
                    addr: index * ADDR_STRIDE + j as u64,
                    disasm,
                    bytes: None,
                    kind: None,
                    jump: None,
                    fail: None,
                    len: 0,
                })
                .collect();
            WasmFunction { index, name, ops }
        })
        .collect();

    Ok(Module {
        functions,
        imports,
        strings,
        stripped,
    })
}

/// Render the module to WebAssembly text in linear (one-operator-per-line)
/// form, which is what the disassembly view expects.
fn print_linear(bytes: &[u8]) -> Result<String, String> {
    struct Sink(String);
    impl wasmprinter::Print for Sink {
        fn write_str(&mut self, s: &str) -> std::io::Result<()> {
            self.0.push_str(s);
            Ok(())
        }
    }
    let mut sink = Sink(String::new());
    let mut config = wasmprinter::Config::new();
    config.fold_instructions(false);
    config
        .print(bytes, &mut sink)
        .map_err(|e| format!("wasm text: {e}"))?;
    Ok(sink.0)
}

/// Split WebAssembly text into `(func ...)` blocks, returning each function's
/// name (empty when unnamed) and its rendered operator lines.
fn split_functions(wat: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut lines = wat.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("(func ") || trimmed.starts_with("(func(")) {
            continue;
        }
        let mut depth = paren_balance(line);
        let mut block = vec![line];
        while depth > 0 {
            match lines.next() {
                Some(next) => {
                    depth += paren_balance(next);
                    block.push(next);
                }
                None => break,
            }
        }
        out.push((function_name(trimmed), function_ops(&block)));
    }
    out
}

/// Net parenthesis balance of a line, ignoring `;;` comments.
fn paren_balance(line: &str) -> i32 {
    let code = line.split(";;").next().unwrap_or(line);
    code.chars().fold(0, |n, c| match c {
        '(' => n + 1,
        ')' => n - 1,
        _ => n,
    })
}

/// The `$name` of a `(func ...)` header, if present.
fn function_name(header: &str) -> String {
    let rest = header.trim_start_matches("(func").trim_start();
    let rest = rest.strip_prefix("(;").map_or(rest, |r| {
        r.split_once(";)")
            .map(|(_, tail)| tail.trim_start())
            .unwrap_or(r)
    });
    if let Some(name) = rest.strip_prefix('$') {
        return format!("${}", name.split_whitespace().next().unwrap_or(""));
    }
    String::new()
}

/// The operator lines of a function block: the body minus the header/closing
/// paren, empty lines, comments, and local declarations.
fn function_ops(block: &[&str]) -> Vec<String> {
    block
        .iter()
        .skip(1)
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with(";;"))
        .filter(|l| !l.starts_with(')'))
        .filter(|l| {
            !["(local", "(type", "(param", "(result", "(export", "(import"]
                .iter()
                .any(|p| l.starts_with(p))
        })
        .map(|l| l.trim_end_matches(')').trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Extract contiguous ASCII runs from a data segment, using the segment's
/// offset as the base address.
fn scan_ascii(data: &[u8]) -> Vec<(u64, String, String)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= data.len() {
        let printable = i < data.len() && (0x20..=0x7e).contains(&data[i]);
        if printable {
            i += 1;
            continue;
        }
        if i.saturating_sub(start) >= 4 {
            if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                out.push((start as u64, s.to_string(), "ascii".to_string()));
            }
        }
        start = i + 1;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn detects_magic() {
        assert!(is_wasm(b"\0asm\x01\0\0\0"));
        assert!(!is_wasm(b"MZ\x90\0"));
        assert!(!is_wasm(b"\x7fELF"));
    }

    #[test]
    fn splits_functions_and_names() {
        let wat = "(module\n  (func $add (param i32 i32) (result i32)\n    local.get 0\n    local.get 1\n    i32.add)\n  (func (;1;) (result i32)\n    i32.const 7))\n";
        let funcs = split_functions(wat);
        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0].0, "$add");
        assert!(funcs[0].1.iter().any(|l| l == "i32.add"), "funcs={funcs:?}");
        assert_eq!(funcs[1].0, "");
    }

    #[test]
    fn scans_ascii_runs() {
        let found = scan_ascii(b"\x00hello world\x00ab\x00");
        assert!(found.iter().any(|(_, s, _)| s == "hello world"));
        assert!(!found.iter().any(|(_, s, _)| s == "ab"));
    }

    #[test]
    fn parses_a_module_with_a_function() {
        // (module (type (func (result i32))) (func (type 0) i32.const 7))
        let bytes: &[u8] = b"\0asm\x01\0\0\0\
            \x01\x05\x01\x60\x00\x01\x7f\
            \x03\x02\x01\x00\
            \x0a\x06\x01\x04\x00\x41\x07\x0b";
        let module = parse(bytes).expect("parse module");
        assert_eq!(module.functions.len(), 1);
        assert!(
            module.functions[0]
                .ops
                .iter()
                .any(|o| o.disasm.contains("i32.const 7")),
            "body decoded: {:?}",
            module.functions[0].ops
        );
    }
}
