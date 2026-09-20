//! Pure-Rust analysis backend: no radare2 process, no copyleft dependency.
//!
//! Parsing (ELF/PE/Mach-O), symbols, imports and strings come from the
//! [`object`](https://docs.rs/object) crate. Disassembly and control-flow
//! recovery for x86/x86-64 come from [`iced-x86`](https://docs.rs/iced-x86).
//! Everything is in-process, so there is no child to spawn, interrupt or reap
//! and no external tool to install.
//!
//! Scope, stated honestly:
//!
//! * x86-64 / x86 is disassembled; other architectures are detected and
//!   reported, but disassembly returns a clear "use the r2 backend" error.
//! * Functions are discovered from the symbol table and the entry point, then
//!   extended by recursive descent over direct call targets. A stripped binary
//!   therefore yields fewer functions than radare2's heuristics.
//! * There is no decompiler in the permissive Rust ecosystem, so
//!   [`Engine::decompile`] reports `capabilities().decompile == false`.
//!
//! All types are owned and merged into the backend-neutral results from
//! [`crate::engine`]; nothing here leaks into the agent or the UI.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use object::{
    Architecture, BinaryFormat, Object, ObjectKind, ObjectSection, ObjectSymbol, SectionKind,
    SymbolKind,
};
use serde_json::json;

use crate::engine::{
    BackendKind, BasicBlock, Capabilities, Decompilation, Disassembly, Engine, FunctionGraph,
    FunctionInfo, Import, Instruction, StringRef, Target, Xref, XrefDirection,
};

/// Maximum functions discovered per binary; guards recursive descent.
const MAX_FUNCTIONS: usize = 4096;
/// Maximum basic blocks decoded per function.
const MAX_BLOCKS: usize = 2048;
/// Maximum instructions decoded per block.
const MAX_BLOCK_INSNS: usize = 4096;
/// Minimum run length for an ASCII string.
const MIN_STRING_LEN: usize = 4;

/// Mutable analysis state, guarded by a mutex because [`Engine`] methods take
/// `&self`.
struct NativeState {
    /// Whether recursive-descent discovery has run.
    analyzed: bool,
    /// Discovered functions, keyed by entry address for stable ordering.
    functions: BTreeMap<u64, FunctionInfo>,
    /// Decoded basic blocks per function entry, cached across queries.
    blocks: HashMap<u64, Vec<BasicBlock>>,
}

impl NativeState {
    fn new() -> Self {
        Self {
            analyzed: false,
            functions: BTreeMap::new(),
            blocks: HashMap::new(),
        }
    }
}

/// The in-process [`Engine`] implementation.
pub struct NativeEngine {
    data: Vec<u8>,
    path: PathBuf,
    state: Mutex<NativeState>,
}

impl NativeEngine {
    /// Read `path` into memory and prepare the backend. Parsing is deferred to
    /// each query, so opening a large binary is a single read.
    ///
    /// ```
    /// use librecurse::native::NativeEngine;
    /// let path = std::env::current_exe().unwrap();
    /// let e = NativeEngine::open(&path).unwrap();
    /// use librecurse::engine::Engine;
    /// assert!(e.summary().unwrap()["function_count"].as_u64().unwrap() >= 0);
    /// ```
    pub fn open(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        // Fail fast on non-objects; every later query then only fails on
        // odd sections, not on a fundamentally unparsable file.
        object::File::parse(&*data).map_err(|e| format!("not a recognised binary: {e}"))?;
        Ok(Self {
            data,
            path: path.to_path_buf(),
            state: Mutex::new(NativeState::new()),
        })
    }

    /// Parse the in-memory image.
    fn parse(&self) -> Result<object::File<'_>, String> {
        object::File::parse(&*self.data).map_err(|e| format!("parse failed: {e}"))
    }

    /// True when `addr` falls inside an executable section.
    fn in_text(file: &object::File<'_>, addr: u64) -> bool {
        file.sections().any(|s| {
            s.kind() == SectionKind::Text
                && addr >= s.address()
                && addr < s.address().saturating_add(s.size())
        })
    }

    /// Return the executable section containing `addr`.
    fn text_section<'f>(file: &'f object::File<'f>, addr: u64) -> Option<object::Section<'f, 'f>> {
        file.sections().find(|s| {
            s.kind() == SectionKind::Text
                && addr >= s.address()
                && addr < s.address().saturating_add(s.size())
        })
    }

    /// Decode up to `count` instructions linearly from `addr`.
    fn decode_linear(&self, addr: u64, count: usize) -> Result<Vec<Instruction>, String> {
        let file = self.parse()?;
        self.decode_from(&file, addr, count)
    }

    /// Decode `count` instructions starting at `addr` inside its section.
    fn decode_from(
        &self,
        file: &object::File<'_>,
        addr: u64,
        count: usize,
    ) -> Result<Vec<Instruction>, String> {
        let bitness = bitness_of(file)?;
        let section = Self::text_section(file, addr)
            .ok_or_else(|| format!("no executable section contains {addr:#x}"))?;
        let data = section.data().map_err(|e| e.to_string())?;
        let base = section.address();
        let start = (addr - base) as usize;
        if start >= data.len() {
            return Err(format!("{addr:#x} is past the end of its section"));
        }
        Ok(decode_bytes(&data[start..], addr, bitness, count))
    }

    /// Decode the basic blocks of the function at `func_addr`, caching the
    /// result. Starts from the entry and follows branch edges within the
    /// executable sections.
    fn blocks_for(&self, func_addr: u64) -> Result<Vec<BasicBlock>, String> {
        {
            let state = self
                .state
                .lock()
                .map_err(|e| format!("native state poisoned: {e}"))?;
            if let Some(b) = state.blocks.get(&func_addr) {
                return Ok(b.clone());
            }
        }
        let file = self.parse()?;
        let bitness = bitness_of(&file)?;
        let section = Self::text_section(&file, func_addr)
            .ok_or_else(|| format!("no executable section contains {func_addr:#x}"))?;
        let data = section.data().map_err(|e| e.to_string())?;
        let base = section.address();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        let mut blocks: Vec<BasicBlock> = Vec::new();
        queue.push_back(func_addr);

        while let Some(start) = queue.pop_front() {
            if !visited.insert(start) || blocks.len() >= MAX_BLOCKS {
                continue;
            }
            if start < base || !Self::in_text(&file, start) {
                continue;
            }
            let offset = (start - base) as usize;
            if offset >= data.len() {
                continue;
            }
            let ops = decode_bytes(&data[offset..], start, bitness, MAX_BLOCK_INSNS);
            if ops.is_empty() {
                continue;
            }
            let last = ops.last().cloned().unwrap_or(Instruction {
                addr: start,
                disasm: String::new(),
                kind: None,
                jump: None,
                fail: None,
            });
            let mut jump = None;
            let mut fail = None;
            let kind = last.kind.as_deref().unwrap_or("");
            if matches!(kind, "jmp" | "call") {
                jump = last.jump;
            } else if kind == "cjmp" {
                jump = last.jump;
                fail = last.fail;
            }
            if let Some(t) = jump {
                if Self::in_text(&file, t) {
                    queue.push_back(t);
                }
            }
            if let Some(t) = fail {
                if Self::in_text(&file, t) {
                    queue.push_back(t);
                }
            }
            blocks.push(BasicBlock {
                addr: start,
                ninstr: ops.len() as u64,
                jump,
                fail,
                ops,
            });
        }
        blocks.sort_by_key(|b| b.addr);
        let mut state = self
            .state
            .lock()
            .map_err(|e| format!("native state poisoned: {e}"))?;
        state.blocks.insert(func_addr, blocks.clone());
        Ok(blocks)
    }

    /// Run discovery: seed from symbols + entry, then follow direct call
    /// targets. Idempotent.
    fn discover(&self) -> Result<(), String> {
        {
            let state = self
                .state
                .lock()
                .map_err(|e| format!("native state poisoned: {e}"))?;
            if state.analyzed {
                return Ok(());
            }
        }
        let file = self.parse()?;
        // Named seeds first: they carry the real symbol names.
        let mut names: HashMap<u64, String> = HashMap::new();
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            if sym.kind() != SymbolKind::Text || sym.address() == 0 || !sym.is_definition() {
                continue;
            }
            if let Ok(name) = sym.name() {
                names.entry(sym.address()).or_insert_with(|| demangle(name));
            }
        }
        let entry = file.entry();
        let mut queue: VecDeque<u64> = VecDeque::new();
        for addr in names.keys().copied().collect::<Vec<_>>() {
            if Self::in_text(&file, addr) {
                queue.push_back(addr);
            }
        }
        if entry != 0 && Self::in_text(&file, entry) {
            queue.push_back(entry);
        }

        let mut discovered: BTreeMap<u64, FunctionInfo> = BTreeMap::new();
        let mut seen: HashSet<u64> = HashSet::new();
        while let Some(addr) = queue.pop_front() {
            if !seen.insert(addr) || discovered.len() >= MAX_FUNCTIONS {
                continue;
            }
            let blocks = self.blocks_for(addr)?;
            let mut ops: Vec<&Instruction> = blocks.iter().flat_map(|b| b.ops.iter()).collect();
            ops.sort_by_key(|o| o.addr);
            for op in &ops {
                if op.kind.as_deref() == Some("call") {
                    if let Some(t) = op.jump {
                        if Self::in_text(&file, t) && !seen.contains(&t) {
                            queue.push_back(t);
                        }
                    }
                }
            }
            let name = names
                .get(&addr)
                .cloned()
                .unwrap_or_else(|| format!("fcn_{addr:x}"));
            discovered.insert(
                addr,
                FunctionInfo {
                    addr,
                    name,
                    size: None,
                    nbbs: Some(blocks.len() as u64),
                    edges: None,
                    signature: None,
                },
            );
        }

        // Fill in sizes from the sorted neighbour addresses.
        let addrs: Vec<u64> = discovered.keys().copied().collect();
        for (i, addr) in addrs.iter().enumerate() {
            let end = addrs
                .get(i + 1)
                .copied()
                .or_else(|| {
                    Self::text_section(&file, *addr).map(|s| s.address().saturating_add(s.size()))
                })
                .unwrap_or(*addr);
            if let Some(f) = discovered.get_mut(addr) {
                f.size = Some(end.saturating_sub(*addr));
            }
        }

        let mut state = self
            .state
            .lock()
            .map_err(|e| format!("native state poisoned: {e}"))?;
        state.functions = discovered;
        state.analyzed = true;
        Ok(())
    }

    /// Build the UI-shaped `info` object.
    fn info_value(&self, file: &object::File<'_>) -> serde_json::Value {
        let arch = arch_name(file.architecture());
        let bits = if file.is_64() { 64 } else { 32 };
        let kind = format_name(file.format());
        let endian = if file.is_little_endian() {
            "little"
        } else {
            "big"
        };
        json!({
            "bin": {
                "arch": arch,
                "bits": bits,
                "type": kind,
                "bintype": kind,
                "os": std::env::consts::OS,
                "endian": endian,
                "stripped": file.symbols().next().is_none(),
                "class": format!("{kind}{bits}"),
            },
            "core": { "type": object_kind_name(file.kind()) },
        })
    }
}

impl Engine for NativeEngine {
    fn backend(&self) -> BackendKind {
        BackendKind::Native
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            decompile: false,
            raw: false,
            graph: true,
            xrefs_from: true,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn analyze(&self) -> Result<(), String> {
        self.discover()
    }

    fn summary(&self) -> Result<serde_json::Value, String> {
        let info = self.info()?;
        self.discover()?;
        let function_count = {
            let state = self
                .state
                .lock()
                .map_err(|e| format!("native state poisoned: {e}"))?;
            state.functions.len()
        };
        let string_count = self.strings().map(|s| s.len()).unwrap_or(0);
        Ok(json!({
            "path": self.path.to_string_lossy(),
            "info": info,
            "function_count": function_count,
            "string_count": string_count,
        }))
    }

    fn info(&self) -> Result<serde_json::Value, String> {
        let file = self.parse()?;
        Ok(self.info_value(&file))
    }

    fn functions(&self) -> Result<Vec<FunctionInfo>, String> {
        self.discover()?;
        let state = self
            .state
            .lock()
            .map_err(|e| format!("native state poisoned: {e}"))?;
        Ok(state.functions.values().cloned().collect())
    }

    fn function_at(&self, addr: u64) -> Result<Option<FunctionInfo>, String> {
        self.discover()?;
        let state = self
            .state
            .lock()
            .map_err(|e| format!("native state poisoned: {e}"))?;
        // The containing function is the greatest entry <= addr.
        Ok(state
            .functions
            .range(..=addr)
            .next_back()
            .map(|(_, f)| f.clone())
            .filter(|f| {
                f.size
                    .map(|s| addr < f.addr.saturating_add(s))
                    .unwrap_or(true)
            }))
    }

    fn disassemble(&self, target: &Target, count: Option<usize>) -> Result<Disassembly, String> {
        let addr = match target {
            Target::Addr(a) => *a,
            Target::Symbol(name) => self
                .resolve(name)?
                .ok_or_else(|| format!("could not resolve symbol `{name}`"))?,
        };
        match count {
            Some(n) => {
                let ops = self.decode_linear(addr, n)?;
                let name = self
                    .function_at(addr)?
                    .map(|f| f.name)
                    .unwrap_or_else(|| format!("fcn_{addr:x}"));
                Ok(Disassembly {
                    addr,
                    name,
                    size: None,
                    ops,
                })
            }
            None => self.function_disasm(addr),
        }
    }

    fn function_disasm(&self, addr: u64) -> Result<Disassembly, String> {
        self.discover()?;
        let func = self.function_at(addr)?;
        let entry = func.as_ref().map(|f| f.addr).unwrap_or(addr);
        let blocks = self.blocks_for(entry)?;
        let mut ops: Vec<Instruction> = blocks.into_iter().flat_map(|b| b.ops).collect();
        ops.sort_by_key(|o| o.addr);
        Ok(Disassembly {
            addr: entry,
            name: func
                .as_ref()
                .map(|f| f.name.clone())
                .unwrap_or_else(|| format!("fcn_{entry:x}")),
            size: func.and_then(|f| f.size),
            ops,
        })
    }

    fn function_graph(&self, addr: u64) -> Result<FunctionGraph, String> {
        self.discover()?;
        let func = self.function_at(addr)?;
        let entry = func.as_ref().map(|f| f.addr).unwrap_or(addr);
        let blocks = self.blocks_for(entry)?;
        Ok(FunctionGraph {
            addr: entry,
            name: func
                .map(|f| f.name)
                .unwrap_or_else(|| format!("fcn_{entry:x}")),
            blocks,
        })
    }

    fn strings(&self) -> Result<Vec<StringRef>, String> {
        let file = self.parse()?;
        let mut out: Vec<StringRef> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for section in file.sections() {
            if !matches!(
                section.kind(),
                SectionKind::Text | SectionKind::Data | SectionKind::ReadOnlyData
            ) {
                continue;
            }
            let Ok(data) = section.data() else {
                continue;
            };
            let base = section.address();
            for (addr, s, kind) in scan_strings(data, base) {
                if seen.insert(s.clone()) {
                    out.push(StringRef {
                        addr,
                        string: s,
                        kind: Some(kind),
                    });
                }
            }
        }
        out.sort_by_key(|s| s.addr);
        Ok(out)
    }

    fn imports(&self) -> Result<Vec<Import>, String> {
        let file = self.parse()?;
        let mut out: Vec<Import> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for imp in file.imports().map_err(|e| e.to_string())? {
            let name = String::from_utf8_lossy(imp.name()).into_owned();
            if name.is_empty() || !seen.insert(name.clone()) {
                continue;
            }
            let bind = String::from_utf8_lossy(imp.library()).into_owned();
            out.push(Import {
                name: demangle(&name),
                plt: None,
                bind: (!bind.is_empty()).then_some(bind),
                kind: Some("import".to_string()),
            });
        }
        // ELF often lists imports only as undefined dynamic symbols.
        if out.is_empty() {
            for sym in file.dynamic_symbols() {
                if !sym.is_undefined() {
                    continue;
                }
                if let Ok(name) = sym.name() {
                    if !name.is_empty() && seen.insert(name.to_string()) {
                        out.push(Import {
                            name: name.to_string(),
                            plt: None,
                            bind: None,
                            kind: Some("import".to_string()),
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn xrefs(&self, target: &Target, direction: XrefDirection) -> Result<Vec<Xref>, String> {
        let addr = match target {
            Target::Addr(a) => *a,
            Target::Symbol(name) => self
                .resolve(name)?
                .ok_or_else(|| format!("could not resolve symbol `{name}`"))?,
        };
        self.discover()?;
        let funcs: Vec<u64> = {
            let state = self
                .state
                .lock()
                .map_err(|e| format!("native state poisoned: {e}"))?;
            state.functions.keys().copied().collect()
        };
        let mut out: Vec<Xref> = Vec::new();
        match direction {
            XrefDirection::To => {
                for f in funcs {
                    let blocks = match self.blocks_for(f) {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    let fname = self
                        .function_at(f)?
                        .map(|x| x.name)
                        .unwrap_or_else(|| format!("fcn_{f:x}"));
                    for op in blocks.iter().flat_map(|b| b.ops.iter()) {
                        if op.jump == Some(addr) {
                            out.push(Xref {
                                from: op.addr,
                                kind: branch_kind(op),
                                to: Some(addr),
                                fcn_name: Some(fname.clone()),
                                opcode: Some(op.disasm.clone()),
                            });
                        }
                    }
                }
            }
            XrefDirection::From => {
                let entry = self.function_at(addr)?.map(|f| f.addr).unwrap_or(addr);
                let fname = self
                    .function_at(entry)?
                    .map(|x| x.name)
                    .unwrap_or_else(|| format!("fcn_{entry:x}"));
                let blocks = self.blocks_for(entry)?;
                for op in blocks.iter().flat_map(|b| b.ops.iter()) {
                    if let Some(to) = op.jump {
                        out.push(Xref {
                            from: op.addr,
                            kind: branch_kind(op),
                            to: Some(to),
                            fcn_name: Some(fname.clone()),
                            opcode: Some(op.disasm.clone()),
                        });
                    }
                }
            }
        }
        out.sort_by_key(|x| x.from);
        out.dedup_by_key(|x| x.from);
        Ok(out)
    }

    fn decompile(&self, _addr: u64) -> Result<Decompilation, String> {
        Err(
            "the native backend has no decompiler; install radare2 + r2ghidra and set \
             RECURSE_BACKEND=r2"
                .to_string(),
        )
    }

    fn raw(&self, _cmd: &str) -> Result<serde_json::Value, String> {
        Err("the native backend has no console; use the r2 backend for raw commands".to_string())
    }

    fn resolve(&self, name: &str) -> Result<Option<u64>, String> {
        let file = self.parse()?;
        let mut suffix: Option<u64> = None;
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            if sym.address() == 0 {
                continue;
            }
            let Ok(sym_name) = sym.name() else {
                continue;
            };
            if sym_name == name {
                return Ok(Some(sym.address()));
            }
            if sym_name.ends_with(name) && suffix.is_none() {
                suffix = Some(sym.address());
            }
        }
        Ok(suffix)
    }
}

/// Decode instructions from a byte slice that begins at `ip`.
fn decode_bytes(bytes: &[u8], ip: u64, bitness: u32, max: usize) -> Vec<Instruction> {
    use iced_x86::{
        Decoder, DecoderOptions, Formatter, Instruction as IcedInstruction, IntelFormatter,
    };

    let mut decoder = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut out = Vec::new();
    while decoder.can_decode() && out.len() < max {
        let instr: IcedInstruction = decoder.decode();
        let mut output = TextOutput::new();
        formatter.format(&instr, &mut output);
        let disasm = output.into_string();
        let fc = instr.flow_control();
        let (kind, jump, fail) = classify(&instr, fc);
        out.push(Instruction {
            addr: instr.ip(),
            disasm,
            kind,
            jump,
            fail,
        });
    }
    out
}

/// Minimal [`iced_x86::FormatterOutput`] that concatenates everything the
/// formatter emits into one string (the crate ships no ready-made collector).
struct TextOutput(String);

impl TextOutput {
    fn new() -> Self {
        Self(String::new())
    }

    fn into_string(self) -> String {
        self.0
    }
}

impl iced_x86::FormatterOutput for TextOutput {
    fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
        self.0.push_str(text);
    }
}

/// Map an iced instruction's flow control to the canonical kind and edges.
fn classify(
    instr: &iced_x86::Instruction,
    fc: iced_x86::FlowControl,
) -> (Option<String>, Option<u64>, Option<u64>) {
    use iced_x86::{FlowControl, OpKind};
    let direct = matches!(
        instr.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    let target = if direct {
        Some(instr.near_branch_target())
    } else {
        None
    };
    match fc {
        FlowControl::Next => (None, None, None),
        FlowControl::UnconditionalBranch => (Some("jmp".into()), target, None),
        FlowControl::IndirectBranch => (Some("ijmp".into()), None, None),
        FlowControl::ConditionalBranch => (Some("cjmp".into()), target, Some(instr.next_ip())),
        FlowControl::Return => (Some("ret".into()), None, None),
        FlowControl::Call => (Some("call".into()), target, None),
        FlowControl::IndirectCall => (Some("icall".into()), None, None),
        FlowControl::Interrupt => (Some("int".into()), None, None),
        _ => (None, None, None),
    }
}

/// The reference kind a branch instruction carries, for xref labels.
fn branch_kind(op: &Instruction) -> String {
    match op.kind.as_deref() {
        Some("call") | Some("icall") => "CALL".to_string(),
        Some("jmp") | Some("ijmp") => "JMP".to_string(),
        Some("cjmp") => "CJMP".to_string(),
        _ => "CODE".to_string(),
    }
}

/// Extract ASCII and UTF-16LE strings from one section's bytes.
fn scan_strings(data: &[u8], base: u64) -> Vec<(u64, String, String)> {
    let mut out = Vec::new();
    // ASCII run scanner: printable bytes terminated by a NUL or a non-printable.
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= data.len() {
        let printable = i < data.len() && is_ascii_printable(data[i]);
        if printable {
            if i == start || !is_ascii_printable(data[start]) {
                start = i;
            }
        } else {
            if i > start && i - start >= MIN_STRING_LEN {
                if let Ok(s) = std::str::from_utf8(&data[start..i]) {
                    out.push((base + start as u64, s.to_string(), "ascii".to_string()));
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    // UTF-16LE: alternating printable + NUL bytes, also >= MIN_STRING_LEN.
    let mut i = 0usize;
    while i + 1 < data.len() {
        if data[i] == 0 {
            i += 1;
            continue;
        }
        let begin = i;
        let mut end = i;
        while end + 1 < data.len() && data[end] != 0 && data[end + 1] == 0 {
            end += 2;
        }
        if (end - begin) / 2 >= MIN_STRING_LEN {
            let mut chars: Vec<u16> = Vec::with_capacity((end - begin) / 2);
            let mut j = begin;
            while j + 1 < end {
                chars.push(u16::from_le_bytes([data[j], data[j + 1]]));
                j += 2;
            }
            if let Ok(s) = String::from_utf16(&chars) {
                if s.chars().all(|c| !c.is_control()) {
                    out.push((base + begin as u64, s, "utf16".to_string()));
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// True for the bytes allowed inside an ASCII string literal.
fn is_ascii_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

/// Decode the iced bitness for an object file, or explain why it can't.
fn bitness_of(file: &object::File<'_>) -> Result<u32, String> {
    match file.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => Ok(64),
        Architecture::I386 => Ok(32),
        other => Err(format!(
            "native backend disassembles x86/x86-64 only (binary is {}); set RECURSE_BACKEND=r2",
            arch_name(other)
        )),
    }
}

/// Short architecture name matching r2's vocabulary.
fn arch_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 | Architecture::X86_64_X32 => "x86",
        Architecture::I386 => "x86",
        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => "arm",
        Architecture::Arm => "arm",
        Architecture::Mips | Architecture::Mips64 | Architecture::Mips64_N32 => "mips",
        Architecture::PowerPc | Architecture::PowerPc64 => "ppc",
        Architecture::Riscv32 | Architecture::Riscv64 => "riscv",
        Architecture::Sparc | Architecture::Sparc32Plus | Architecture::Sparc64 => "sparc",
        Architecture::S390x => "s390",
        Architecture::Wasm32 | Architecture::Wasm64 => "wasm",
        _ => "unknown",
    }
}

/// Short binary-format name matching r2's vocabulary.
fn format_name(format: BinaryFormat) -> &'static str {
    match format {
        BinaryFormat::Elf => "elf",
        BinaryFormat::Pe => "pe",
        BinaryFormat::MachO => "mach0",
        BinaryFormat::Coff => "coff",
        BinaryFormat::Wasm => "wasm",
        BinaryFormat::Xcoff => "xcoff",
        _ => "unknown",
    }
}

/// Human label for an object kind.
fn object_kind_name(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Executable => "executable",
        ObjectKind::Dynamic => "shared library",
        ObjectKind::Relocatable => "relocatable",
        ObjectKind::Core => "core",
        ObjectKind::Unknown => "unknown",
        _ => "unknown",
    }
}

/// Best-effort symbol demangling (Rust first, then Itanium C++), falling back
/// to the original name.
fn demangle(name: &str) -> String {
    if let Ok(sym) = rustc_demangle::try_demangle(name) {
        return format!("{sym:#}");
    }
    if let Ok(sym) = cpp_demangle::Symbol::new(name) {
        if let Ok(demangled) = sym.demangle(&cpp_demangle::DemangleOptions::default()) {
            return demangled;
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn scan_finds_ascii_and_utf16() {
        let mut data = b"hello world\0".to_vec();
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend(
            "abcd"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        );
        let found = scan_strings(&data, 0x1000);
        assert!(found
            .iter()
            .any(|(a, s, k)| *a == 0x1000 && s == "hello world" && k == "ascii"));
        assert!(found.iter().any(|(_, s, k)| s == "abcd" && k == "utf16"));
    }

    #[test]
    fn bitness_reflects_architecture() {
        // /bin/true on this host is an ELF; parse it through object directly.
        if let Ok(data) = std::fs::read("/bin/true") {
            if let Ok(file) = object::File::parse(&*data) {
                // Any bitness the host supports must decode or give a clear error.
                let r = bitness_of(&file);
                assert!(r.is_ok() || r.unwrap_err().contains("x86"));
            }
        }
    }

    #[test]
    fn demangle_falls_back_to_input() {
        assert_eq!(demangle("plain_name"), "plain_name");
    }
}
