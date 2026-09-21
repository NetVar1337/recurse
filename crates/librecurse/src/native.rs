//! Pure-Rust analysis backend: in-process, no external tool, no copyleft
//! dependency.
//!
//! Parsing (ELF/PE/Mach-O) comes from [`object`](https://docs.rs/object).
//! Disassembly and control-flow recovery come from
//! [`capstone`](https://docs.rs/capstone), which covers x86/x86-64, ARM,
//! AArch64, MIPS, PowerPC, RISC-V, SPARC, SystemZ, M68K, BPF and more behind
//! one API. Capstone is BSD-3-Clause, so the whole backend stays permissive.
//!
//! Scope, stated honestly:
//!
//! * Functions are discovered from the symbol table, the entry point, and
//!   direct call targets (recursive descent). A stripped binary therefore
//!   yields fewer functions than a heavier analysis engine would.
//! * Branch targets and fall-through edges are recovered from instruction
//!   details, so the CFG covers reachable code; exotic architectures whose
//!   conditionality we cannot classify exactly are treated as conditional.
//! * There is no decompiler in the permissive ecosystem, so
//!   [`Engine::decompile`] reports `capabilities().decompile == false`.

pub mod wasm;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use capstone::prelude::*;
use capstone::{Endian, InsnGroupType};
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
/// Linear-sweep budget for call-target seeding on stripped binaries. Decoding
/// a whole huge `.text` is bounded so `analyze` stays predictable.
const SWEEP_MAX_INSNS: usize = 1_000_000;
/// Minimum run length for a string.
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
    /// Names + strings for disassembly annotation, built once after discovery.
    labels: Option<Labels>,
    /// Cached string scan (`strings()` and annotation share it).
    strings: Option<Vec<StringRef>>,
}

/// Address indexes used to annotate disassembly with names.
#[derive(Default)]
struct Labels {
    /// address -> best-known name (symbol, imported GOT slot, function).
    names: HashMap<u64, String>,
    /// string vaddr -> text.
    strings: HashMap<u64, String>,
}

impl NativeState {
    fn new() -> Self {
        Self {
            analyzed: false,
            functions: BTreeMap::new(),
            blocks: HashMap::new(),
            labels: None,
            strings: None,
        }
    }
}

/// Build a Capstone disassembler configured for the object file's CPU, mode
/// and endianness. Capstone handles every architecture it supports uniformly,
/// so this is the only place that switches on the architecture.
fn build_capstone(file: &object::File<'_>) -> Result<Capstone, String> {
    let endian = if file.is_little_endian() {
        Endian::Little
    } else {
        Endian::Big
    };
    let built = match file.architecture() {
        Architecture::X86_64 | Architecture::X86_64_X32 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
        Architecture::I386 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),
        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(if is_thumb(file) {
                arch::arm::ArchMode::Thumb
            } else {
                arch::arm::ArchMode::Arm
            })
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::Mips => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::Mips64 | Architecture::Mips64_N32 => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::PowerPc => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode32)
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::PowerPc64 => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::Riscv32 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::Riscv64 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .endian(endian)
            .detail(true)
            .build(),
        Architecture::Sparc | Architecture::Sparc32Plus => Capstone::new()
            .sparc()
            .mode(arch::sparc::ArchMode::Default)
            .detail(true)
            .build(),
        Architecture::Sparc64 => Capstone::new()
            .sparc()
            .mode(arch::sparc::ArchMode::V9)
            .detail(true)
            .build(),
        Architecture::S390x => Capstone::new()
            .sysz()
            .mode(arch::sysz::ArchMode::Default)
            .detail(true)
            .build(),
        Architecture::M68k => Capstone::new()
            .m68k()
            .mode(arch::m68k::ArchMode::M68k000)
            .detail(true)
            .build(),
        Architecture::Bpf => Capstone::new()
            .bpf()
            .mode(arch::bpf::ArchMode::Cbpf)
            .endian(endian)
            .detail(true)
            .build(),
        other => {
            return Err(format!(
                "native backend cannot disassemble {} (unsupported architecture)",
                arch_name(other)
            ))
        }
    };
    built.map_err(|e| format!("capstone initialisation failed: {e}"))
}

/// Best-effort Thumb detection for 32-bit ARM: the low bit of the entry point
/// (and of Thumb function symbols) is set, or Thumb mapping symbols (`$t`)
/// appear in the symbol table. Mixed Arm/Thumb images pick the dominant mode.
fn is_thumb(file: &object::File<'_>) -> bool {
    if file.entry() & 1 == 1 {
        return true;
    }
    file.symbols().chain(file.dynamic_symbols()).any(|s| {
        if let Ok(name) = s.name() {
            if name.starts_with("$t") {
                return true;
            }
        }
        s.kind() == SymbolKind::Text && s.address() & 1 == 1
    })
}

/// 32-bit ARM code addresses carry the Thumb bit in bit 0; clear it before
/// comparing or decoding.
fn code_addr(file: &object::File<'_>, addr: u64) -> u64 {
    if file.architecture() == Architecture::Arm {
        addr & !1
    } else {
        addr
    }
}

/// Open a target, detecting its container format and returning the matching
/// in-process engine. Native object formats (ELF/PE/Mach-O/COFF) go through the
/// [`NativeEngine`]; structured bytecodes route to their own decoders.
///
/// ```no_run
/// use librecurse::native::open;
/// let engine = open(std::path::Path::new("/bin/true")).unwrap();
/// let _ = engine.summary().unwrap();
/// ```
pub fn open(path: &Path) -> Result<Box<dyn Engine>, String> {
    let mut magic = [0u8; 4];
    let read = std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read(&mut f, &mut magic))
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    if read >= 4 && wasm::is_wasm(&magic) {
        return Ok(Box::new(wasm::WasmEngine::open(path)?));
    }
    Ok(Box::new(NativeEngine::open(path)?))
}

/// When `data` is a universal (fat) Mach-O, return the slice for the preferred
/// architecture — x86-64, then x86, else the first — so the object engine can
/// parse it. `None` for thin files (or anything that is not fat Mach-O).
fn macho_slice(data: &[u8]) -> Option<Vec<u8>> {
    use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
    let arches: Vec<(Architecture, u64, u64)> = if let Ok(fat) = MachOFatFile32::parse(data) {
        fat.arches()
            .iter()
            .map(|a| (a.architecture(), arch_word(a.offset()), arch_word(a.size())))
            .collect()
    } else if let Ok(fat) = MachOFatFile64::parse(data) {
        fat.arches()
            .iter()
            .map(|a| (a.architecture(), arch_word(a.offset()), arch_word(a.size())))
            .collect()
    } else {
        return None;
    };
    let (_, offset, size) = arches
        .iter()
        .find(|(a, _, _)| *a == Architecture::X86_64)
        .or_else(|| arches.iter().find(|(a, _, _)| *a == Architecture::I386))
        .or_else(|| arches.first())?;
    let start = *offset as usize;
    let end = start.checked_add(*size as usize)?;
    data.get(start..end).map(<[u8]>::to_vec)
}

/// Widen a fat-arch word (32- or 64-bit) to `u64` without a same-type
/// conversion lint.
fn arch_word<T: Into<u64>>(word: T) -> u64 {
    word.into()
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
    /// use librecurse::engine::Engine;
    /// let path = std::env::current_exe().unwrap();
    /// let e = NativeEngine::open(&path).unwrap();
    /// assert!(e.summary().unwrap()["function_count"].as_u64().unwrap() >= 0);
    /// ```
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        // Universal (fat) Mach-O: analyse one architecture's slice.
        if let Some(slice) = macho_slice(&data) {
            data = slice;
        }
        // Fail fast on non-objects; every later query then only fails on odd
        // sections, not on a fundamentally unparsable file.
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
        let cs = build_capstone(&file)?;
        let addr = code_addr(&file, addr);
        let section = Self::text_section(&file, addr).ok_or_else(|| missing_code(addr))?;
        let data = section.data().map_err(|e| e.to_string())?;
        let offset = (addr - section.address()) as usize;
        if offset >= data.len() {
            return Err(format!("{addr:#x} is past the end of its section"));
        }
        Ok(decode_with(&cs, &data[offset..], addr, count.max(1), false))
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
        let cs = build_capstone(&file)?;
        let blocks = decode_blocks(&file, &cs, func_addr)?;
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
        let cs = build_capstone(&file)?;
        // Imported GOT slots, so PLT stubs and indirect calls can be named.
        let got = import_got_labels(&file);
        // Named seeds first: they carry the real symbol names.
        let mut names: HashMap<u64, String> = HashMap::new();
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            if sym.kind() != SymbolKind::Text || sym.address() == 0 || !sym.is_definition() {
                continue;
            }
            if let Ok(name) = sym.name() {
                let addr = code_addr(&file, sym.address());
                names.entry(addr).or_insert_with(|| shorten_name(name));
            }
        }
        let entry = code_addr(&file, file.entry());
        let mut queue: VecDeque<u64> = VecDeque::new();
        for addr in names.keys().copied().collect::<Vec<_>>() {
            if Self::in_text(&file, addr) {
                queue.push_back(addr);
            }
        }
        if entry != 0 && Self::in_text(&file, entry) {
            queue.push_back(entry);
            // Stripped binaries often expose only `_start`, and they pass
            // `main` to libc as a pointer rather than calling it directly.
            // Recover it from the entry's argument setup (x86/x86-64).
            if let Some(main) = entry_main_seed(&file, &cs, entry) {
                names.entry(main).or_insert_with(|| "main".to_string());
                queue.push_back(main);
            }
        }
        // A linear sweep adds every direct call target as a candidate. This is
        // what finds internal functions when the entry only calls through the
        // PLT (the common stripped-binary case), where recursive descent from
        // symbols alone yields just `_start`.
        for target in sweep_seeds(&file, &cs, SWEEP_MAX_INSNS) {
            queue.push_back(target);
        }

        let mut discovered: BTreeMap<u64, FunctionInfo> = BTreeMap::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut cache: HashMap<u64, Vec<BasicBlock>> = HashMap::new();
        while let Some(addr) = queue.pop_front() {
            if !seen.insert(addr) || discovered.len() >= MAX_FUNCTIONS {
                continue;
            }
            let blocks = decode_blocks(&file, &cs, addr)?;
            for op in blocks.iter().flat_map(|b| b.ops.iter()) {
                if op.kind.as_deref() == Some("call") {
                    if let Some(t) = op.jump {
                        if Self::in_text(&file, t) && !seen.contains(&t) {
                            queue.push_back(t);
                        }
                    }
                }
            }
            let name = names.get(&addr).cloned().unwrap_or_else(|| {
                plt_import_name(&blocks, &got)
                    .map(|imported| format!("imp.{imported}"))
                    .unwrap_or_else(|| format!("fcn_{addr:x}"))
            });
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
            cache.insert(addr, blocks);
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
        state.blocks = cache;
        state.analyzed = true;
        Ok(())
    }

    /// Build the UI-shaped `info` object.
    fn info_value(&self, file: &object::File<'_>) -> serde_json::Value {
        let arch = arch_name(file.architecture());
        let bits = arch_bits(file.architecture()).unwrap_or(0);
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

    /// Build the name/string index once (after discovery).
    fn ensure_labels(&self) -> Result<(), String> {
        {
            let state = self
                .state
                .lock()
                .map_err(|e| format!("native state poisoned: {e}"))?;
            if state.labels.is_some() {
                return Ok(());
            }
        }
        self.discover()?;
        let file = self.parse()?;
        let strings = scan_all_strings(&file);
        let mut names: HashMap<u64, String> = HashMap::new();
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            if sym.address() == 0 {
                continue;
            }
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    names
                        .entry(sym.address())
                        .or_insert_with(|| shorten_name(name));
                }
            }
        }
        for (addr, name) in import_got_labels(&file) {
            names.insert(addr, name);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|e| format!("native state poisoned: {e}"))?;
        // Discovered function names are the friendliest, so they win.
        for f in state.functions.values() {
            names.insert(f.addr, f.name.clone());
        }
        let string_map = strings.iter().map(|s| (s.addr, s.string.clone())).collect();
        state.labels = Some(Labels {
            names,
            strings: string_map,
        });
        state.strings = Some(strings);
        Ok(())
    }

    /// Append `; name` / `; "string"` comments to `ops`, so the model does not
    /// have to cross-reference addresses by hand.
    fn annotate_ops(&self, ops: &mut [Instruction]) {
        if self.ensure_labels().is_err() {
            return;
        }
        let Ok(state) = self.state.lock() else {
            return;
        };
        let Some(labels) = state.labels.as_ref() else {
            return;
        };
        for op in ops.iter_mut() {
            let mut comment: Option<String> = op.jump.and_then(|t| labels.names.get(&t).cloned());
            if comment.is_none() {
                for ea in memory_references(op) {
                    if let Some(name) = labels.names.get(&ea) {
                        comment = Some(name.clone());
                        break;
                    }
                    if let Some(text) = labels.strings.get(&ea) {
                        comment = Some(format!("\"{}\"", truncate_str(text, 48)));
                        break;
                    }
                }
            }
            if let Some(c) = comment {
                op.disasm = format!("{} ; {}", op.disasm, c);
            }
        }
    }
}

/// Decode up to `max` instructions from a byte slice that begins at `ip`.
/// When `stop_at_terminator` is set, decoding stops *after* the first
/// instruction that ends a basic block (jump, conditional jump, return, trap).
///
/// Decoding is batched: Capstone honours a count by decoding that many
/// instructions up front, so asking for the whole cap (4096) just to stop at
/// the first branch wasted most of the work on large binaries. Small batches
/// plus an early return keep the cost proportional to the block length.
fn decode_with(
    cs: &Capstone,
    bytes: &[u8],
    ip: u64,
    max: usize,
    stop_at_terminator: bool,
) -> Vec<Instruction> {
    /// Instructions requested per Capstone call.
    const BATCH: usize = 32;

    let mut out: Vec<Instruction> = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() && out.len() < max {
        let want = BATCH.min(max - out.len());
        let Ok(insns) = cs.disasm_count(&bytes[cursor..], ip + cursor as u64, want) else {
            break;
        };
        if insns.is_empty() {
            break;
        }
        let exhausted = insns.len() < want;
        let mut consumed = 0usize;
        for insn in insns.iter() {
            let (kind, jump, fail) = classify(cs, insn);
            let terminator = matches!(
                kind.as_deref(),
                Some("jmp") | Some("cjmp") | Some("ret") | Some("int")
            );
            consumed += insn.bytes().len();
            out.push(Instruction {
                addr: insn.address(),
                disasm: format_insn(insn),
                bytes: Some(hex_bytes(insn.bytes())),
                kind,
                jump,
                fail,
                len: insn.bytes().len() as u32,
            });
            if (stop_at_terminator && terminator) || out.len() >= max {
                return out;
            }
        }
        cursor += consumed;
        if exhausted {
            break;
        }
    }
    out
}

/// Recover the basic blocks of the function at `func_addr` by following
/// branch and fall-through edges. Pure over the parsed file and Capstone
/// handle, so callers share one handle across many functions.
fn decode_blocks(
    file: &object::File<'_>,
    cs: &Capstone,
    func_addr: u64,
) -> Result<Vec<BasicBlock>, String> {
    let func_addr = code_addr(file, func_addr);
    let section =
        NativeEngine::text_section(file, func_addr).ok_or_else(|| missing_code(func_addr))?;
    let data = section.data().map_err(|e| e.to_string())?;
    let base = section.address();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    let mut blocks: Vec<BasicBlock> = Vec::new();
    queue.push_back(func_addr);

    loop {
        while let Some(start) = queue.pop_front() {
            if !visited.insert(start) || blocks.len() >= MAX_BLOCKS {
                continue;
            }
            if start < base || start >= base.saturating_add(data.len() as u64) {
                continue;
            }
            let offset = (start - base) as usize;
            let mut ops = decode_with(cs, &data[offset..], start, MAX_BLOCK_INSNS, true);
            if ops.is_empty() {
                continue;
            }
            // Follow indirect calls/jumps through data slots to their target,
            // so a tail call or function-pointer dispatch becomes an edge and a
            // cross-reference instead of a dead end.
            for op in ops.iter_mut() {
                if op.jump.is_none() && matches!(op.kind.as_deref(), Some("call") | Some("jmp")) {
                    if let Some(target) = resolve_indirect(file, op) {
                        op.jump = Some(target);
                    }
                }
            }
            let Some(last) = ops.last() else {
                continue;
            };
            let (jump, fail) = match last.kind.as_deref() {
                Some("cjmp") => (last.jump, last.fail),
                _ => (last.jump, None),
            };
            // An indexed-memory jump table is fully described by the one
            // instruction, so it can be resolved immediately.
            let targets = if jump.is_none() && last.kind.as_deref() == Some("jmp") {
                jump_table_targets(file, &ops, last)
            } else {
                Vec::new()
            };
            let successors = jump
                .into_iter()
                .chain(fail)
                .chain(targets.iter().copied())
                .filter(|t| NativeEngine::in_text(file, *t));
            for target in successors {
                queue.push_back(target);
            }
            blocks.push(BasicBlock {
                addr: start,
                ninstr: ops.len() as u64,
                jump,
                fail,
                targets,
                ops,
            });
        }

        // Second pass: a computed `jmp reg` is often its own block, separate
        // from the table setup that precedes it. Search the function's
        // preceding ops for the switch idiom and pull in the case blocks.
        blocks.sort_by_key(|b| b.addr);
        let flat: Vec<Instruction> = blocks.iter().flat_map(|b| b.ops.iter().cloned()).collect();
        let mut discovered = false;
        for block in blocks.iter_mut() {
            if !block.targets.is_empty() {
                continue;
            }
            let Some(last) = block.ops.last() else {
                continue;
            };
            if !(last.kind.as_deref() == Some("jmp") && last.jump.is_none()) {
                continue;
            }
            let window: Vec<Instruction> = flat
                .iter()
                .filter(|o| o.addr <= last.addr)
                .cloned()
                .collect();
            let targets = switch_targets(file, &window);
            if targets.is_empty() {
                continue;
            }
            for target in targets.iter().filter(|t| NativeEngine::in_text(file, **t)) {
                if !visited.contains(target) {
                    queue.push_back(*target);
                    discovered = true;
                }
            }
            block.targets = targets;
        }
        if !discovered {
            break;
        }
    }
    blocks.sort_by_key(|b| b.addr);
    Ok(blocks)
}

/// Decode the executable sections linearly and collect function-entry seeds:
/// every direct call target, plus CET landing pads and classic `push rbp; mov
/// rbp, rsp` prologues. A bounded, cheap complement to recursive descent: it
/// finds functions the call graph alone misses (indirect-only callers, no
/// symbols).
fn sweep_seeds(file: &object::File<'_>, cs: &Capstone, max_insns: usize) -> Vec<u64> {
    let mut out = Vec::new();
    let mut budget = max_insns;
    for section in file.sections() {
        if budget == 0 {
            break;
        }
        if section.kind() != SectionKind::Text {
            continue;
        }
        let Ok(data) = section.data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let ops = decode_with(cs, data, section.address(), budget, false);
        budget = budget.saturating_sub(ops.len().max(1));
        for (i, op) in ops.iter().enumerate() {
            if op.kind.as_deref() == Some("call") {
                if let Some(target) = op.jump {
                    if NativeEngine::in_text(file, target) {
                        out.push(target);
                    }
                }
            }
            let is_entry = op.disasm.starts_with("endbr64")
                || op.disasm.starts_with("endbr32")
                || (op.disasm == "push rbp"
                    && ops
                        .get(i + 1)
                        .is_some_and(|n| n.disasm.starts_with("mov rbp, rsp")));
            if is_entry {
                out.push(op.addr);
            }
        }
    }
    out
}

/// Map every imported GOT slot to its (demangled) name, from dynamic
/// relocations. This is what turns `call qword ptr [rip + 0x2fe2]` into
/// `... ; __libc_start_main`, and lets PLT stubs be named.
fn import_got_labels(file: &object::File<'_>) -> HashMap<u64, String> {
    // Dynamic relocations index `.dynsym` directly (`SymbolIndex(1)` is the
    // first entry yielded by `dynamic_symbols()`), so build index -> name.
    let mut dyn_names: HashMap<usize, String> = HashMap::new();
    for (i, sym) in file.dynamic_symbols().enumerate() {
        if let Ok(name) = sym.name() {
            if !name.is_empty() {
                dyn_names.insert(i + 1, shorten_name(name));
            }
        }
    }
    let mut out = HashMap::new();
    if let Some(iter) = file.dynamic_relocations() {
        for (addr, rel) in iter {
            if let object::RelocationTarget::Symbol(index) = rel.target() {
                if let Some(name) = dyn_names.get(&index.0) {
                    out.insert(addr, name.clone());
                }
            }
        }
    }
    out
}

/// If the first instruction is an indirect jump through a known GOT slot, the
/// block is a PLT stub; return the imported name it forwards to.
fn plt_import_name(blocks: &[BasicBlock], got: &HashMap<u64, String>) -> Option<String> {
    let first = blocks.first()?.ops.first()?;
    if first.kind.as_deref() != Some("jmp") {
        return None;
    }
    memory_references(first)
        .into_iter()
        .find_map(|ea| got.get(&ea).cloned())
}

/// Candidate absolute addresses referenced by an instruction, for annotation:
/// the effective address of a `[rip + disp]` operand, or any bare `0x` operand
/// (non-PIE string addresses). Exact lookups filter out false positives.
fn memory_references(op: &Instruction) -> Vec<u64> {
    let text = &op.disasm;
    if let Some(idx) = text.find("[rip") {
        return rip_displacement(&text[idx..])
            .map(|disp| {
                vec![op
                    .addr
                    .wrapping_add(op.len as u64)
                    .wrapping_add(disp as u64)]
            })
            .unwrap_or_default();
    }
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter_map(|token| token.strip_prefix("0x"))
        .filter_map(|hex| u64::from_str_radix(hex, 16).ok())
        .collect()
}

/// The effective address of a non-indexed memory operand (`[rip + X]` or
/// `[0xADDR]`), or `None` for a register-relative / indexed operand.
fn memory_operand_address(op: &Instruction) -> Option<u64> {
    let text = &op.disasm;
    let start = text.find('[')?;
    let end = text[start..].find(']')? + start;
    let inner = &text[start + 1..end];
    if inner.contains('*') {
        return None;
    }
    if inner.contains("rip") {
        let disp = rip_displacement(inner)?;
        return Some(
            op.addr
                .wrapping_add(op.len as u64)
                .wrapping_add(disp as u64),
        );
    }
    let hex = inner.trim().strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

/// Resolve an indirect call/jump through a data slot: read the pointer stored
/// at the operand address and return it when it points into executable code —
/// a tail call through a GOT slot, an ifunc stub, or a function-pointer table.
fn resolve_indirect(file: &object::File<'_>, op: &Instruction) -> Option<u64> {
    let slot = memory_operand_address(op)?;
    if !in_data(file, slot) {
        return None;
    }
    let (data, base) = section_at(file, slot)?;
    let off = (slot - base) as usize;
    if off + 8 > data.len() {
        return None;
    }
    let value = u64::from_le_bytes(data[off..off + 8].try_into().ok()?);
    NativeEngine::in_text(file, value).then_some(value)
}

/// Find the section containing `addr`, returning its bytes and base address.
fn section_at<'f>(file: &'f object::File<'f>, addr: u64) -> Option<(&'f [u8], u64)> {
    file.sections()
        .find(|s| addr >= s.address() && addr < s.address().saturating_add(s.size()))
        .and_then(|s| s.data().ok().map(|data| (data, s.address())))
}

/// True when `addr` lands in a data section (used to tell a real data
/// reference from an ordinary immediate).
fn in_data(file: &object::File<'_>, addr: u64) -> bool {
    file.sections().any(|s| {
        matches!(
            s.kind(),
            SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::UninitializedData
        ) && addr >= s.address()
            && addr < s.address().saturating_add(s.size())
    })
}

/// Where a jump table lives: a fixed address, or a register set earlier in the
/// block (the position-independent case: `lea rdx, [rip + table]`).
#[derive(Clone, Debug, PartialEq)]
enum TableBase {
    Abs(u64),
    Reg(String),
}

/// Recover the case targets of a jump table: the base is named in the computed
/// jump operand (`jmp qword ptr [rax*8 + 0x4020]` or `jmp [rdx + rax*8]`), and
/// entries are either absolute pointers or offsets relative to the base.
fn jump_table_targets(file: &object::File<'_>, ops: &[Instruction], op: &Instruction) -> Vec<u64> {
    let Some((entry_size, base)) = parse_jump_table(&op.disasm) else {
        return Vec::new();
    };
    let base = match base {
        TableBase::Abs(addr) => addr,
        TableBase::Reg(reg) => match resolve_table_base(ops, &reg) {
            Some(addr) => addr,
            None => return Vec::new(),
        },
    };
    let Some((data, data_addr)) = section_at(file, base) else {
        return Vec::new();
    };
    let mut off = (base - data_addr) as usize;
    let mut out = Vec::new();
    while off + entry_size <= data.len() && out.len() < 1024 {
        let value = if entry_size == 8 {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
        } else {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4])) as u64
        };
        let target = if NativeEngine::in_text(file, value) {
            value
        } else if NativeEngine::in_text(file, base.wrapping_add(value)) {
            base.wrapping_add(value)
        } else {
            break;
        };
        out.push(target);
        off += entry_size;
    }
    out
}

/// Resolve a jump-table base register from an earlier instruction in the same
/// block: `lea reg, [rip + X]` (position-independent) or `mov reg, imm`.
fn resolve_table_base(ops: &[Instruction], reg: &str) -> Option<u64> {
    let lea = format!("lea {reg}, [rip");
    let mov = format!("mov {reg}, ");
    let movabs = format!("movabs {reg}, ");
    for op in ops.iter().rev() {
        let disasm = &op.disasm;
        if disasm.starts_with(&lea) {
            if let Some(disp) = rip_displacement(disasm) {
                return Some(
                    op.addr
                        .wrapping_add(op.len as u64)
                        .wrapping_add(disp as u64),
                );
            }
        } else if let Some(rest) = disasm
            .strip_prefix(&mov)
            .or_else(|| disasm.strip_prefix(&movabs))
        {
            let imm = rest.split(',').next().unwrap_or("").trim();
            if let Some(addr) = parse_number(imm) {
                if addr != 0 {
                    return Some(addr);
                }
            }
        }
    }
    None
}

/// Recover switch cases from the `jmp reg` idiom compilers emit for dense
/// matches: a table base is loaded into a register, an entry is loaded and
/// (for position-independent tables) added to the base, then jumped to.
fn switch_targets(file: &object::File<'_>, ops: &[Instruction]) -> Vec<u64> {
    match switch_table(ops) {
        Some((table, relative)) => read_table(file, table, relative),
        None => Vec::new(),
    }
}

/// Recognise the switch idiom and return `(table_base, relative_entries)`.
///
/// * relative: `lea B,[rip+T]; movsxd R,[B + I*4]; add R, B; jmp R`
/// * absolute: `lea B,[rip+T]; mov R,[B + I*8]; jmp R`
fn switch_table(ops: &[Instruction]) -> Option<(u64, bool)> {
    let last = ops.last()?;
    let reg = last.disasm.strip_prefix("jmp ")?.trim();
    if reg.is_empty() || reg.contains(['[', ',', '+']) {
        return None;
    }
    // Collect candidate table-base registers from the setup instructions:
    // `add reg, base` (relative table) and `mov/movsxd reg, [base + idx*scale]`
    // (absolute table).
    let mut bases: Vec<String> = Vec::new();
    let mut relative = false;
    let add = format!("add {reg}, ");
    let mov = format!("mov {reg}, ");
    let movsxd = format!("movsxd {reg}, ");
    for op in ops.iter().rev() {
        let disasm = &op.disasm;
        if let Some(rest) = disasm.strip_prefix(&add) {
            let base = rest
                .trim()
                .split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .unwrap_or("");
            if !base.is_empty() {
                bases.push(base.to_string());
                relative = true;
            }
        } else if let Some(rest) = disasm
            .strip_prefix(&mov)
            .or_else(|| disasm.strip_prefix(&movsxd))
        {
            if let Some(base) = bracketed_base_register(rest) {
                bases.push(base);
            }
        }
    }
    bases.push(reg.to_string());
    for candidate in &bases {
        let lea = format!("lea {candidate}, [rip");
        for op in ops.iter().rev() {
            if op.disasm.starts_with(&lea) {
                if let Some(disp) = rip_displacement(&op.disasm) {
                    let table = op
                        .addr
                        .wrapping_add(op.len as u64)
                        .wrapping_add(disp as u64);
                    return Some((table, relative));
                }
            }
        }
    }
    None
}

/// The base register of a memory operand — the register that is not the scaled
/// index — e.g. `[rdx + rax*8]` yields `rdx`.
fn bracketed_base_register(operands: &str) -> Option<String> {
    let start = operands.find('[')?;
    let end = operands[start..].find(']')? + start;
    let inner = &operands[start + 1..end];
    let tokens: Vec<&str> = inner
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    let index = tokens
        .iter()
        .enumerate()
        .find(|(i, t)| matches!(**t, "8" | "4" | "2") && *i > 0)
        .map(|(i, _)| tokens[i - 1]);
    tokens
        .iter()
        .find(|t| {
            t.chars().any(|c| c.is_ascii_alphabetic()) && Some(**t) != index && !t.starts_with("0x")
        })
        .map(|t| (*t).to_string())
}

/// Read up to 1024 case targets from a table. `relative` selects 4-byte signed
/// offsets from the table base (position-independent) versus 8-byte absolute
/// pointers.
fn read_table(file: &object::File<'_>, table: u64, relative: bool) -> Vec<u64> {
    let Some((data, data_addr)) = section_at(file, table) else {
        return Vec::new();
    };
    let entry_size = if relative { 4 } else { 8 };
    let mut off = (table - data_addr) as usize;
    let mut out = Vec::new();
    while off + entry_size <= data.len() && out.len() < 1024 {
        let target = if relative {
            let delta = i32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0; 4])) as i64;
            table.wrapping_add(delta as u64)
        } else {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0; 8]))
        };
        if !NativeEngine::in_text(file, target) {
            break;
        }
        out.push(target);
        off += entry_size;
    }
    out
}

/// Parse `jmp ... [reg*8 + 0xADDR]` / `[0xADDR + reg*8]` into
/// `(entry_size, table_base)`. A register-indexed table with a RIP-relative
/// base is not statically resolvable here and yields `None`.
fn parse_jump_table(disasm: &str) -> Option<(usize, TableBase)> {
    let start = disasm.find('[')?;
    let end = disasm[start..].find(']')? + start;
    let inner = &disasm[start + 1..end];
    let entry_size = if inner.contains("*8") {
        8
    } else if inner.contains("*4") {
        4
    } else {
        return None;
    };
    let tokens: Vec<&str> = inner
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    // A fixed table base (non-position-independent code).
    for token in &tokens {
        if let Some(hex) = token.strip_prefix("0x") {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                return Some((entry_size, TableBase::Abs(v)));
            }
        }
    }
    // Register-indexed: the index is the token before the scale; the base is the
    // other register, resolved from an earlier `lea`/`mov` in the block.
    let mut index = None;
    for (i, token) in tokens.iter().enumerate() {
        if (*token == "8" || *token == "4") && i > 0 {
            index = Some(tokens[i - 1]);
            break;
        }
    }
    let base = tokens.iter().find(|t| {
        t.chars().any(|c| c.is_ascii_alphabetic()) && Some(**t) != index && !t.starts_with("0x")
    })?;
    Some((entry_size, TableBase::Reg((*base).to_string())))
}

/// Scan every loadable section for ASCII/UTF-16 strings, deduplicated and
/// sorted by address. Shared by `strings()` and disassembly annotation.
fn scan_all_strings(file: &object::File<'_>) -> Vec<StringRef> {
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
    out
}

/// Error text for an address outside any executable section.
fn missing_code(addr: u64) -> String {
    format!(
        "{addr:#x} is not in an executable section (it may be data); use `strings`, `xrefs`, or a function address"
    )
}

/// Cap a string for an inline disassembly comment.
fn truncate_str(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut s: String = text.chars().take(max).collect();
    s.push('…');
    s
}

/// Recover `main` from a glibc `_start` prologue on x86/x86-64: the entry
/// loads `main`'s address into the first argument register and only *then*
/// calls `__libc_start_main`. Recognises both the PIE `lea rdi, [rip + X]`
/// form and the absolute `mov rdi, X` form.
fn entry_main_seed(file: &object::File<'_>, cs: &Capstone, entry: u64) -> Option<u64> {
    if !matches!(
        file.architecture(),
        Architecture::X86_64 | Architecture::X86_64_X32 | Architecture::I386
    ) {
        return None;
    }
    let section = NativeEngine::text_section(file, entry)?;
    let data = section.data().ok()?;
    let offset = entry.saturating_sub(section.address()) as usize;
    if offset >= data.len() {
        return None;
    }
    let reg = if file.is_64() { "rdi" } else { "edi" };
    let insns = cs.disasm_count(&data[offset..], entry, 64).ok()?;
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        let operands = insn.op_str().unwrap_or("");
        let next = insn.address().wrapping_add(insn.bytes().len() as u64);
        let prefix = format!("{reg}, ");
        if mnemonic == "lea" && operands.starts_with(&format!("{reg}, [rip")) {
            if let Some(disp) = rip_displacement(operands) {
                let target = next.wrapping_add(disp as u64);
                if NativeEngine::in_text(file, target) {
                    return Some(target);
                }
            }
        } else if (mnemonic == "mov" || mnemonic == "movabs") && operands.starts_with(&prefix) {
            let imm = operands[prefix.len()..]
                .split(',')
                .next()
                .unwrap_or("")
                .trim();
            if let Some(value) = parse_number(imm) {
                if NativeEngine::in_text(file, value) {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Parse the displacement in an x86 `[rip + X]` / `[rip - X]` operand.
fn rip_displacement(operands: &str) -> Option<i64> {
    let after_rip = operands
        .split("rip")
        .nth(1)?
        .split(']')
        .next()
        .unwrap_or("");
    let compact = after_rip.replace(' ', "");
    let (sign, rest) = match compact.chars().next() {
        Some('+') => (1i64, &compact[1..]),
        Some('-') => (-1i64, &compact[1..]),
        _ => (1i64, compact.as_str()),
    };
    let magnitude = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        rest.parse::<i64>().ok()?
    };
    Some(sign * magnitude)
}

/// Parse a decimal or `0x` hex number as printed in an operand.
fn parse_number(token: &str) -> Option<u64> {
    let t = token.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u64>().ok()
    }
}

/// Loose symbol-name match for [`Engine::resolve`]: ignores C++ template
/// arguments and argument list, a `sym.`/`imp.` prefix and trailing
/// underscores, so `readInput` matches `readInput()`, `readInput__`, or the
/// mangled `_Z9readInputv` once demangled.
///
/// ```
/// use librecurse::native::name_matches;
/// assert!(name_matches("readInput", "readInput()"));
/// assert!(name_matches("success", "success()"));
/// assert!(name_matches("main", "sym.main__"));
/// assert!(name_matches("exit", "imp.exit"));
/// assert!(!name_matches("success", "_Z7successv")); // demangle first (resolve does)
/// assert!(!name_matches("main", "domain"));
/// assert!(!name_matches("", "anything"));
/// ```
pub fn name_matches(query: &str, candidate: &str) -> bool {
    let norm = |s: &str| -> String {
        strip_templates(s)
            .split('(')
            .next()
            .unwrap_or("")
            .trim_start_matches("sym.")
            .trim_start_matches("imp.")
            .trim_matches('_')
            .to_string()
    };
    let q = norm(query);
    !q.is_empty() && norm(candidate) == q
}

/// Remove balanced C++ template argument lists (`<...>`), leaving `operator<<`
/// and comparisons alone. Nested templates collapse entirely.
fn strip_templates(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut depth = 0i32;
    for (i, &c) in chars.iter().enumerate() {
        match c {
            '<' => {
                if depth > 0 {
                    depth += 1;
                } else {
                    let prev = if i > 0 { chars[i - 1] } else { ' ' };
                    let next = chars.get(i + 1).copied().unwrap_or(' ');
                    if matches!(prev, '<' | '=') || matches!(next, '<' | '=') {
                        out.push(c);
                    } else {
                        depth += 1;
                    }
                }
            }
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// A bounded, human-usable display name for a symbol: demangled, template
/// arguments and parameters stripped. C++ STL symbols demangle to hundreds of
/// characters (measured: 496 for one `std::iter_swap`), which bloats the
/// model's context for no benefit.
///
/// ```
/// use librecurse::native::shorten_name;
/// assert_eq!(shorten_name("_Z9readInputv"), "readInput");
/// assert_eq!(shorten_name("main"), "main");
/// assert!(shorten_name("void std::iter_swap<char*, std::string>(char*, std::string)").len() <= 66);
/// ```
pub fn shorten_name(raw: &str) -> String {
    let base = strip_templates(&demangle(raw));
    let no_params = base.split('(').next().unwrap_or("");
    let collapsed = no_params.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_str(collapsed.trim(), 64)
}

/// Render bytes as lowercase hex (`554889e5`).
fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Render one Capstone instruction as `mnemonic operand, operand`.
fn format_insn(insn: &capstone::Insn<'_>) -> String {
    let mnemonic = insn.mnemonic().unwrap_or("");
    let operands = insn.op_str().unwrap_or("");
    if operands.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {operands}")
    }
}

/// Map a Capstone instruction's groups to the canonical kind and edges.
///
/// Flow control comes from Capstone's instruction groups (jump/call/ret), and
/// direct targets are read from the operand text. An operand containing a
/// memory reference (`[...]`) or a register is a register/memory-indirect
/// branch and therefore has no static target.
fn classify(
    cs: &Capstone,
    insn: &capstone::Insn<'_>,
) -> (Option<String>, Option<u64>, Option<u64>) {
    let mnemonic = insn.mnemonic().unwrap_or("");
    let operands = insn.op_str().unwrap_or("");
    let groups = cs
        .insn_detail(insn)
        .map(|d| d.groups().to_vec())
        .unwrap_or_default();
    let has = |g: u8| groups.iter().any(|x| x.0 == g);
    let next = insn.address().saturating_add(insn.bytes().len() as u64);

    if has(InsnGroupType::CS_GRP_RET as u8) || has(InsnGroupType::CS_GRP_IRET as u8) {
        return (Some("ret".into()), None, None);
    }
    if has(InsnGroupType::CS_GRP_CALL as u8) {
        return (Some("call".into()), parse_branch_target(operands), None);
    }
    if has(InsnGroupType::CS_GRP_JUMP as u8) {
        let target = parse_branch_target(operands);
        if is_unconditional_branch(mnemonic) {
            return (Some("jmp".into()), target, None);
        }
        return (Some("cjmp".into()), target, Some(next));
    }
    if has(InsnGroupType::CS_GRP_INT as u8) {
        return (Some("int".into()), None, None);
    }
    (None, None, None)
}

/// Extract a direct branch/call target from an operand string, if it names a
/// bare immediate. Memory (`[...]`) and register operands yield `None`.
///
/// ```
/// use librecurse::native::parse_branch_target;
/// assert_eq!(parse_branch_target("0x401000"), Some(0x401000));
/// assert_eq!(parse_branch_target("#0x1234"), Some(0x1234));
/// assert_eq!(parse_branch_target("ra, 0x1234"), Some(0x1234));
/// assert_eq!(parse_branch_target("rax"), None);
/// assert_eq!(parse_branch_target("qword ptr [rip + 0x10]"), None);
/// ```
pub fn parse_branch_target(operands: &str) -> Option<u64> {
    if operands.contains('[') || operands.contains("ptr") {
        return None;
    }
    for token in operands
        .split(|c: char| c.is_whitespace() || c == ',')
        .rev()
    {
        let t = token.trim_matches(|c: char| matches!(c, '#' | ']' | ')' | '+' | ':' | '$' | '('));
        if t.is_empty() {
            continue;
        }
        if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                return Some(v);
            }
        } else if t.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(v) = t.parse::<u64>() {
                return Some(v);
            }
        }
    }
    None
}

/// True when a branch mnemonic is an unconditional jump (so a block has no
/// fall-through edge). Best-effort across the architectures Capstone covers;
/// an unrecognised mnemonic is treated as conditional, which only adds a
/// fall-through edge rather than dropping real control flow.
///
/// ```
/// use librecurse::native::is_unconditional_branch;
/// assert!(is_unconditional_branch("jmp"));
/// assert!(is_unconditional_branch("b"));
/// assert!(is_unconditional_branch("b.w"));
/// assert!(is_unconditional_branch("ba"));
/// assert!(!is_unconditional_branch("je"));
/// assert!(!is_unconditional_branch("beq"));
/// ```
pub fn is_unconditional_branch(mnemonic: &str) -> bool {
    // Strip ARM condition/width suffixes (`b.w`, `b.n`, `bne` stays distinct).
    let stem = mnemonic
        .split(['.', ' '])
        .next()
        .unwrap_or(mnemonic)
        .to_ascii_lowercase();
    matches!(
        stem.as_str(),
        "jmp"
            | "ljmp"
            | "b"
            | "ba"
            | "br"
            | "bx"
            | "bxj"
            | "bra"
            | "braf"
            | "brf"
            | "j"
            | "ja"
            | "jr"
            | "jal"
            | "jalr"
            | "bctr"
            | "blr"
            | "rg"
    )
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
                let mut ops = self.decode_linear(addr, n)?;
                self.annotate_ops(&mut ops);
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
        ops.dedup_by_key(|o| o.addr);
        self.annotate_ops(&mut ops);
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
        let mut blocks = self.blocks_for(entry)?;
        for block in &mut blocks {
            self.annotate_ops(&mut block.ops);
        }
        Ok(FunctionGraph {
            addr: entry,
            name: func
                .map(|f| f.name)
                .unwrap_or_else(|| format!("fcn_{entry:x}")),
            blocks,
        })
    }

    fn strings(&self) -> Result<Vec<StringRef>, String> {
        self.ensure_labels()?;
        let state = self
            .state
            .lock()
            .map_err(|e| format!("native state poisoned: {e}"))?;
        Ok(state.strings.clone().unwrap_or_default())
    }

    fn imports(&self) -> Result<Vec<Import>, String> {
        let file = self.parse()?;
        let mut out: Vec<Import> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for imp in file.imports().map_err(|e| e.to_string())? {
            let raw = String::from_utf8_lossy(imp.name()).into_owned();
            if raw.is_empty() {
                continue;
            }
            let name = shorten_name(&raw);
            if !seen.insert(name.clone()) {
                continue;
            }
            let bind = String::from_utf8_lossy(imp.library()).into_owned();
            out.push(Import {
                name,
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
                if let Ok(raw) = sym.name() {
                    let name = shorten_name(raw);
                    if !name.is_empty() && seen.insert(name.clone()) {
                        out.push(Import {
                            name,
                            plt: None,
                            bind: None,
                            kind: Some("import".to_string()),
                        });
                    }
                }
            }
        }
        // Each import is forwarded through a discovered `imp.<name>` stub;
        // attach its address so callers can jump straight to the thunk.
        self.discover()?;
        let plts: HashMap<String, u64> = {
            let state = self
                .state
                .lock()
                .map_err(|e| format!("native state poisoned: {e}"))?;
            state
                .functions
                .values()
                .filter_map(|f| f.name.strip_prefix("imp.").map(|n| (n.to_string(), f.addr)))
                .collect()
        };
        for imp in &mut out {
            if imp.plt.is_none() {
                imp.plt = plts.get(&imp.name).copied();
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
        let file = self.parse()?;
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
                        } else if memory_references(op).contains(&addr) {
                            out.push(Xref {
                                from: op.addr,
                                kind: "DATA".into(),
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
                    for referenced in memory_references(op) {
                        // Only real data addresses; an ordinary immediate is not
                        // a reference.
                        if in_data(&file, referenced) {
                            out.push(Xref {
                                from: op.addr,
                                kind: "DATA".into(),
                                to: Some(referenced),
                                fcn_name: Some(fname.clone()),
                                opcode: Some(op.disasm.clone()),
                            });
                        }
                    }
                }
            }
        }
        out.sort_by_key(|x| x.from);
        out.dedup_by(|a, b| a.from == b.from && a.kind == b.kind && a.to == b.to);
        Ok(out)
    }

    fn decompile(&self, _addr: u64) -> Result<Decompilation, String> {
        Err("the native backend has no decompiler; select a decompiler-capable backend".to_string())
    }

    fn raw(&self, _cmd: &str) -> Result<serde_json::Value, String> {
        Err("the native backend has no console".to_string())
    }

    fn resolve(&self, name: &str) -> Result<Option<u64>, String> {
        // Names the tool itself emits (`fcn_1080`, `sub_1080`, `loc_1080`) are
        // not ELF symbols, but the model will ask for them verbatim, so parse
        // the hex form before falling back to the symbol table.
        for prefix in ["fcn_", "sub_", "loc_"] {
            if let Some(hex) = name.strip_prefix(prefix) {
                if let Ok(addr) = u64::from_str_radix(hex.trim_start_matches("0x"), 16) {
                    return Ok(Some(addr));
                }
            }
        }
        // A discovered function name. Matched loosely so the model can drop the
        // C++ argument list it saw in the list (`readInput()` -> `readInput`).
        // The query may also be given mangled (`_Z4mainiPPc`), so demangle it.
        let query_demangled = demangle(name);
        self.discover()?;
        {
            let state = self
                .state
                .lock()
                .map_err(|e| format!("native state poisoned: {e}"))?;
            if let Some((_, f)) = state.functions.iter().find(|(_, f)| {
                name_matches(name, &f.name) || name_matches(&query_demangled, &f.name)
            }) {
                return Ok(Some(f.addr));
            }
        }
        let file = self.parse()?;
        let mut suffix: Option<u64> = None;
        for sym in file.symbols().chain(file.dynamic_symbols()) {
            if sym.address() == 0 {
                continue;
            }
            let Ok(sym_name) = sym.name() else {
                continue;
            };
            // The mangled name, its demangled form, and the demangled query
            // (`_Z4mainiPPc` -> `main(int, char**)` -> `main`).
            let demangled = demangle(sym_name);
            if name_matches(name, sym_name)
                || name_matches(name, &demangled)
                || name_matches(&query_demangled, sym_name)
                || name_matches(&query_demangled, &demangled)
            {
                return Ok(Some(sym.address()));
            }
            let stripped = sym_name.trim_start_matches("sym.").trim_end_matches('_');
            if !name.is_empty()
                && stripped.ends_with(name.trim_end_matches('_'))
                && suffix.is_none()
            {
                suffix = Some(sym.address());
            }
        }
        Ok(suffix)
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

/// Short architecture name.
fn arch_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 | Architecture::X86_64_X32 | Architecture::I386 => "x86",
        Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => "arm",
        Architecture::Arm => "arm",
        Architecture::Mips | Architecture::Mips64 | Architecture::Mips64_N32 => "mips",
        Architecture::PowerPc | Architecture::PowerPc64 => "ppc",
        Architecture::Riscv32 | Architecture::Riscv64 => "riscv",
        Architecture::Sparc | Architecture::Sparc32Plus | Architecture::Sparc64 => "sparc",
        Architecture::S390x => "s390",
        Architecture::M68k => "m68k",
        Architecture::Bpf => "bpf",
        Architecture::Avr => "avr",
        Architecture::Wasm32 | Architecture::Wasm64 => "wasm",
        _ => "unknown",
    }
}

/// Address width in bits for an architecture, when known.
fn arch_bits(arch: Architecture) -> Option<u64> {
    match arch {
        Architecture::X86_64
        | Architecture::X86_64_X32
        | Architecture::Aarch64
        | Architecture::Mips64
        | Architecture::Mips64_N32
        | Architecture::PowerPc64
        | Architecture::Riscv64
        | Architecture::Sparc64
        | Architecture::S390x
        | Architecture::Wasm64 => Some(64),
        Architecture::I386
        | Architecture::Arm
        | Architecture::Aarch64_Ilp32
        | Architecture::Mips
        | Architecture::PowerPc
        | Architecture::Riscv32
        | Architecture::Sparc
        | Architecture::Sparc32Plus
        | Architecture::Wasm32
        | Architecture::Bpf
        | Architecture::M68k => Some(32),
        Architecture::Avr => Some(8),
        _ => None,
    }
}

/// Short binary-format name.
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
    fn branch_targets_ignore_indirect_operands() {
        assert_eq!(parse_branch_target("0x401000"), Some(0x401000));
        assert_eq!(parse_branch_target("#0x1234"), Some(0x1234));
        assert_eq!(parse_branch_target("ra, 0x1234"), Some(0x1234));
        assert_eq!(parse_branch_target("rax"), None);
        assert_eq!(parse_branch_target("qword ptr [rip + 0x10]"), None);
    }

    #[test]
    fn parses_rip_displacements_and_numbers() {
        assert_eq!(parse_number("0x401000"), Some(0x401000));
        assert_eq!(parse_number("4437"), Some(4437));
        assert_eq!(rip_displacement("rdi, [rip + 0x11e]"), Some(0x11e));
        assert_eq!(rip_displacement("rdi, [rip - 0x10]"), Some(-16));
        assert_eq!(rip_displacement("rax, rbx"), None);
    }

    #[test]
    fn unconditional_branch_detection() {
        assert!(is_unconditional_branch("jmp"));
        assert!(is_unconditional_branch("b.w"));
        assert!(is_unconditional_branch("ba"));
        assert!(!is_unconditional_branch("je"));
        assert!(!is_unconditional_branch("bne"));
    }

    #[test]
    fn name_matches_is_loose() {
        assert!(name_matches("readInput", "readInput()"));
        assert!(name_matches("main", "sym.main__"));
        assert!(name_matches("exit", "imp.exit"));
        assert!(name_matches("checkPassword", "checkPassword(int)"));
        assert!(!name_matches("main", "domain"));
        assert!(!name_matches("", "anything"));
    }

    #[test]
    fn shortens_long_cpp_names() {
        assert_eq!(shorten_name("_Z9readInputv"), "readInput");
        assert_eq!(shorten_name("main"), "main");
        let long = "void std::iter_swap<char*, std::string>(char*, std::string)";
        assert!(
            shorten_name(long).len() <= 66,
            "got: {}",
            shorten_name(long)
        );
        // `operator<<` keeps its symbol rather than being eaten as a template.
        assert_eq!(
            strip_templates("std::operator<< <char>(int)"),
            "std::operator<< (int)"
        );
    }

    #[test]
    fn parses_jump_table_operands() {
        assert_eq!(
            parse_jump_table("jmp qword ptr [rax*8 + 0x4020]"),
            Some((8, TableBase::Abs(0x4020)))
        );
        assert_eq!(
            parse_jump_table("jmp qword ptr [0x4020 + rax*8]"),
            Some((8, TableBase::Abs(0x4020)))
        );
        assert_eq!(
            parse_jump_table("jmp dword ptr [eax*4 + 0x8040]"),
            Some((4, TableBase::Abs(0x8040)))
        );
        // Register-indexed base (position-independent code).
        assert_eq!(
            parse_jump_table("jmp qword ptr [rdx + rax*8]"),
            Some((8, TableBase::Reg("rdx".into())))
        );
        assert_eq!(parse_jump_table("jmp rax"), None);
    }

    #[test]
    fn detects_switch_idiom() {
        let mk = |addr: u64, disasm: &str, len: u32| Instruction {
            addr,
            disasm: disasm.into(),
            bytes: None,
            kind: None,
            jump: None,
            fail: None,
            len,
        };
        // Relative table: lea rcx,[rip+0x100] @0x1000 -> table 0x1107.
        let relative = vec![
            mk(0x1000, "lea rcx, [rip + 0x100]", 7),
            mk(0x1007, "movsxd rax, dword ptr [rcx + rax*4]", 7),
            mk(0x100e, "add rax, rcx", 3),
            mk(0x1011, "jmp rax", 2),
        ];
        assert_eq!(switch_table(&relative), Some((0x1107, true)));
        // Absolute table: lea rdx,[rip+0x200] @0x2000 -> table 0x2207.
        let absolute = vec![
            mk(0x2000, "lea rdx, [rip + 0x200]", 7),
            mk(0x2007, "mov rax, qword ptr [rdx + rax*8]", 7),
            mk(0x200e, "jmp rax", 2),
        ];
        assert_eq!(switch_table(&absolute), Some((0x2207, false)));
        // A plain indirect tail call is not a switch.
        let tail = vec![mk(0x3000, "jmp rax", 2)];
        assert_eq!(switch_table(&tail), None);
    }

    #[test]
    fn selects_x86_64_from_a_fat_macho() {
        fn arch_entry(cputype: u32, offset: u32, size: u32) -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(&cputype.to_be_bytes()); // cputype
            v.extend_from_slice(&3u32.to_be_bytes()); // cpusubtype
            v.extend_from_slice(&offset.to_be_bytes());
            v.extend_from_slice(&size.to_be_bytes());
            v.extend_from_slice(&0u32.to_be_bytes()); // align
            v
        }
        let arm = vec![0xAAu8; 8];
        let x86 = vec![0xBBu8; 12];
        let header = 8 + 2 * 20;
        let mut fat = Vec::new();
        fat.extend_from_slice(&0xcafebabeu32.to_be_bytes());
        fat.extend_from_slice(&2u32.to_be_bytes());
        fat.extend(arch_entry(0x0100_000C, header as u32, arm.len() as u32));
        fat.extend(arch_entry(
            0x0100_0007,
            (header + arm.len()) as u32,
            x86.len() as u32,
        ));
        fat.extend_from_slice(&arm);
        fat.extend_from_slice(&x86);
        // x86-64 is preferred over the earlier arm64 slice.
        assert_eq!(macho_slice(&fat), Some(x86));
        // A non-fat file is left alone.
        assert_eq!(macho_slice(b"\x7fELF\x02\x01\x01\0"), None);
    }

    #[test]
    fn demangle_falls_back_to_input() {
        assert_eq!(demangle("plain_name"), "plain_name");
    }
}
