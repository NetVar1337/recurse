//! Vulnerability sink / taint analysis: track data flowing from an
//! untrusted source call (`recv`, `getenv`, `argv`, …) through a
//! routine's lifted IL, and flag a "sink" call (`strcpy`, `system`,
//! `memcpy`, …) reached with a tainted argument and no sanitizer in
//! between — the same class of static audit `knife`-style vulnerability
//! scanners run.
//!
//! # Design
//!
//! A whole-CFG, flow-sensitive, forward register-taint dataflow over
//! [`crate::il::Routine`], built on the same [`crate::cfg::Cfg`] worklist
//! shape [`crate::opt`]/[`crate::liveness`] already use, including the
//! same non-destructive-analysis-then-final-report split those modules
//! settled on after [`crate::opt`]'s own back-edge soundness fix: taint
//! sets are only ever unioned (monotone) during the fixpoint, and
//! [`Finding`]s are collected in one final pass from the converged
//! per-block entry state, so a loop body is never analyzed against a
//! premature, not-yet-widened taint set.
//!
//! # Call semantics are the caller's to provide
//!
//! [`crate::il::Op::Vxcall`]'s only operand is the call target itself —
//! VTIL (deliberately) does not model calling-convention argument
//! registers as instruction operands, since those live in the ABI, not
//! the `call` instruction. So this module needs, and [`TaintSpec`]
//! carries, the calling convention explicitly: which register holds a
//! call's return value ([`TaintSpec::return_register`]) and which
//! registers are argument slots at a call site
//! ([`TaintSpec::argument_registers`]) — real, honest configuration
//! rather than a silently baked-in assumption. A sink [`Finding`] fires
//! when *any* argument register is tainted at that call, which
//! over-approximates "the tainted value is the specific argument that
//! matters" the same way every practical static taint tool does; see
//! honest scope below.
//!
//! Call targets are resolved to names via a caller-supplied
//! `resolve_call: &HashMap<u64, String>` (a [`crate::il::Instr::target`]
//! address to an import/symbol name) — the same "caller wires in their
//! own already-resolved data" shape `crate::diff`/`crate::capa` use.

use std::collections::{HashMap, HashSet};

use crate::cfg::Cfg;
use crate::il::{Instr, Op, Operand, Register, Routine};

/// Source/sink/sanitizer function names plus the calling-convention
/// registers this analysis needs to know about.
#[derive(Clone, Debug)]
pub struct TaintSpec {
    /// Call targets that introduce taint — their return value becomes
    /// tainted.
    pub sources: Vec<String>,
    /// Call targets that consume taint — flagged when any argument
    /// register is tainted at the call site.
    pub sinks: Vec<String>,
    /// Call targets that remove taint — their return value becomes
    /// untainted, modeling "this call validated/cleaned the value".
    pub sanitizers: Vec<String>,
    /// The register a call's return value is conventionally left in
    /// (e.g. `"rax"` on x86-64, both Windows and SysV).
    pub return_register: String,
    /// Registers holding a call's arguments at the call site (e.g.
    /// `["rcx", "rdx", "r8", "r9"]` for Win64, or
    /// `["rdi", "rsi", "rdx", "rcx", "r8", "r9"]` for SysV).
    pub argument_registers: Vec<String>,
}

impl TaintSpec {
    /// A `TaintSpec` using the Win64 integer-argument calling convention
    /// (`rcx`, `rdx`, `r8`, `r9`) and `rax` for the return value.
    #[must_use]
    pub fn win64(sources: Vec<String>, sinks: Vec<String>, sanitizers: Vec<String>) -> Self {
        Self {
            sources,
            sinks,
            sanitizers,
            return_register: "rax".to_string(),
            argument_registers: vec![
                "rcx".to_string(),
                "rdx".to_string(),
                "r8".to_string(),
                "r9".to_string(),
            ],
        }
    }

    /// A `TaintSpec` using the System V AMD64 integer-argument calling
    /// convention (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`) and `rax` for
    /// the return value.
    #[must_use]
    pub fn sysv64(sources: Vec<String>, sinks: Vec<String>, sanitizers: Vec<String>) -> Self {
        Self {
            sources,
            sinks,
            sanitizers,
            return_register: "rax".to_string(),
            argument_registers: vec![
                "rdi".to_string(),
                "rsi".to_string(),
                "rdx".to_string(),
                "rcx".to_string(),
                "r8".to_string(),
                "r9".to_string(),
            ],
        }
    }
}

/// A sink call reached with a tainted argument register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub sink_addr: u64,
    pub sink_name: String,
    /// Argument registers (from [`TaintSpec::argument_registers`]) that
    /// were tainted at this call, in convention order.
    pub tainted_arguments: Vec<String>,
}

/// Registers currently possibly-tainted, keyed by their [`Register`]
/// (physical name or lifter temporary).
type TaintSet = HashSet<Register>;

/// Run the taint analysis over `routine`.
///
/// `resolve_call` maps a [`crate::il::Instr::target`] address to the
/// import/symbol name it calls; a target absent from this map is treated
/// as an unknown call — taint passes through it unchanged (conservative:
/// neither tainting nor sanitizing, since this analysis has no basis to
/// assume either about code it can't identify).
#[must_use]
pub fn analyze(
    routine: &Routine,
    resolve_call: &HashMap<u64, String>,
    spec: &TaintSpec,
) -> Vec<Finding> {
    let cfg = Cfg::build(routine);
    let blocks: HashMap<u64, &crate::il::Block> =
        routine.blocks.iter().map(|b| (b.addr, b)).collect();

    // Fixpoint: a block's entry taint is the union of every predecessor's
    // *exit* taint (not its entry taint — taint a block generates itself
    // must reach its successors too). Monotone (taint only ever grows),
    // so this always converges; scratch clones only, no rewriting, mirroring
    // `crate::opt`'s own analysis-then-final-report split.
    let mut exit_taint: HashMap<u64, TaintSet> = routine
        .blocks
        .iter()
        .map(|b| (b.addr, TaintSet::new()))
        .collect();
    let mut entry_taint: HashMap<u64, TaintSet> = routine
        .blocks
        .iter()
        .map(|b| (b.addr, TaintSet::new()))
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for &addr in &cfg.order {
            let mut incoming = TaintSet::new();
            for &pred in cfg.predecessors(addr) {
                incoming.extend(exit_taint.get(&pred).cloned().unwrap_or_default());
            }
            if incoming != entry_taint[&addr] {
                entry_taint.insert(addr, incoming.clone());
                changed = true;
            }
            if let Some(block) = blocks.get(&addr) {
                let exit = simulate_block(block, incoming, resolve_call, spec, None);
                if exit != exit_taint[&addr] {
                    exit_taint.insert(addr, exit);
                    changed = true;
                }
            }
        }
    }

    // Final pass: walk every block from its converged entry state,
    // collecting findings this time.
    let mut findings = Vec::new();
    for &addr in &cfg.order {
        if let Some(block) = blocks.get(&addr) {
            let entry = entry_taint.get(&addr).cloned().unwrap_or_default();
            simulate_block(block, entry, resolve_call, spec, Some(&mut findings));
        }
    }
    findings
}

/// Simulate one block's instructions from `entry`, returning the taint
/// set after the last instruction. When `findings` is `Some`, also
/// records a [`Finding`] for every sink call reached with a tainted
/// argument register — kept `None` during the fixpoint (state-only) and
/// `Some` only on the final, converged pass, so a finding is never
/// double-reported (or reported against a not-yet-widened loop state)
/// while the fixpoint is still settling.
fn simulate_block(
    block: &crate::il::Block,
    entry: TaintSet,
    resolve_call: &HashMap<u64, String>,
    spec: &TaintSpec,
    mut findings: Option<&mut Vec<Finding>>,
) -> TaintSet {
    let mut taint = entry;
    for instr in &block.instrs {
        match &instr.op {
            Op::Vxcall => {
                let name = instr.target.and_then(|t| resolve_call.get(&t));
                if let Some(name) = name {
                    if spec.sinks.contains(name) {
                        let tainted_arguments: Vec<String> = spec
                            .argument_registers
                            .iter()
                            .filter(|r| taint.contains(&Register::Physical((*r).clone())))
                            .cloned()
                            .collect();
                        if !tainted_arguments.is_empty() {
                            if let Some(findings) = findings.as_deref_mut() {
                                findings.push(Finding {
                                    sink_addr: instr.addr,
                                    sink_name: name.clone(),
                                    tainted_arguments,
                                });
                            }
                        }
                    }
                    if spec.sources.contains(name) {
                        taint.insert(Register::Physical(spec.return_register.clone()));
                    } else if spec.sanitizers.contains(name) {
                        taint.remove(&Register::Physical(spec.return_register.clone()));
                    }
                    // An unrecognised name: taint passes through
                    // unchanged (see this function's own doc / the module
                    // doc's `resolve_call` note).
                }
            }
            _ => propagate(instr, &mut taint),
        }
    }
    taint
}

/// Ordinary (non-call) instruction: the written operand's taint becomes
/// the union of every read register's taint — standard forward taint
/// propagation. A `str` (memory store) has no written *register* operand
/// so this is a no-op for it (see honest scope: no memory-taint
/// modeling). `ldd` (memory load) is likewise conservative: its written
/// register is tainted only when the load's own address expression
/// textually mentions an already-tainted register's name — a real but
/// admittedly textual heuristic, matching [`crate::il::Operand::Mem`]'s
/// own "kept as unparsed text, structured pointer modeling is future
/// work" status.
fn propagate(instr: &Instr, taint: &mut TaintSet) {
    let Some(written) = instr.written() else {
        return;
    };
    let Operand::Reg(dst) = written else { return };
    let dst = dst.clone();

    let any_source_tainted = if instr.op == Op::Ldd {
        instr.operands.iter().any(|op| match op {
            Operand::Mem(text) => taint.iter().any(|t| text.contains(&t.to_string())),
            Operand::Reg(r) => taint.contains(r),
            Operand::Imm(_) => false,
        })
    } else {
        instr
            .read_registers()
            .into_iter()
            .any(|r| taint.contains(r))
    };

    if any_source_tainted {
        taint.insert(dst);
    } else {
        taint.remove(&dst);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::il::Block;

    fn reg(name: &str) -> Operand {
        Operand::Reg(Register::Physical(name.to_string()))
    }

    fn call(addr: u64, target: u64) -> Instr {
        Instr {
            addr,
            op: Op::Vxcall,
            operands: vec![Operand::Imm(target as i64)],
            target: Some(target),
            fallthrough: None,
            native: format!("call {target:#x}"),
        }
    }

    fn mov(addr: u64, dst: &str, src: &str) -> Instr {
        Instr {
            addr,
            op: Op::Mov,
            operands: vec![reg(dst), reg(src)],
            target: None,
            fallthrough: None,
            native: format!("mov {dst}, {src}"),
        }
    }

    fn spec() -> TaintSpec {
        TaintSpec::win64(
            vec!["recv".to_string()],
            vec!["strcpy".to_string()],
            vec!["validate".to_string()],
        )
    }

    fn resolver() -> HashMap<u64, String> {
        HashMap::from([
            (0x1000, "recv".to_string()),
            (0x2000, "strcpy".to_string()),
            (0x3000, "validate".to_string()),
        ])
    }

    #[test]
    fn straight_line_taint_from_source_to_sink_is_flagged() {
        // recv() -> rax tainted; mov rcx, rax; strcpy(rcx, ...) -- flagged.
        let routine = Routine {
            entry: 0x100,
            name: "f".to_string(),
            blocks: vec![Block {
                addr: 0x100,
                instrs: vec![
                    call(0x100, 0x1000),
                    mov(0x110, "rcx", "rax"),
                    call(0x120, 0x2000),
                ],
                jump: None,
                fail: None,
                targets: vec![],
            }],
        };
        let findings = analyze(&routine, &resolver(), &spec());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink_addr, 0x120);
        assert_eq!(findings[0].sink_name, "strcpy");
        assert_eq!(findings[0].tainted_arguments, vec!["rcx".to_string()]);
    }

    #[test]
    fn untainted_call_to_the_same_sink_is_not_flagged() {
        let routine = Routine {
            entry: 0x100,
            name: "f".to_string(),
            blocks: vec![Block {
                addr: 0x100,
                // No source call at all: rcx is never tainted.
                instrs: vec![mov(0x110, "rcx", "rbx"), call(0x120, 0x2000)],
                jump: None,
                fail: None,
                targets: vec![],
            }],
        };
        let findings = analyze(&routine, &resolver(), &spec());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_sanitizer_call_clears_taint_before_the_sink() {
        // recv() -> rax tainted; validate(rax) -> rax untainted; mov rcx, rax; strcpy(rcx) -- not flagged.
        let routine = Routine {
            entry: 0x100,
            name: "f".to_string(),
            blocks: vec![Block {
                addr: 0x100,
                instrs: vec![
                    call(0x100, 0x1000),
                    call(0x105, 0x3000),
                    mov(0x110, "rcx", "rax"),
                    call(0x120, 0x2000),
                ],
                jump: None,
                fail: None,
                targets: vec![],
            }],
        };
        let findings = analyze(&routine, &resolver(), &spec());
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn taint_survives_a_loop_back_edge() {
        // Block A (entry): recv() taints rax, mov rcx,rax, falls into B.
        // Block B: strcpy(rcx) is flagged, then loops back to itself (a
        // self-loop back edge) -- this must not lose the taint the way a
        // destructive single-pass analysis would on the first visit
        // before the loop is widened.
        let routine = Routine {
            entry: 0x100,
            name: "f".to_string(),
            blocks: vec![
                Block {
                    addr: 0x100,
                    instrs: vec![call(0x100, 0x1000), mov(0x110, "rcx", "rax")],
                    jump: Some(0x200),
                    fail: None,
                    targets: vec![],
                },
                Block {
                    addr: 0x200,
                    instrs: vec![call(0x200, 0x2000)],
                    jump: Some(0x200), // self-loop
                    fail: None,
                    targets: vec![],
                },
            ],
        };
        let findings = analyze(&routine, &resolver(), &spec());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink_addr, 0x200);
    }

    #[test]
    fn an_unresolved_call_target_neither_taints_nor_sanitizes() {
        let routine = Routine {
            entry: 0x100,
            name: "f".to_string(),
            blocks: vec![Block {
                addr: 0x100,
                // 0x9999 is not in the resolver map at all.
                instrs: vec![
                    call(0x100, 0x9999),
                    mov(0x110, "rcx", "rax"),
                    call(0x120, 0x2000),
                ],
                jump: None,
                fail: None,
                targets: vec![],
            }],
        };
        let findings = analyze(&routine, &resolver(), &spec());
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_routine_yields_no_findings() {
        let routine = Routine {
            entry: 0x100,
            name: "f".to_string(),
            blocks: vec![],
        };
        assert!(analyze(&routine, &resolver(), &spec()).is_empty());
    }
}
