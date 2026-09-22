//! recurse-vtil: a [VTIL][vtil]-inspired intermediate language for
//! de-obfuscation and de-virtualization, built on top of Recurse's own
//! backend-neutral disassembly instead of any one disassembler's details.
//!
//! # Why
//!
//! [VTIL-Core][vtil-core] ("Virtual-machine Translation Intermediate
//! Language") is an optimizing IL purpose-built for de-obfuscation and
//! de-virtualization: unlike LLVM, it keeps the native ISA's physical
//! registers, the stack, and non-SSA structure intact instead of abstracting
//! them away, which is exactly what makes it tractable to lift *from* a
//! VM-obfuscated stack machine in the first place. VTIL-Core ships the IR,
//! its optimizer pass pipeline, a symbolic VM, and an amd64
//! assembler/disassembler utility — but, by upstream's own admission
//! ("this repository is currently incomplete"), never shipped the
//! x86-to-VTIL lifter itself. The organization's other public repositories
//! ([vtil-project/*][vtil-org]) and the community continuation
//! [vtil2][vtil2] (a C# rewrite, same IR shape) inherit that same gap.
//!
//! This crate is an independent, from-scratch implementation of that
//! missing half — for Recurse specifically, not a port of any of the above.
//! It lifts the canonical [`Disassembly`](recurse_static::engine::Disassembly)
//! /[`FunctionGraph`](recurse_static::engine::FunctionGraph) every
//! [`Engine`](recurse_static::engine::Engine) already produces (native or
//! r2) into VTIL-named opcodes ([`il`]), runs a scoped-down version of
//! VTIL's own optimizer passes ([`opt`]), and renders VTIL-style text
//! ([`text`]) an agent (or a human) can read the way they would read a real
//! `.vtil` dump. Wired into `recurse_static::engine::Engine::lift` /
//! `analyze op:"lift"`, this gives Recurse's agent a way to ask for a
//! de-obfuscated view of a function instead of raw disassembly — most
//! useful exactly where VTIL itself targets: opaque-predicate and
//! VM-dispatcher-style control flow, where [`opt::resolve_constant_branches`]
//! collapses a constant-driven conditional into the single real edge.
//!
//! Every scope limit — no memory/alias modelling beyond the native operand
//! text, ten relational conditions, a fixed structural identity set rather
//! than an e-graph/SMT search — is documented at the function or type that
//! draws the line, rather than left implicit. See `docs/vtil-lift.md` in
//! the repository root for the full picture and related prior art
//! (A²MBA-LLVM's Mixed Boolean-Arithmetic hardening, approached here only
//! through the identities [`opt::simplify_algebraic`] and [`symex`] already
//! need in the *simplifying* direction). Dataflow ([`opt`]) and symbolic
//! execution ([`symex`]) both run over the whole routine
//! ([`cfg::Cfg`]-driven forward worklists with meet-at-merge), not just one
//! block, so a value set far from where it is used still resolves.
//!
//! [vtil]: https://github.com/vtil-project
//! [vtil-core]: https://github.com/vtil-project/VTIL-Core
//! [vtil-org]: https://github.com/orgs/vtil-project/repositories
//! [vtil2]: https://github.com/pop-rip/vtil2

pub mod cfg;
pub mod decompile;
#[cfg(feature = "unicorn-engine")]
pub mod emu;
pub mod il;
pub mod input;
pub mod lift;
pub mod liveness;
pub mod opt;
pub mod regalias;
pub mod symex;
pub mod taint;
pub mod text;

pub use il::{Block, Cond, Instr, Op, Operand, Register, Routine};
pub use input::{InputBlock, InputInsn};
pub use opt::OptStats;

/// Lift `blocks` (one function's worth, in the shape any backend-neutral
/// `Engine::function_graph` returns) into a [`Routine`] and run every
/// optimizer pass in [`opt::optimize`] to a fixpoint. The single entry point
/// a host — `recurse_static::engine::Engine::lift` — is expected to call.
pub fn lift_and_optimize(entry: u64, name: &str, blocks: &[InputBlock]) -> (Routine, OptStats) {
    let mut routine = lift::lift_routine(entry, name, blocks);
    let stats = opt::optimize(&mut routine);
    (routine, stats)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::input::InputInsn;

    fn insn(
        addr: u64,
        disasm: &str,
        kind: Option<&str>,
        jump: Option<u64>,
        fail: Option<u64>,
    ) -> InputInsn {
        InputInsn {
            addr,
            disasm: disasm.to_string(),
            kind: kind.map(str::to_string),
            jump,
            fail,
        }
    }

    /// End-to-end: an opaque-predicate idiom (`mov eax,1 ; cmp eax,1 ; je`)
    /// — the shape a VM dispatcher's constant-driven guard takes — lifts and
    /// folds down to a single unconditional edge, and renders as VTIL text.
    #[test]
    fn lifts_and_folds_an_opaque_predicate_to_one_edge() {
        let blocks = vec![InputBlock {
            addr: 0x1000,
            jump: None,
            fail: None,
            targets: vec![],
            ops: vec![
                insn(0x1000, "mov eax, 1", None, None, None),
                insn(0x1005, "cmp eax, 1", None, None, None),
                insn(
                    0x1008,
                    "je 0x2000",
                    Some("cjmp"),
                    Some(0x2000),
                    Some(0x100a),
                ),
            ],
        }];

        let (routine, stats) = lift_and_optimize(0x1000, "opaque_predicate", &blocks);
        assert!(stats.folded > 0);
        assert_eq!(stats.branches_resolved, 1);

        let block = &routine.blocks[0];
        assert_eq!(block.jump, Some(0x2000));
        assert_eq!(block.fail, None);
        assert_eq!(block.instrs.last().map(|i| &i.op), Some(&Op::Jmp));

        let dump = text::to_vtil_text(&routine);
        assert!(dump.contains("begin_routine 0x1000 \"opaque_predicate\""));
        assert!(dump.contains("jmp"));
    }

    #[test]
    fn unmodelled_instructions_stay_total_via_vemit() {
        let blocks = vec![InputBlock {
            addr: 0x1000,
            jump: None,
            fail: None,
            targets: vec![],
            ops: vec![
                insn(0x1000, "vpxor ymm0, ymm1, ymm2", None, None, None),
                insn(0x1004, "ret", Some("ret"), None, None),
            ],
        }];
        let (routine, _stats) = lift_and_optimize(0x1000, "f", &blocks);
        assert_eq!(routine.instr_count(), 2);
        assert_eq!(routine.blocks[0].instrs[0].op, Op::Vemit);
        assert_eq!(routine.blocks[0].instrs[1].op, Op::Vexit);
    }

    /// The real point of whole-routine dataflow: a value set in one block,
    /// carried unchanged through a passthrough block, resolves a compare in
    /// a *third* block — the shape a VM dispatcher's `opcode == N` guard
    /// takes once its opcode fetch and the guard are in different blocks
    /// (almost always, in real compiled/virtualized code). A purely
    /// block-local optimizer (what this crate shipped before whole-routine
    /// propagation/liveness) cannot fold this at all: `cmp eax, 1` starts
    /// its own block with no idea `eax` is `1`.
    #[test]
    fn resolves_a_branch_whose_constant_flows_through_an_unrelated_block() {
        let blocks = vec![
            InputBlock {
                addr: 0x1000,
                jump: Some(0x1010),
                fail: None,
                targets: vec![],
                ops: vec![insn(0x1000, "mov eax, 1", None, None, None)],
            },
            // A passthrough block that never mentions `eax` at all.
            InputBlock {
                addr: 0x1010,
                jump: Some(0x1020),
                fail: None,
                targets: vec![],
                ops: vec![insn(0x1010, "nop", None, None, None)],
            },
            InputBlock {
                addr: 0x1020,
                jump: Some(0x2000),
                fail: Some(0x1026),
                targets: vec![],
                ops: vec![
                    insn(0x1020, "cmp eax, 1", None, None, None),
                    insn(
                        0x1024,
                        "je 0x2000",
                        Some("cjmp"),
                        Some(0x2000),
                        Some(0x1026),
                    ),
                ],
            },
        ];

        let (routine, stats) = lift_and_optimize(0x1000, "dispatcher_guard", &blocks);
        assert!(stats.propagated > 0, "eax=1 must propagate across blocks");
        assert!(stats.branches_resolved > 0);

        let guard = routine
            .blocks
            .iter()
            .find(|b| b.addr == 0x1020)
            .expect("guard block present");
        assert_eq!(guard.jump, Some(0x2000));
        assert_eq!(
            guard.fail, None,
            "the now-unreachable fall-through edge is dropped"
        );
        assert_eq!(guard.instrs.last().map(|i| &i.op), Some(&Op::Jmp));

        // Once nothing downstream reads `eax` through the (now-literal)
        // guard, the setup `mov eax, 1` in the entry block is itself dead —
        // whole-routine liveness, not just local dead-store elimination,
        // is what proves that.
        let entry = &routine.blocks[0];
        assert!(
            entry.instrs.is_empty(),
            "the eax=1 setup should be cleaned up once nothing reads it: {entry:?}"
        );
    }
}
