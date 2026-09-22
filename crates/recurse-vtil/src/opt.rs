//! Optimizer passes over the lifted IL, run block-local to a fixpoint.
//!
//! Named after (and scoped-down from) VTIL-Core's and vtil2's optimizer
//! pipeline: `MovPropagationPass`/`CollectivePropagationPass` →
//! [`propagate_and_fold`], `DeadCodeEliminationPass` →
//! [`eliminate_dead_stores`], `SymbolicRewritePass` →
//! [`simplify_algebraic`], `BranchCorrectionPass` →
//! [`resolve_constant_branches`]. Every pass here is **block-local**: it
//! never assumes anything about what a successor block does with a
//! register, which is what keeps it sound without a full whole-routine
//! dataflow/dominance analysis (what VTIL's real optimizer builds via its
//! symbolic executor). That is the honest scope line: this crate recovers
//! the constant-driven cases a VM dispatcher's opcode fetch/compare chain
//! produces in one block, not the general cross-block case.

use crate::il::{Block, Cond, Instr, Op, Operand, Register, Routine};
use std::collections::HashMap;

/// Counts of what each round of [`optimize`] actually changed, returned so a
/// caller (or the `analyze` tool's `lift` op) can report whether
/// optimization did anything rather than silently no-op.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct OptStats {
    /// Fixpoint rounds run across all blocks (mostly diagnostic).
    pub rounds: usize,
    /// Register reads rewritten to a known constant or copy source.
    pub propagated: usize,
    /// Instructions whose result was resolved to a literal at compile time
    /// and rewritten to `mov`.
    pub folded: usize,
    /// Instructions simplified or removed by an algebraic identity.
    pub simplified: usize,
    /// Register writes removed because a later write in the same block
    /// overwrote them before any read observed the old value.
    pub dead_stores_removed: usize,
    /// `js` instructions whose condition resolved to a compile-time
    /// constant, rewritten to an unconditional `jmp` (the CFG edge that is
    /// now unreachable is dropped from the block too).
    pub branches_resolved: usize,
}

impl OptStats {
    fn total(&self) -> usize {
        self.propagated
            + self.folded
            + self.simplified
            + self.dead_stores_removed
            + self.branches_resolved
    }

    fn add(&mut self, other: &OptStats) {
        self.propagated += other.propagated;
        self.folded += other.folded;
        self.simplified += other.simplified;
        self.dead_stores_removed += other.dead_stores_removed;
        self.branches_resolved += other.branches_resolved;
    }
}

/// Hard cap on fixpoint rounds per block. Each round strictly reduces or
/// resolves something counted in [`OptStats::total`], so this bounds
/// pathological input rather than being expected to bind in practice.
const MAX_ROUNDS_PER_BLOCK: usize = 64;

/// Run every pass over every block of `routine`, in place, to a fixpoint.
pub fn optimize(routine: &mut Routine) -> OptStats {
    let mut total = OptStats::default();
    for block in &mut routine.blocks {
        loop {
            let mut round = OptStats::default();
            let (propagated, folded) = propagate_and_fold(&mut block.instrs);
            round.propagated = propagated;
            round.folded = folded;
            round.simplified = simplify_algebraic(&mut block.instrs);
            round.dead_stores_removed = eliminate_dead_stores(&mut block.instrs);
            round.branches_resolved = resolve_constant_branches(block);
            total.add(&round);
            total.rounds += 1;
            if round.total() == 0 || total.rounds >= MAX_ROUNDS_PER_BLOCK {
                break;
            }
        }
    }
    total
}

/// A statically-known register value, tracked forward through one block.
#[derive(Clone, Debug, PartialEq)]
enum Known {
    Const(i64),
    /// This register currently holds the same value as `Register`, which
    /// was not itself a known constant at the time of the copy.
    Copy(Register),
}

/// VTIL-style copy/constant propagation plus constant folding, in one
/// forward pass. Mirrors VTIL's `MovPropagationPass` (propagate a `mov`'s
/// source into later reads) composed with its `CollectivePropagationPass`
/// (fold once every operand of an instruction is a literal): here both
/// happen per instruction so a folded `mov` is immediately available to
/// propagate into whatever reads it next.
///
/// Block-local and conservative: any instruction this crate does not
/// understand the write set of (`Op::Vemit`, `Op::Vxcall` — an opaque native
/// instruction or an external call, either of which may touch registers
/// this IL never sees mentioned) clears everything tracked so far rather
/// than risk propagating a value past where it could have been clobbered.
fn propagate_and_fold(instrs: &mut [Instr]) -> (usize, usize) {
    let mut known: HashMap<Register, Known> = HashMap::new();
    let mut propagated = 0usize;
    let mut folded = 0usize;

    for instr in instrs.iter_mut() {
        if matches!(instr.op, Op::Vemit | Op::Vxcall) {
            known.clear();
        }

        // The register this instruction writes, if any — captured by name
        // before substitution below can turn `operands[0]` into a folded
        // immediate for a `readwrite` op.
        let dst_reg = if instr.op.writes_operand0() {
            match instr.operands.first() {
                Some(Operand::Reg(r)) => Some(r.clone()),
                _ => None,
            }
        } else {
            None
        };

        let start = if instr.op.writes_operand0() && !instr.op.reads_operand0() {
            1
        } else {
            0
        };
        for operand in instr.operands.iter_mut().skip(start) {
            if let Operand::Reg(r) = operand {
                match known.get(r) {
                    Some(Known::Const(v)) => {
                        *operand = Operand::Imm(*v);
                        propagated += 1;
                    }
                    Some(Known::Copy(src)) => {
                        let src = src.clone();
                        *operand = Operand::Reg(src);
                        propagated += 1;
                    }
                    None => {}
                }
            }
        }

        if let (Some(v), Some(dst)) = (fold_value(instr), dst_reg.clone()) {
            instr.op = Op::Mov;
            instr.operands = vec![Operand::Reg(dst), Operand::Imm(v)];
            folded += 1;
        }

        if let Some(dst) = dst_reg {
            let new_known = match &instr.op {
                Op::Mov => match instr.operands.get(1) {
                    Some(Operand::Imm(v)) => Some(Known::Const(*v)),
                    Some(Operand::Reg(src)) => Some(
                        known
                            .get(src)
                            .cloned()
                            .unwrap_or_else(|| Known::Copy(src.clone())),
                    ),
                    _ => None,
                },
                _ => None,
            };
            match new_known {
                Some(k) => {
                    known.insert(dst, k);
                }
                None => {
                    known.remove(&dst);
                }
            }
        }
    }

    (propagated, folded)
}

fn as_imm(operand: Option<&Operand>) -> Option<i64> {
    match operand {
        Some(Operand::Imm(v)) => Some(*v),
        _ => None,
    }
}

/// Evaluate `instr` to a literal when every operand it reads is already a
/// known immediate (wrapping arithmetic throughout — this models the native
/// machine's own wraparound, not a trap).
fn fold_value(instr: &Instr) -> Option<i64> {
    match &instr.op {
        Op::Neg => as_imm(instr.operands.first()).map(i64::wrapping_neg),
        Op::Not => as_imm(instr.operands.first()).map(|a| !a),
        Op::Add => {
            Some(as_imm(instr.operands.first())?.wrapping_add(as_imm(instr.operands.get(1))?))
        }
        Op::Sub => {
            Some(as_imm(instr.operands.first())?.wrapping_sub(as_imm(instr.operands.get(1))?))
        }
        Op::And => Some(as_imm(instr.operands.first())? & as_imm(instr.operands.get(1))?),
        Op::Or => Some(as_imm(instr.operands.first())? | as_imm(instr.operands.get(1))?),
        Op::Xor => Some(as_imm(instr.operands.first())? ^ as_imm(instr.operands.get(1))?),
        Op::Shl => {
            let n = as_imm(instr.operands.get(1))?;
            Some(as_imm(instr.operands.first())?.wrapping_shl(n as u32))
        }
        Op::Shr => {
            let n = as_imm(instr.operands.get(1))?;
            let a = as_imm(instr.operands.first())? as u64;
            Some(a.wrapping_shr(n as u32) as i64)
        }
        Op::Sar => {
            let n = as_imm(instr.operands.get(1))?;
            Some(as_imm(instr.operands.first())?.wrapping_shr(n as u32))
        }
        Op::Mul | Op::IMul => {
            Some(as_imm(instr.operands.first())?.wrapping_mul(as_imm(instr.operands.get(1))?))
        }
        Op::SetCond(cond) => {
            let a = as_imm(instr.operands.get(1))?;
            let b = as_imm(instr.operands.get(2))?;
            Some(if evaluate_cond(*cond, a, b) { 1 } else { 0 })
        }
        _ => None,
    }
}

fn evaluate_cond(cond: Cond, a: i64, b: i64) -> bool {
    match cond {
        Cond::Eq => a == b,
        Cond::Ne => a != b,
        Cond::Gt => a > b,
        Cond::Ge => a >= b,
        Cond::Lt => a < b,
        Cond::Le => a <= b,
        Cond::UGt => (a as u64) > (b as u64),
        Cond::UGe => (a as u64) >= (b as u64),
        Cond::ULt => (a as u64) < (b as u64),
        Cond::ULe => (a as u64) <= (b as u64),
    }
}

/// Local dead-store elimination: if a register is written and then written
/// *again* later in the same block with no read of it in between, the
/// earlier write is unobservable and safe to delete. This is a sound
/// subset of VTIL's real `DeadCodeEliminationPass`, which additionally
/// deletes a write that reaches the end of a block unread by tracking
/// liveness across the whole routine; doing that here would need CFG
/// dominance/liveness this crate does not yet build (a write surviving to
/// block exit might still be read by a successor block, so it is always
/// kept). `Op::Vemit`/`Op::Vxcall` clear everything tracked so far, for the
/// same "may read/write anything" reason as in [`propagate_and_fold`].
fn eliminate_dead_stores(instrs: &mut Vec<Instr>) -> usize {
    let mut last_write: HashMap<Register, usize> = HashMap::new();
    let mut dead = vec![false; instrs.len()];

    for (i, instr) in instrs.iter().enumerate() {
        if matches!(instr.op, Op::Vemit | Op::Vxcall) {
            last_write.clear();
        } else {
            for r in instr.read_registers() {
                last_write.remove(r);
            }
        }
        if let Some(Operand::Reg(r)) = instr.written() {
            if !instr.op.has_side_effect() {
                if let Some(&prev) = last_write.get(r) {
                    dead[prev] = true;
                }
                last_write.insert(r.clone(), i);
            }
        }
    }

    let removed = dead.iter().filter(|d| **d).count();
    if removed > 0 {
        let mut kept = Vec::with_capacity(instrs.len() - removed);
        for (instr, is_dead) in instrs.drain(..).zip(dead) {
            if !is_dead {
                kept.push(instr);
            }
        }
        *instrs = kept;
    }
    removed
}

enum Identity {
    None,
    /// The instruction has no effect at all (`x | x`, `x & -1`, …); drop it.
    Noop,
    /// The instruction always produces zero regardless of its inputs
    /// (`x & 0`, `x ^ x`, `x - x`, `x * 0`); rewrite to `mov dst, 0`.
    Zero(Register),
    /// The instruction always produces all-ones (`x | -1`); rewrite to
    /// `mov dst, -1`.
    AllOnes(Register),
}

/// Single-instruction algebraic identities — idempotence (`x | x`, `x & x`),
/// the identity element (`x ^ 0`, `x + 0`, `x * 1`, `x & -1`), the
/// annihilator (`x & 0`, `x * 0`, `x | -1`), and self-inverses (`x ^ x`,
/// `x - x`). These are the narrow, always-sound end of the identity space
/// A2MBA-LLVM's paper explores in the *obfuscating* direction (composing
/// bitwise/arithmetic terms that are equal by one of exactly these laws);
/// recognising the multi-instruction compositions it builds — or the
/// equality-saturation search A2MBA-LLVM's own hybrid mode and tools like
/// GAMBA/ProMBA use — needs an expression-tree/e-graph pass over the block,
/// which is future work, not implemented here.
fn identity_result(instr: &Instr) -> Identity {
    let dst = match instr.operands.first() {
        Some(Operand::Reg(r)) => r.clone(),
        _ => return Identity::None,
    };
    let same_operand = instr.operands.len() >= 2 && instr.operands[0] == instr.operands[1];
    let rhs = instr.operands.get(1);

    match (&instr.op, rhs) {
        (Op::Xor | Op::Or | Op::Add | Op::Sub, Some(Operand::Imm(0))) => Identity::Noop,
        (Op::Shl | Op::Shr | Op::Sar | Op::Rol | Op::Ror, Some(Operand::Imm(0))) => Identity::Noop,
        (Op::Mul | Op::IMul, Some(Operand::Imm(1))) => Identity::Noop,
        (Op::And, Some(Operand::Imm(-1))) => Identity::Noop,
        (Op::And, Some(Operand::Imm(0))) => Identity::Zero(dst),
        (Op::Mul | Op::IMul, Some(Operand::Imm(0))) => Identity::Zero(dst),
        (Op::Or, Some(Operand::Imm(-1))) => Identity::AllOnes(dst),
        (Op::Xor, _) if same_operand => Identity::Zero(dst),
        (Op::Sub, _) if same_operand => Identity::Zero(dst),
        (Op::And, _) if same_operand => Identity::Noop,
        (Op::Or, _) if same_operand => Identity::Noop,
        _ => Identity::None,
    }
}

/// Apply [`identity_result`] everywhere, then collapse an adjacent
/// same-register `neg;neg` or `not;not` pair (involution: applying either
/// twice is the identity function).
fn simplify_algebraic(instrs: &mut Vec<Instr>) -> usize {
    let mut count = 0usize;
    let mut keep = vec![true; instrs.len()];

    for (i, instr) in instrs.iter_mut().enumerate() {
        match identity_result(instr) {
            Identity::None => {}
            Identity::Noop => {
                keep[i] = false;
                count += 1;
            }
            Identity::Zero(dst) => {
                instr.op = Op::Mov;
                instr.operands = vec![Operand::Reg(dst), Operand::Imm(0)];
                count += 1;
            }
            Identity::AllOnes(dst) => {
                instr.op = Op::Mov;
                instr.operands = vec![Operand::Reg(dst), Operand::Imm(-1)];
                count += 1;
            }
        }
    }

    let mut j = 0usize;
    while j + 1 < instrs.len() {
        let collapses = keep[j]
            && keep[j + 1]
            && matches!(instrs[j].op, Op::Neg | Op::Not)
            && instrs[j].op == instrs[j + 1].op
            && instrs[j].operands.first() == instrs[j + 1].operands.first();
        if collapses {
            keep[j] = false;
            keep[j + 1] = false;
            count += 1;
            j += 2;
        } else {
            j += 1;
        }
    }

    if count > 0 {
        let mut kept = Vec::with_capacity(instrs.len());
        for (instr, keep_it) in instrs.drain(..).zip(keep) {
            if keep_it {
                kept.push(instr);
            }
        }
        *instrs = kept;
    }
    count
}

/// VTIL's `BranchCorrectionPass`, scoped to what block-local folding can
/// actually prove: when a block's terminating `js` has been reduced (by
/// [`propagate_and_fold`]) to a literal condition, replace it with an
/// unconditional `jmp` and drop the CFG edge that is now unreachable. This
/// is exactly the shape a devirtualized VM dispatcher takes once its opcode
/// compare chain folds: one opaque conditional collapses into the single
/// real successor.
fn resolve_constant_branches(block: &mut Block) -> usize {
    let Some(last) = block.instrs.last() else {
        return 0;
    };
    if last.op != Op::Js {
        return 0;
    }
    let taken = match last.operands.first() {
        Some(Operand::Imm(v)) => *v != 0,
        _ => return 0,
    };
    let target = if taken { last.target } else { last.fallthrough };
    let Some(target) = target else {
        return 0;
    };

    let idx = block.instrs.len() - 1;
    block.instrs[idx].op = Op::Jmp;
    block.instrs[idx].operands = vec![Operand::Imm(target as i64)];
    block.instrs[idx].target = Some(target);
    block.instrs[idx].fallthrough = None;
    block.jump = Some(target);
    block.fail = None;
    1
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn mov_imm(reg: &str, v: i64) -> Instr {
        Instr {
            addr: 0,
            op: Op::Mov,
            operands: vec![
                Operand::Reg(Register::Physical(reg.into())),
                Operand::Imm(v),
            ],
            target: None,
            fallthrough: None,
            native: format!("mov {reg}, {v:#x}"),
        }
    }

    fn binop(op: Op, reg: &str, rhs: Operand) -> Instr {
        Instr {
            addr: 0,
            op,
            operands: vec![Operand::Reg(Register::Physical(reg.into())), rhs],
            target: None,
            fallthrough: None,
            native: String::new(),
        }
    }

    #[test]
    fn propagates_and_folds_constant_chain() {
        // mov eax, 5 ; add eax, 3  ->  mov eax, 5 ; mov eax, 8
        let mut instrs = vec![mov_imm("eax", 5), binop(Op::Add, "eax", Operand::Imm(3))];
        let (propagated, folded) = propagate_and_fold(&mut instrs);
        assert_eq!(propagated, 1);
        assert_eq!(folded, 1);
        assert_eq!(instrs[1].op, Op::Mov);
        assert_eq!(instrs[1].operands[1], Operand::Imm(8));
    }

    #[test]
    fn dead_store_removed_when_overwritten_before_any_read() {
        let mut instrs = vec![
            mov_imm("eax", 1),
            mov_imm("eax", 2), // first mov is dead: never read before this
        ];
        let removed = eliminate_dead_stores(&mut instrs);
        assert_eq!(removed, 1);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].operands[1], Operand::Imm(2));
    }

    #[test]
    fn dead_store_kept_when_read_in_between() {
        let mut instrs = vec![
            mov_imm("eax", 1),
            binop(
                Op::Add,
                "ebx",
                Operand::Reg(Register::Physical("eax".into())),
            ),
            mov_imm("eax", 2),
        ];
        let removed = eliminate_dead_stores(&mut instrs);
        assert_eq!(removed, 0, "eax was read before being overwritten");
    }

    #[test]
    fn xor_self_becomes_zero() {
        let mut instrs = vec![binop(
            Op::Xor,
            "eax",
            Operand::Reg(Register::Physical("eax".into())),
        )];
        let count = simplify_algebraic(&mut instrs);
        assert_eq!(count, 1);
        assert_eq!(instrs[0].op, Op::Mov);
        assert_eq!(instrs[0].operands[1], Operand::Imm(0));
    }

    #[test]
    fn or_with_self_is_a_noop_and_is_removed() {
        let mut instrs = vec![binop(
            Op::Or,
            "eax",
            Operand::Reg(Register::Physical("eax".into())),
        )];
        assert_eq!(simplify_algebraic(&mut instrs), 1);
        assert!(instrs.is_empty());
    }

    #[test]
    fn double_negation_collapses() {
        let neg = |reg: &str| Instr {
            addr: 0,
            op: Op::Neg,
            operands: vec![Operand::Reg(Register::Physical(reg.into()))],
            target: None,
            fallthrough: None,
            native: String::new(),
        };
        let mut instrs = vec![neg("eax"), neg("eax")];
        assert_eq!(simplify_algebraic(&mut instrs), 1);
        assert!(instrs.is_empty());
    }

    #[test]
    fn constant_setcond_resolves_js_to_unconditional_jmp() {
        let mut block = Block {
            addr: 0,
            instrs: vec![
                Instr {
                    addr: 0,
                    op: Op::SetCond(Cond::Lt),
                    operands: vec![
                        Operand::Reg(Register::Temp(0)),
                        Operand::Imm(1),
                        Operand::Imm(2),
                    ],
                    target: None,
                    fallthrough: None,
                    native: String::new(),
                },
                Instr {
                    addr: 4,
                    op: Op::Js,
                    operands: vec![Operand::Reg(Register::Temp(0))],
                    target: Some(0x2000),
                    fallthrough: Some(0x2010),
                    native: String::new(),
                },
            ],
            jump: Some(0x2000),
            fail: Some(0x2010),
            targets: vec![],
        };

        let mut routine = Routine {
            entry: 0,
            name: "f".into(),
            blocks: vec![block.clone()],
        };
        let stats = optimize(&mut routine);
        assert!(stats.folded >= 1, "SetCond(1 < 2) should fold to true");
        assert!(stats.branches_resolved >= 1);
        block = routine.blocks.remove(0);
        let last = block.instrs.last().expect("block keeps its terminator");
        assert_eq!(last.op, Op::Jmp);
        assert_eq!(block.jump, Some(0x2000));
        assert_eq!(block.fail, None);
    }
}
