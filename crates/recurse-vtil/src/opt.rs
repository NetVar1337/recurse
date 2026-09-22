//! Optimizer passes over the lifted IL, run to a whole-routine fixpoint.
//!
//! Named after (and scoped-down from) VTIL-Core's and vtil2's optimizer
//! pipeline: `MovPropagationPass`/`CollectivePropagationPass` →
//! [`propagate_and_fold_global`], `DeadCodeEliminationPass` → the
//! [`crate::liveness`]-driven [`eliminate_dead_stores_with_live_out`],
//! `SymbolicRewritePass` → [`simplify_algebraic`], `BranchCorrectionPass` →
//! [`resolve_constant_branches`].
//!
//! Propagation/folding and dead-store elimination now see the whole
//! [`Routine`]'s [`crate::cfg::Cfg`], not just one block: constant/copy
//! facts flow forward across edges (merged — kept only where every
//! predecessor agrees — at a join point, so a value known on every path
//! into a block is still known inside it, standard forward "must" dataflow),
//! and a register write that reaches a block's end is deleted when
//! whole-routine liveness ([`crate::liveness::compute_live_out`]) proves no
//! successor can read it. That is what makes the `lift` op's devirtualizing
//! use case (a VM dispatcher's opcode fetch/compare chain, almost never
//! confined to one block) actually resolvable end to end — the block-local
//! versions of both passes ([`propagate_and_fold`], [`eliminate_dead_stores`])
//! are kept as the conservative, CFG-free primitives the whole-routine
//! passes are built from, and stay usable on their own (and covered by their
//! own tests) for exactly that reason.
//!
//! The honest scope line has moved, not disappeared: this is a real
//! multi-block dataflow fixpoint, but still not VTIL's own symbolic
//! executor (`VTIL-Architecture/symex`) — it tracks *known-constant*
//! register values, never a general expression, never memory (`Ldd`/`Str`
//! are opaque reads/writes to this pass), and never resolves a computed
//! jump/call target. Building a real symbolic tracer over this same
//! [`crate::cfg::Cfg`] is the natural next step.

use crate::cfg::Cfg;
use crate::il::{Block, Cond, Instr, Op, Operand, Register, Routine};
use crate::liveness;
use crate::regalias;
use std::collections::{HashMap, HashSet};

/// Counts of what each round of [`optimize`] actually changed, returned so a
/// caller (or the `analyze` tool's `lift` op) can report whether
/// optimization did anything rather than silently no-op.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct OptStats {
    /// Whole-routine fixpoint rounds run (mostly diagnostic).
    pub rounds: usize,
    /// Register reads rewritten to a known constant or copy source.
    pub propagated: usize,
    /// Instructions whose result was resolved to a literal at compile time
    /// and rewritten to `mov`.
    pub folded: usize,
    /// Instructions simplified or removed by an algebraic identity.
    pub simplified: usize,
    /// Register writes removed because whole-routine liveness proved no
    /// later instruction — in this block or any reachable successor — could
    /// still read the value.
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

/// Hard cap on whole-routine fixpoint rounds. Each round strictly reduces or
/// resolves something counted in [`OptStats::total`], so this bounds
/// pathological input rather than being expected to bind in practice.
const MAX_ROUNDS: usize = 64;

/// Run every pass over `routine`, in place, to a fixpoint. Rebuilds the
/// [`Cfg`] every round, since [`resolve_constant_branches`] can change edges
/// (a devirtualized branch loses one successor), which in turn changes what
/// the next round's propagation/liveness sees.
pub fn optimize(routine: &mut Routine) -> OptStats {
    let mut total = OptStats::default();
    loop {
        let cfg = Cfg::build(routine);
        let mut round = OptStats::default();

        let (propagated, folded) = propagate_and_fold_global(routine, &cfg);
        round.propagated = propagated;
        round.folded = folded;

        let live_out = liveness::compute_live_out(routine, &cfg);
        let empty = HashSet::new();
        for block in &mut routine.blocks {
            round.simplified += simplify_algebraic(&mut block.instrs);
            let lo = live_out.get(&block.addr).unwrap_or(&empty);
            round.dead_stores_removed += eliminate_dead_stores_with_live_out(&mut block.instrs, lo);
        }
        for block in &mut routine.blocks {
            round.branches_resolved += resolve_constant_branches(block);
        }

        total.add(&round);
        total.rounds += 1;
        if round.total() == 0 || total.rounds >= MAX_ROUNDS {
            break;
        }
    }
    total
}

/// A statically-known register value, tracked forward through the routine.
#[derive(Clone, Debug, PartialEq)]
enum Known {
    Const(i64),
    /// This register currently holds the same value as `Register`, which
    /// was not itself a known constant at the time of the copy.
    Copy(Register),
}

/// VTIL-style copy/constant propagation plus constant folding, in one
/// forward pass over one block. Mirrors VTIL's `MovPropagationPass`
/// (propagate a `mov`'s source into later reads) composed with its
/// `CollectivePropagationPass` (fold once every operand of an instruction is
/// a literal): here both happen per instruction so a folded `mov` is
/// immediately available to propagate into whatever reads it next.
///
/// Block-local: starts from no assumptions and reports nothing about what
/// held at block entry. [`propagate_and_fold_global`] is the whole-routine
/// driver built on the same per-block step ([`propagate_and_fold_seeded`]),
/// seeded from what is known on *every* path into the block instead of
/// nothing; this block-local entry point is kept for callers (and tests)
/// that only have one block and no [`Cfg`] to give it context from.
pub fn propagate_and_fold(instrs: &mut [Instr]) -> (usize, usize) {
    let (propagated, folded, _out) = propagate_and_fold_seeded(instrs, HashMap::new());
    (propagated, folded)
}

/// The same forward pass as [`propagate_and_fold`], but starting from
/// `known` (typically the meet of every predecessor block's exit state) and
/// returning the resulting exit state alongside the change counts, so a
/// whole-routine caller can carry it into successor blocks.
///
/// Any instruction this crate does not understand the write set of
/// (`Op::Vemit`, `Op::Vxcall` — an opaque native instruction or an external
/// call, either of which may touch registers this IL never sees mentioned)
/// clears everything tracked so far, including whatever was seeded in, since
/// nothing propagated past it could be trusted.
fn propagate_and_fold_seeded(
    instrs: &mut [Instr],
    mut known: HashMap<Register, Known>,
) -> (usize, usize, HashMap<Register, Known>) {
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

    (propagated, folded, known)
}

/// The meet of two predecessor exit states for the forward "must" lattice
/// this pass uses: a fact survives into a join point only if every
/// predecessor processed so far agrees on it exactly. Anything either side
/// doesn't have (not yet computed, or genuinely unknown there) drops out —
/// silently correct, never a false fact.
fn meet(a: &HashMap<Register, Known>, b: &HashMap<Register, Known>) -> HashMap<Register, Known> {
    let mut out = HashMap::new();
    for (k, v) in a {
        if b.get(k) == Some(v) {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

/// Whole-routine driver for [`propagate_and_fold_seeded`]: a forward
/// worklist fixpoint over `cfg`, carrying each block's known-constant/copy
/// state into its successors and merging ([`meet`]) at any block with more
/// than one predecessor. A predecessor not processed yet simply doesn't
/// contribute to the merge (treated as "no constraint yet"); the block is
/// reprocessed — and the merge redone with fresh input — the first time that
/// predecessor's own exit state becomes available, so nothing is missed.
/// Terminates because each register's tracked fact can only be dropped by a
/// merge, never re-introduced once two predecessors disagree on it.
///
/// Deliberately **two phases**, not one: phase 1 converges every block's
/// `known_in` *without* touching `routine` (each visit re-runs
/// [`propagate_and_fold_seeded`] over a throwaway clone of the block's
/// instructions, keeping only the resulting state); phase 2 rewrites each
/// block exactly once, from its final, fully-converged `known_in`. Folding
/// destructively *during* the fixpoint — mutating an instruction from a
/// visit whose `known_in` a later, correctly-widened visit would have
/// disagreed with — is unsound across a loop: the first visit to a loop
/// header sees only the entry edge (the back edge's predecessor state does
/// not exist yet), so a loop-carried value looks constant for exactly one
/// premature pass. If that pass is allowed to rewrite `add ecx, 1` down to
/// `mov ecx, 1`, the increment is gone — a later, correctly widened
/// (`ecx` no longer known-constant) visit has no way to recover it, because
/// the instruction it needed is no longer there. Keeping analysis
/// non-destructive until the whole routine has converged is what makes the
/// single, final rewrite pass sound.
fn propagate_and_fold_global(routine: &mut Routine, cfg: &Cfg) -> (usize, usize) {
    let mut known_in: HashMap<u64, HashMap<Register, Known>> = HashMap::new();
    let mut known_out: HashMap<u64, HashMap<Register, Known>> = HashMap::new();

    let mut worklist: std::collections::VecDeque<u64> = cfg.order.iter().copied().collect();
    let mut dequeues = 0usize;
    let max_dequeues = cfg.order.len().saturating_mul(64).max(256);

    // Phase 1: converge `known_in`/`known_out` for every block. Reads
    // `routine` only (a scratch clone absorbs the transfer function's
    // would-be edits), never writes it.
    while let Some(addr) = worklist.pop_front() {
        dequeues += 1;
        if dequeues > max_dequeues {
            break;
        }

        let preds = cfg.predecessors(addr);
        let mut merged: Option<HashMap<Register, Known>> = None;
        for &p in preds {
            if let Some(pout) = known_out.get(&p) {
                merged = Some(match merged {
                    None => pout.clone(),
                    Some(existing) => meet(&existing, pout),
                });
            }
        }
        let in_state = merged.unwrap_or_default();

        if known_in.get(&addr) == Some(&in_state) && known_out.contains_key(&addr) {
            // Nothing changed since the last time this block ran; its exit
            // state (and everything downstream of it) is already accounted
            // for.
            continue;
        }
        known_in.insert(addr, in_state.clone());

        let Some(block) = routine.blocks.iter().find(|b| b.addr == addr) else {
            continue;
        };
        let mut scratch = block.instrs.clone();
        let (_, _, out_state) = propagate_and_fold_seeded(&mut scratch, in_state);

        let changed_out = known_out.get(&addr) != Some(&out_state);
        known_out.insert(addr, out_state);
        if changed_out {
            for &succ in cfg.successors(addr) {
                worklist.push_back(succ);
            }
        }
    }

    // Phase 2: one real rewrite pass per block, from its converged
    // known_in — the facts are now the true meet over every path
    // (including any loop's back edge), so this application cannot later
    // be invalidated the way an intra-fixpoint one could.
    let mut propagated = 0usize;
    let mut folded = 0usize;
    for block in &mut routine.blocks {
        let in_state = known_in.get(&block.addr).cloned().unwrap_or_default();
        let (p, f, _) = propagate_and_fold_seeded(&mut block.instrs, in_state);
        propagated += p;
        folded += f;
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
/// earlier write is unobservable and safe to delete. `Op::Vemit`/
/// `Op::Vxcall` clear everything tracked so far, for the same "may
/// read/write anything" reason as in [`propagate_and_fold`].
///
/// Kept, alongside [`eliminate_dead_stores_with_live_out`], as the
/// conservative primitive for a caller with no [`Cfg`]: with no whole-
/// routine liveness available, a write reaching the block's end is always
/// assumed observable (never deleted) rather than guessed at.
pub fn eliminate_dead_stores(instrs: &mut Vec<Instr>) -> usize {
    eliminate_dead_stores_scoped(instrs, None)
}

/// The same pass, but additionally deleting a write that reaches the
/// block's end when `live_out` (from [`crate::liveness::compute_live_out`])
/// proves no successor can still read it — the whole-routine half of VTIL's
/// `DeadCodeEliminationPass` this crate did not have before. `live_out`
/// entries are compared under [`regalias::canonical`] identity, matching how
/// they were computed.
fn eliminate_dead_stores_with_live_out(
    instrs: &mut Vec<Instr>,
    live_out: &HashSet<Register>,
) -> usize {
    eliminate_dead_stores_scoped(instrs, Some(live_out))
}

fn eliminate_dead_stores_scoped(
    instrs: &mut Vec<Instr>,
    live_out: Option<&HashSet<Register>>,
) -> usize {
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

    // Anything still pending at block end is unread *within this block*.
    // With whole-routine liveness available, it is only actually dead when
    // no successor can read it either; without it (block-local callers),
    // conservatively assume it might still be needed.
    for (reg, &idx) in &last_write {
        let still_needed = match live_out {
            Some(set) => set.contains(&regalias::canonical(reg)),
            None => true,
        };
        if !still_needed {
            dead[idx] = true;
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
