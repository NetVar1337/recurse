//! A minimal symbolic executor over the lifted IL — named after, and shaped
//! after, VTIL-Architecture's own `symex` (`tracer`/`variable`/`pointer`/
//! `memory`/`context`), the part of the real VTIL project this crate had not
//! attempted yet (`crates/recurse-vtil/src/opt.rs`'s propagation lattice only
//! ever tracks a register's value as *a literal or a copy of another
//! register* — never a general expression).
//!
//! Registers are tracked here as symbolic expression trees ([`Expr`])
//! instead. That resolves identities constant folding structurally cannot
//! see: an expression can simplify to a known-equal *form* even when none of
//! its inputs are ever literal on any path — `(a ^ b) ^ b` collapses to `a`
//! symbolically, which is exactly the double-XOR-with-the-same-key idiom RE
//! keeps running into, whether or not the key is ever a compile-time
//! constant — and still folds all the way to a literal exactly when
//! [`crate::opt`] would.
//!
//! # Scope, honestly
//!
//! - **Registers only.** A load ([`crate::il::Op::Ldd`]) always produces
//!   [`Expr::Unknown`] — this crate does not model memory contents or
//!   aliasing (see the note in `opt.rs`'s module doc), so nothing read from
//!   memory can ever be more than opaque input here. Moving that boundary is
//!   VTIL's own `pointer`/`memory` machinery, and future work for this
//!   crate too.
//! - **Every [`Expr::Unknown`] is a fresh, distinct value** (a monotonically
//!   increasing id, not tied to the introducing instruction's address) —
//!   *not* "the same unknown quantity as any other unknown". This is what
//!   keeps the simplifier sound: `unknown_a ^ unknown_a` (the *same* traced
//!   value, referenced twice) is legitimately `0`; `unknown_a ^ unknown_b`
//!   from two different loads is not, and never simplifies. See
//!   `tests::unrelated_unknowns_do_not_falsely_cancel` for the regression
//!   this guards.
//! - **Structural, not SMT-backed.** Simplification is a fixed, bottom-up
//!   rule set applied at construction time (a "smart constructor" —
//!   [`mk_bin`]/[`mk_un`] — so every [`Expr`] a caller ever sees is already
//!   simplified as far as these rules go). Nothing here searches for an
//!   equivalent form the way an e-graph or SMT solver would; see
//!   `docs/vtil-lift.md`'s Mixed Boolean-Arithmetic section for that honest
//!   line, which this module moves but does not erase — the `(a&b)|(a&!b)`
//!   rule below is one concrete, hand-written instance of the *general*
//!   case that section flagged as needing an e-graph pass, not that search
//!   itself.

use crate::cfg::Cfg;
use crate::il::{Cond, Instr, Op, Operand, Register, Routine};
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

/// A unary operator this tracer models.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnOp {
    Neg,
    Not,
}

/// A binary operator this tracer models. `Cmp(Cond)` is the relation a
/// `SetCond` produces (see [`crate::il::Op::SetCond`]) — a boolean-valued
/// (`0`/`1`) result, kept distinct from the arithmetic/bitwise family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Mul,
    Cmp(Cond),
}

impl BinOp {
    fn symbol(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::Shl => "<<",
            BinOp::Shr => ">>",
            BinOp::Sar => ">>a",
            BinOp::Mul => "*",
            BinOp::Cmp(_) => "cmp",
        }
    }
}

/// A symbolic value. Either resolved down to structure this tracer
/// understands, or [`Expr::Unknown`] — the sound "give up" case.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Expr {
    Const(i64),
    /// The value `reg` held at the routine's entry — a symbolic input, not
    /// (yet) any particular number. Two `Input`s of the same register are
    /// always equal: unlike [`Expr::Unknown`], this is a fixed (if unknown)
    /// quantity, so referencing it twice really is referencing the same
    /// value twice.
    Input(Register),
    Un(UnOp, Rc<Expr>),
    Bin(BinOp, Rc<Expr>, Rc<Expr>),
    /// Not modelled: a memory read, a call result, an opcode this crate does
    /// not lift (`Op::Vemit`), or anything else outside this tracer's scope.
    /// The id is fresh per introduction (see the module doc) — never reused,
    /// never meaningful beyond "is this literally the same traced value as
    /// that other one".
    Unknown(u64),
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Const(v) if *v < 0 => write!(f, "-0x{:x}", v.unsigned_abs()),
            Expr::Const(v) => write!(f, "0x{v:x}"),
            Expr::Input(r) => write!(f, "entry({r})"),
            Expr::Un(UnOp::Neg, x) => write!(f, "-({x})"),
            Expr::Un(UnOp::Not, x) => write!(f, "~({x})"),
            Expr::Bin(op, l, r) => write!(f, "({l} {} {r})", op.symbol()),
            Expr::Unknown(id) => write!(f, "unk#{id}"),
        }
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

/// Build `l op r`, applying every simplification rule this module knows
/// before handing back the result — so every [`Expr`] ever observed outside
/// this function is already in the simplest form these rules reach.
fn mk_bin(op: BinOp, l: Rc<Expr>, r: Rc<Expr>) -> Rc<Expr> {
    use BinOp::{Add, And, Mul, Or, Sar, Shl, Shr, Sub, Xor};
    use Expr::{Bin, Const};

    // Constant folding.
    if let (Const(a), Const(b)) = (l.as_ref(), r.as_ref()) {
        let v = match op {
            Add => a.wrapping_add(*b),
            Sub => a.wrapping_sub(*b),
            And => a & b,
            Or => a | b,
            Xor => a ^ b,
            Shl => a.wrapping_shl(*b as u32),
            Shr => ((*a as u64).wrapping_shr(*b as u32)) as i64,
            Sar => a.wrapping_shr(*b as u32),
            Mul => a.wrapping_mul(*b),
            BinOp::Cmp(cond) => i64::from(evaluate_cond(cond, *a, *b)),
        };
        return Rc::new(Const(v));
    }

    // Identity element / annihilator, against a literal right-hand side.
    if let Const(b) = r.as_ref() {
        match (op, *b) {
            (Add | Sub | Xor | Or | Shl | Shr | Sar, 0) => return l,
            (Mul, 1) => return l,
            (Mul, 0) | (And, 0) => return Rc::new(Const(0)),
            (And, -1) => return l,
            (Or, -1) => return Rc::new(Const(-1)),
            _ => {}
        }
    }

    // Idempotence / self-inverse, comparing operands structurally.
    if l == r {
        match op {
            Xor | Sub => return Rc::new(Const(0)),
            And | Or => return l,
            _ => {}
        }
    }

    // `(a OP b) OP' b` / `(a OP b) OP' a` — cancels a self-inverse binary op
    // applied twice with the same right-hand operand (XOR-with-key twice,
    // subtract-then-add-back, …), even when neither operand is a literal.
    if let Bin(inner_op, a, b) = l.as_ref() {
        if matches!((op, inner_op), (Xor, Xor) | (Add, Sub) | (Sub, Add))
            && b.as_ref() == r.as_ref()
        {
            return a.clone();
        }
        if op == Xor && *inner_op == Xor && a.as_ref() == r.as_ref() {
            return b.clone();
        }
    }

    // `(a & b) | (a & ~b)` (in either order) — the concrete distributive/
    // complement identity this module's doc points to as the one general
    // case it hand-implements rather than searches for.
    if op == Or {
        if let Some(a) = and_or_complement_and(&l, &r) {
            return a;
        }
    }

    Rc::new(Bin(op, l, r))
}

/// Recognise `(a & b) | (a & ~b)` for [`mk_bin`]'s `Or` case, trying both
/// operand orders and both placements of the complement.
fn and_or_complement_and(l: &Rc<Expr>, r: &Rc<Expr>) -> Option<Rc<Expr>> {
    let (Expr::Bin(BinOp::And, a1, b1), Expr::Bin(BinOp::And, a2, b2)) = (l.as_ref(), r.as_ref())
    else {
        return None;
    };
    let complements = |x: &Rc<Expr>, y: &Rc<Expr>| matches!(x.as_ref(), Expr::Un(UnOp::Not, inner) if inner.as_ref() == y.as_ref());
    if a1 == a2 && (complements(b1, b2) || complements(b2, b1)) {
        return Some(a1.clone());
    }
    if b1 == b2 && (complements(a1, a2) || complements(a2, a1)) {
        return Some(b1.clone());
    }
    None
}

/// Build `op x`, applying involution (`--a == a`, `~~a == a`) before
/// returning.
fn mk_un(op: UnOp, x: Rc<Expr>) -> Rc<Expr> {
    if let Expr::Un(inner, y) = x.as_ref() {
        if *inner == op {
            return y.clone();
        }
    }
    if let Expr::Const(v) = x.as_ref() {
        let folded = match op {
            UnOp::Neg => v.wrapping_neg(),
            UnOp::Not => !v,
        };
        return Rc::new(Expr::Const(folded));
    }
    Rc::new(Expr::Un(op, x))
}

/// The symbolic state ([`Expr`] per register) at the entry of every block in
/// a routine, after the whole-routine fixpoint.
#[derive(Clone, Debug, Default)]
pub struct SymbolicTrace {
    block_entry: HashMap<u64, HashMap<Register, Rc<Expr>>>,
}

impl SymbolicTrace {
    /// The traced expression for `reg` at the entry of the block at `addr`,
    /// if this tracer determined one. Absent means "not tracked here" —
    /// callers should treat that exactly like [`Expr::Unknown`], not as a
    /// stronger claim.
    pub fn at_block_entry(&self, addr: u64, reg: &Register) -> Option<&Rc<Expr>> {
        self.block_entry.get(&addr)?.get(reg)
    }
}

/// Trace `routine` over `cfg`: a forward worklist fixpoint carrying each
/// block's symbolic register state into its successors, merging (keeping a
/// register's expression only where every predecessor agrees on the exact
/// same [`Expr`]) at any block with more than one predecessor — the same
/// shape as [`crate::opt::propagate_and_fold_global`], generalized from
/// literal-or-copy facts to full expression trees.
pub fn trace(routine: &Routine, cfg: &Cfg) -> SymbolicTrace {
    let mut state_in: HashMap<u64, HashMap<Register, Rc<Expr>>> = HashMap::new();
    let mut state_out: HashMap<u64, HashMap<Register, Rc<Expr>>> = HashMap::new();
    let mut next_unknown_id: u64 = 0;

    let mut worklist: std::collections::VecDeque<u64> = cfg.order.iter().copied().collect();
    let mut dequeues = 0usize;
    let max_dequeues = cfg.order.len().saturating_mul(64).max(256);

    while let Some(addr) = worklist.pop_front() {
        dequeues += 1;
        if dequeues > max_dequeues {
            break;
        }

        let mut merged: Option<HashMap<Register, Rc<Expr>>> = None;
        for &p in cfg.predecessors(addr) {
            if let Some(pout) = state_out.get(&p) {
                merged = Some(match merged {
                    None => pout.clone(),
                    Some(existing) => meet(&existing, pout),
                });
            }
        }
        let in_state = merged.unwrap_or_default();

        if state_in.get(&addr) == Some(&in_state) && state_out.contains_key(&addr) {
            continue;
        }
        state_in.insert(addr, in_state.clone());

        let Some(block) = routine.blocks.iter().find(|b| b.addr == addr) else {
            continue;
        };
        let out_state = trace_block(&block.instrs, in_state, &mut next_unknown_id);

        let changed = state_out.get(&addr) != Some(&out_state);
        state_out.insert(addr, out_state);
        if changed {
            for &succ in cfg.successors(addr) {
                worklist.push_back(succ);
            }
        }
    }

    SymbolicTrace {
        block_entry: state_in,
    }
}

fn meet(
    a: &HashMap<Register, Rc<Expr>>,
    b: &HashMap<Register, Rc<Expr>>,
) -> HashMap<Register, Rc<Expr>> {
    let mut out = HashMap::new();
    for (k, v) in a {
        if b.get(k) == Some(v) {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

fn fresh(next_unknown_id: &mut u64) -> Rc<Expr> {
    let id = *next_unknown_id;
    *next_unknown_id += 1;
    Rc::new(Expr::Unknown(id))
}

/// The symbolic value of one already-lifted operand: a literal, the current
/// (or, if never written this block, the routine-entry) value of a
/// register, or — for a memory operand this tracer does not model — a
/// freshly minted [`Expr::Unknown`] (never a reused sentinel: see the
/// module doc on why that would be unsound).
fn value_of(
    regs: &HashMap<Register, Rc<Expr>>,
    operand: &Operand,
    next_unknown_id: &mut u64,
) -> Rc<Expr> {
    match operand {
        Operand::Imm(v) => Rc::new(Expr::Const(*v)),
        Operand::Reg(r) => regs
            .get(r)
            .cloned()
            .unwrap_or_else(|| Rc::new(Expr::Input(r.clone()))),
        Operand::Mem(_) => fresh(next_unknown_id),
    }
}

fn to_binop(op: &Op) -> Option<BinOp> {
    Some(match op {
        Op::Add => BinOp::Add,
        Op::Sub => BinOp::Sub,
        Op::And => BinOp::And,
        Op::Or => BinOp::Or,
        Op::Xor => BinOp::Xor,
        Op::Shl => BinOp::Shl,
        Op::Shr => BinOp::Shr,
        Op::Sar => BinOp::Sar,
        Op::Mul | Op::IMul => BinOp::Mul,
        _ => return None,
    })
}

/// Symbolically execute one block's instructions forward from `regs`,
/// returning the resulting register state. `next_unknown_id` is threaded
/// through so every fresh [`Expr::Unknown`] introduced (by a load, an
/// external call, or any opcode this crate does not lift) gets its own id.
fn trace_block(
    instrs: &[Instr],
    mut regs: HashMap<Register, Rc<Expr>>,
    next_unknown_id: &mut u64,
) -> HashMap<Register, Rc<Expr>> {
    for instr in instrs {
        if matches!(instr.op, Op::Vemit | Op::Vxcall) {
            // Unknown reads/writes: nothing carried forward can be trusted.
            regs.clear();
            continue;
        }

        let dst = match instr.written() {
            Some(Operand::Reg(r)) => Some(r.clone()),
            _ => None,
        };
        let Some(dst) = dst else {
            continue;
        };

        let new_value = match &instr.op {
            Op::Mov => match instr.operands.get(1) {
                Some(op @ (Operand::Imm(_) | Operand::Reg(_))) => {
                    Some(value_of(&regs, op, next_unknown_id))
                }
                _ => None,
            },
            Op::Ldd | Op::Movsx | Op::Lea => Some(fresh(next_unknown_id)),
            Op::Neg => instr
                .operands
                .first()
                .map(|op| mk_un(UnOp::Neg, value_of(&regs, op, next_unknown_id))),
            Op::Not => instr
                .operands
                .first()
                .map(|op| mk_un(UnOp::Not, value_of(&regs, op, next_unknown_id))),
            Op::Add
            | Op::Sub
            | Op::And
            | Op::Or
            | Op::Xor
            | Op::Shl
            | Op::Shr
            | Op::Sar
            | Op::Mul
            | Op::IMul => {
                match (
                    instr.operands.first(),
                    instr.operands.get(1),
                    to_binop(&instr.op),
                ) {
                    (Some(a), Some(b), Some(op)) => {
                        let av = value_of(&regs, a, next_unknown_id);
                        let bv = value_of(&regs, b, next_unknown_id);
                        Some(mk_bin(op, av, bv))
                    }
                    _ => Some(fresh(next_unknown_id)),
                }
            }
            Op::SetCond(cond) => match (instr.operands.get(1), instr.operands.get(2)) {
                (Some(a), Some(b)) => {
                    let av = value_of(&regs, a, next_unknown_id);
                    let bv = value_of(&regs, b, next_unknown_id);
                    Some(mk_bin(BinOp::Cmp(*cond), av, bv))
                }
                _ => Some(fresh(next_unknown_id)),
            },
            _ => Some(fresh(next_unknown_id)),
        };

        match new_value {
            Some(v) => {
                regs.insert(dst, v);
            }
            None => {
                regs.remove(&dst);
            }
        }
    }

    regs
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::il::Block;

    fn binop(addr: u64, op: Op, dst: &str, rhs: Operand) -> Instr {
        Instr {
            addr,
            op,
            operands: vec![Operand::Reg(Register::Physical(dst.into())), rhs],
            target: None,
            fallthrough: None,
            native: String::new(),
        }
    }

    fn reg(name: &str) -> Operand {
        Operand::Reg(Register::Physical(name.into()))
    }

    #[test]
    fn xor_with_same_symbolic_key_twice_cancels() {
        // eax = eax ^ ebx ; eax = eax ^ ebx  ->  eax == entry(eax)
        let instrs = vec![
            binop(0x1000, Op::Xor, "eax", reg("ebx")),
            binop(0x1004, Op::Xor, "eax", reg("ebx")),
        ];
        let mut next = 0u64;
        let out = trace_block(&instrs, HashMap::new(), &mut next);
        let eax = out
            .get(&Register::Physical("eax".into()))
            .expect("eax tracked");
        assert_eq!(**eax, Expr::Input(Register::Physical("eax".into())));
    }

    #[test]
    fn subtract_then_add_back_cancels() {
        let instrs = vec![
            binop(0x1000, Op::Sub, "eax", reg("ebx")),
            binop(0x1004, Op::Add, "eax", reg("ebx")),
        ];
        let mut next = 0u64;
        let out = trace_block(&instrs, HashMap::new(), &mut next);
        let eax = out
            .get(&Register::Physical("eax".into()))
            .expect("eax tracked");
        assert_eq!(**eax, Expr::Input(Register::Physical("eax".into())));
    }

    #[test]
    fn and_or_complement_collapses_to_the_shared_operand() {
        // (a & b) | (a & ~b)  ->  a
        let a = Rc::new(Expr::Input(Register::Physical("eax".into())));
        let b = Rc::new(Expr::Input(Register::Physical("ebx".into())));
        let not_b = mk_un(UnOp::Not, b.clone());
        let left = mk_bin(BinOp::And, a.clone(), b);
        let right = mk_bin(BinOp::And, a.clone(), not_b);
        let combined = mk_bin(BinOp::Or, left, right);
        assert_eq!(combined, a);
    }

    #[test]
    fn unrelated_unknowns_do_not_falsely_cancel() {
        // eax = [rbx] (a load: fresh unknown) ; ecx = [rbx] (a *different*
        // load, its own fresh unknown, even though the memory text repeats)
        // ; eax = eax ^ ecx must NOT fold to 0.
        let ldd = |addr: u64, dst: &str| Instr {
            addr,
            op: Op::Ldd,
            operands: vec![
                Operand::Reg(Register::Physical(dst.into())),
                Operand::Mem("[rbx]".into()),
            ],
            target: None,
            fallthrough: None,
            native: String::new(),
        };
        let instrs = vec![
            ldd(0x1000, "eax"),
            ldd(0x1004, "ecx"),
            binop(0x1008, Op::Xor, "eax", reg("ecx")),
        ];
        let mut next = 0u64;
        let out = trace_block(&instrs, HashMap::new(), &mut next);
        let eax = out
            .get(&Register::Physical("eax".into()))
            .expect("eax tracked");
        assert_ne!(
            **eax,
            Expr::Const(0),
            "two different loads must not be treated as the same unknown"
        );
        assert!(matches!(eax.as_ref(), Expr::Bin(BinOp::Xor, _, _)));
    }

    #[test]
    fn setcond_of_two_known_constants_folds_through_mk_bin() {
        let a = Rc::new(Expr::Const(5));
        let b = Rc::new(Expr::Const(5));
        let cmp = mk_bin(BinOp::Cmp(Cond::Eq), a, b);
        assert_eq!(*cmp, Expr::Const(1));
    }

    #[test]
    fn whole_routine_trace_carries_an_expression_across_an_unrelated_block() {
        // B0: ecx = ecx ^ eax ; jmp B1
        // B1 (passthrough, mentions nothing tracked): jmp B2
        // B2: entry state should show ecx == entry(ecx) ^ entry(eax).
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![
                Block {
                    addr: 0x1000,
                    instrs: vec![binop(0x1000, Op::Xor, "ecx", reg("eax"))],
                    jump: Some(0x1010),
                    fail: None,
                    targets: vec![],
                },
                Block {
                    addr: 0x1010,
                    instrs: vec![],
                    jump: Some(0x1020),
                    fail: None,
                    targets: vec![],
                },
                Block {
                    addr: 0x1020,
                    instrs: vec![binop(0x1020, Op::Xor, "ecx", reg("eax"))],
                    jump: None,
                    fail: None,
                    targets: vec![],
                },
            ],
        };
        let cfg = Cfg::build(&routine);
        let trace_result = trace(&routine, &cfg);
        let entry_ecx = trace_result
            .at_block_entry(0x1020, &Register::Physical("ecx".into()))
            .expect("ecx reaches B2's entry");
        assert_eq!(
            **entry_ecx,
            Expr::Bin(
                BinOp::Xor,
                Rc::new(Expr::Input(Register::Physical("ecx".into()))),
                Rc::new(Expr::Input(Register::Physical("eax".into())))
            )
        );
    }
}
