//! The VTIL-inspired intermediate language: registers, operands, opcodes,
//! instructions, basic blocks, and routines.
//!
//! Naming follows [VTIL-Architecture's `instruction_set.hpp`][vtil-isa] where
//! a semantic matches exactly (`mov`, `movsx`, `str`, `ldd`, `neg`, `add`,
//! `sub`, `mul`, `imul`, `div`, `idiv`, `popcnt`, `bsf`, `bsr`, `not`, `shr`,
//! `shl`, `xor`, `or`, `and`, `ror`, `rol`, the `t*` relational family, `js`,
//! `jmp`, `vexit`, `vxcall`, `nop`, `vemit`). A handful of opcodes are
//! extensions this crate adds to cover cases upstream VTIL's public
//! instruction set does not model on its own (`lea`, `movzx`, `sar`, and the
//! not-yet-raised `jcc`) — each is called out at its definition. VTIL-Core
//! ships the IR, its optimizer, and a symbolic VM, but not the x86-to-VTIL
//! lifter itself (never open-sourced); [`crate::lift`] is an independent,
//! from-scratch implementation of that missing half, built on Recurse's own
//! backend-neutral disassembly instead of Capstone details directly, so it
//! works unchanged against every [`Engine`](recurse_static) implementation.
//!
//! [vtil-isa]: https://github.com/vtil-project/VTIL-Core/blob/master/VTIL-Architecture/arch/instruction_set.hpp

use serde::{Deserialize, Serialize};
use std::fmt;

/// A register reference in the IL. VTIL keeps the native ISA's physical
/// registers addressable directly rather than abstracting them into an
/// infinite SSA register file — this lifter does the same, and only
/// introduces a virtual temporary ([`Register::Temp`]) for values the native
/// disassembly does not name (recovered condition-code predicates).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Register {
    /// A native register, addressed by its disassembler-printed name
    /// (`"rax"`, `"eax"`, `"w0"`, …), lowercased.
    Physical(String),
    /// A lifter-introduced temporary (`t0`, `t1`, …), currently used only to
    /// hold the recovered value of a relational (`t*`) instruction that feeds
    /// a `js`.
    Temp(u32),
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Register::Physical(name) => f.write_str(name),
            Register::Temp(n) => write!(f, "t{n}"),
        }
    }
}

/// One operand of an IL instruction — VTIL's `operand_type` collapses to
/// three cases once a concrete value is known: a register, an immediate, or
/// (for `ldd`/`str`) a native memory expression.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Operand {
    Reg(Register),
    Imm(i64),
    /// An unparsed native memory expression (`"[rax + rbx*4 + 0x10]"`,
    /// stripped of its size prefix). VTIL represents memory access as
    /// `ldd`/`str` against a symbolic pointer expression built by its
    /// `symex` layer; recovering base/index/scale/segment into that same
    /// representation is future work; this crate keeps the pointer text
    /// verbatim instead of dropping it.
    Mem(String),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Reg(r) => write!(f, "{r}"),
            Operand::Imm(v) if *v < 0 => write!(f, "-0x{:x}", v.unsigned_abs()),
            Operand::Imm(v) => write!(f, "0x{v:x}"),
            Operand::Mem(text) => f.write_str(text),
        }
    }
}

/// A relational condition, recovered from an x86 `Jcc` mnemonic suffix and
/// the comparison that feeds it. Named after VTIL's `t*` instruction family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Cond {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    UGt,
    UGe,
    ULt,
    ULe,
}

impl Cond {
    /// The upstream VTIL mnemonic for this relation (`te`, `tne`, `tg`, …).
    pub fn vtil_mnemonic(self) -> &'static str {
        match self {
            Cond::Eq => "te",
            Cond::Ne => "tne",
            Cond::Gt => "tg",
            Cond::Ge => "tge",
            Cond::Lt => "tl",
            Cond::Le => "tle",
            Cond::UGt => "tug",
            Cond::UGe => "tuge",
            Cond::ULt => "tul",
            Cond::ULe => "tule",
        }
    }

    /// Recover the condition an x86 `Jcc` mnemonic tests. `None` for
    /// mnemonics that test a flag this crate does not model as a relation
    /// (parity, overflow, sign alone, `jcxz`/`jecxz`/`jrcxz`) — those stay
    /// unlifted (`Op::Vemit`) rather than risk a wrong semantic.
    pub fn from_jcc(mnemonic: &str) -> Option<Self> {
        let stem = mnemonic.strip_prefix('j')?;
        Some(match stem {
            "e" | "z" => Cond::Eq,
            "ne" | "nz" => Cond::Ne,
            "g" | "nle" => Cond::Gt,
            "ge" | "nl" => Cond::Ge,
            "l" | "nge" => Cond::Lt,
            "le" | "ng" => Cond::Le,
            "a" | "nbe" => Cond::UGt,
            "ae" | "nb" | "nc" => Cond::UGe,
            "b" | "nae" | "c" => Cond::ULt,
            "be" | "na" => Cond::ULe,
            _ => return None,
        })
    }

    /// The logical negation of this condition (used to swap a `js`'s taken
    /// and fall-through targets during simplification).
    pub fn negate(self) -> Self {
        match self {
            Cond::Eq => Cond::Ne,
            Cond::Ne => Cond::Eq,
            Cond::Gt => Cond::Le,
            Cond::Ge => Cond::Lt,
            Cond::Lt => Cond::Ge,
            Cond::Le => Cond::Gt,
            Cond::UGt => Cond::ULe,
            Cond::UGe => Cond::ULt,
            Cond::ULt => Cond::UGe,
            Cond::ULe => Cond::UGt,
        }
    }
}

/// IL opcodes. See the module docs for the mapping to VTIL-Architecture's
/// public instruction set; opcodes marked "extension" have no upstream VTIL
/// counterpart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Op {
    // -- Data / memory (VTIL: mov, movsx, str, ldd) --
    Mov,
    Movsx,
    /// Extension: x86 zero-extending move (`movzx`). Upstream VTIL's `mov`
    /// is defined as `OP1 = ZX(OP2)` (zero-extend), so a native `movzx`
    /// lifts to plain [`Op::Mov`]; this variant exists only so the lifter
    /// can record that the *native* instruction was `movzx` for `vemit`
    /// fallback and diagnostics.
    Movzx,
    /// Extension: address computation (`lea`). VTIL does not compute
    /// addresses as a value-producing instruction of its own; recovering one
    /// requires the pointer-expression modelling `ldd`/`str` already need
    /// (see [`Operand::Mem`]).
    Lea,
    Ldd,
    Str,

    // -- Arithmetic (VTIL: neg, add, sub, mul, imul, div, idiv) --
    Neg,
    Add,
    Sub,
    Mul,
    IMul,
    Div,
    IDiv,

    // -- Bitwise (VTIL: popcnt, bsf, bsr, not, shr, shl, xor, or, and, ror, rol) --
    Popcnt,
    Bsf,
    Bsr,
    Not,
    Shr,
    Shl,
    /// Extension: arithmetic (sign-preserving) right shift. Upstream VTIL's
    /// public instruction set has one shift-right opcode; it disambiguates
    /// signedness through its symbolic value types rather than a second
    /// opcode.
    Sar,
    Xor,
    Or,
    And,
    Ror,
    Rol,

    // -- Conditional (VTIL: tg, tge, te, tne, tle, tl, tug, tuge, tule, tul) --
    SetCond(Cond),

    // -- Control flow (VTIL: js, jmp, vexit, vxcall) --
    /// `js cond_reg` — branch, both edges known ([`Instr::target`] taken,
    /// [`Instr::fallthrough`] not-taken); mirrors VTIL's
    /// `JS Reg, Reg/Imm, Reg/Imm`.
    Js,
    Jmp,
    Vexit,
    Vxcall,
    /// Extension: a conditional branch whose flag producer this lifter did
    /// not recognise (so it could not raise the pair to `SetCond` + `Js`).
    /// Total-but-honest: the condition is recorded, but evaluating it
    /// requires the native flags this IL does not model.
    Jcc(Cond),

    // -- Special (VTIL: nop, vemit) --
    Nop,
    /// A native instruction embedded verbatim because this lifter does not
    /// (yet) give it a semantic — VTIL's own escape hatch for keeping
    /// translation total. [`Instr::native`] is authoritative for this op.
    Vemit,
}

impl Op {
    /// The upstream-or-extension mnemonic, as printed by [`crate::text`].
    pub fn mnemonic(&self) -> String {
        match self {
            Op::Mov => "mov".into(),
            Op::Movsx => "movsx".into(),
            Op::Movzx => "movzx".into(),
            Op::Lea => "lea".into(),
            Op::Ldd => "ldd".into(),
            Op::Str => "str".into(),
            Op::Neg => "neg".into(),
            Op::Add => "add".into(),
            Op::Sub => "sub".into(),
            Op::Mul => "mul".into(),
            Op::IMul => "imul".into(),
            Op::Div => "div".into(),
            Op::IDiv => "idiv".into(),
            Op::Popcnt => "popcnt".into(),
            Op::Bsf => "bsf".into(),
            Op::Bsr => "bsr".into(),
            Op::Not => "not".into(),
            Op::Shr => "shr".into(),
            Op::Shl => "shl".into(),
            Op::Sar => "sar".into(),
            Op::Xor => "xor".into(),
            Op::Or => "or".into(),
            Op::And => "and".into(),
            Op::Ror => "ror".into(),
            Op::Rol => "rol".into(),
            Op::SetCond(c) => c.vtil_mnemonic().into(),
            Op::Js => "js".into(),
            Op::Jmp => "jmp".into(),
            Op::Vexit => "vexit".into(),
            Op::Vxcall => "vxcall".into(),
            Op::Jcc(c) => format!("jcc.{}", c.vtil_mnemonic()),
            Op::Nop => "nop".into(),
            Op::Vemit => "vemit".into(),
        }
    }

    /// True when operand 0 is written (VTIL's `write`/`readwrite` operand
    /// types) — the value [`crate::opt`] tracks for copy propagation and
    /// dead-code elimination.
    pub fn writes_operand0(&self) -> bool {
        matches!(
            self,
            Op::Mov
                | Op::Movsx
                | Op::Movzx
                | Op::Lea
                | Op::Ldd
                | Op::Neg
                | Op::Add
                | Op::Sub
                | Op::Mul
                | Op::IMul
                | Op::Div
                | Op::IDiv
                | Op::Popcnt
                | Op::Bsf
                | Op::Bsr
                | Op::Not
                | Op::Shr
                | Op::Shl
                | Op::Sar
                | Op::Xor
                | Op::Or
                | Op::And
                | Op::Ror
                | Op::Rol
                | Op::SetCond(_)
        )
    }

    /// True when operand 0 must also be read before the write (x86's
    /// destructive two-address form, VTIL's `readwrite` operand type) —
    /// `dst = dst OP rhs`, as opposed to a pure write like `mov`/`ldd`.
    pub fn reads_operand0(&self) -> bool {
        matches!(
            self,
            Op::Neg
                | Op::Add
                | Op::Sub
                | Op::Mul
                | Op::IMul
                | Op::Div
                | Op::IDiv
                | Op::Popcnt
                | Op::Bsf
                | Op::Bsr
                | Op::Not
                | Op::Shr
                | Op::Shl
                | Op::Sar
                | Op::Xor
                | Op::Or
                | Op::And
                | Op::Ror
                | Op::Rol
        )
    }

    /// True when the instruction must never be dropped by dead-code
    /// elimination even if its written operand looks unused (control flow,
    /// memory stores, and anything not semantically modelled).
    pub fn has_side_effect(&self) -> bool {
        matches!(
            self,
            Op::Str | Op::Js | Op::Jmp | Op::Vexit | Op::Vxcall | Op::Jcc(_) | Op::Nop | Op::Vemit
        )
    }
}

/// One IL instruction. Follows VTIL's own restriction of at most three
/// operands (`OP1`/`OP2`/`OP3`), kept here as a plain `Vec` rather than a
/// fixed array so extension opcodes are not forced into it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Instr {
    /// Address of the native instruction this IL instruction was lifted
    /// from (or, after optimization, the address of whichever instruction
    /// contributed it).
    pub addr: u64,
    pub op: Op,
    pub operands: Vec<Operand>,
    /// Taken branch target (`jmp`, `vxcall`, unconditional `js` taken edge),
    /// when statically known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    /// Not-taken / fall-through edge (`js`, `jcc`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallthrough: Option<u64>,
    /// The original disassembly text this instruction was lifted from —
    /// always kept (not just for `vemit`) so the VTIL-style dump stays
    /// traceable back to the native listing.
    pub native: String,
}

impl Instr {
    /// The operand written by this instruction, if any (see
    /// [`Op::writes_operand0`]).
    pub fn written(&self) -> Option<&Operand> {
        if self.op.writes_operand0() {
            self.operands.first()
        } else {
            None
        }
    }

    /// Registers this instruction reads, in VTIL's `read_any`/`read_reg`
    /// sense (excludes a pure `write`-only destination, includes a
    /// `readwrite` destination since it is read before being overwritten).
    pub fn read_registers(&self) -> Vec<&Register> {
        let mut out = Vec::new();
        let start = if self.op.writes_operand0() && !self.op.reads_operand0() {
            1
        } else {
            0
        };
        for operand in self.operands.iter().skip(start) {
            if let Operand::Reg(r) = operand {
                out.push(r);
            }
        }
        out
    }
}

/// One basic block of lifted instructions plus its recovered control-flow
/// edges — mirrors [`recurse_static::engine::BasicBlock`]'s shape (native
/// name kept distinct so this crate never needs `recurse-static` as a
/// dependency; see [`crate::input`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub addr: u64,
    pub instrs: Vec<Instr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<u64>,
}

/// A lifted routine: one function's worth of [`Block`]s, addressed by their
/// native entry address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Routine {
    pub entry: u64,
    pub name: String,
    pub blocks: Vec<Block>,
}

impl Routine {
    /// Total instruction count across every block.
    pub fn instr_count(&self) -> usize {
        self.blocks.iter().map(|b| b.instrs.len()).sum()
    }
}
