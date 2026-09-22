//! Lift backend-neutral disassembly ([`crate::input`]) into the VTIL-inspired
//! IL ([`crate::il`]).
//!
//! The lifter works from the canonical `"mnemonic operand, operand"` text
//! every [`Engine`](recurse_static) already produces (comments stripped)
//! rather than from Capstone instruction details, so it runs unchanged
//! against the native backend or r2. Control-flow shape (`jmp`/`cjmp`/`call`/
//! `ret`) comes from the backend-neutral `kind` classification and is
//! therefore correct for every architecture Capstone covers; the mnemonic
//! dispatch below that recovers *data* semantics targets x86/x86-64.
//! Anything it does not recognise — another architecture's mnemonics, or an
//! x86 instruction this lifter has not modelled yet (`adc`, `sbb`, `xchg`,
//! `cmov*`, `set*`, SIMD, …) — becomes [`Op::Vemit`]: the translation stays
//! total, and the original text is always kept on [`Instr::native`].

use crate::il::{Block, Cond, Instr, Op, Operand, Register, Routine};
use crate::input::{InputBlock, InputInsn};

/// Lift every block of a function into a [`Routine`]. Block order, addresses,
/// and edges (`jump`/`fail`/`targets`) are carried through unchanged; only
/// the instruction stream inside each block is translated.
pub fn lift_routine(entry: u64, name: &str, blocks: &[InputBlock]) -> Routine {
    Routine {
        entry,
        name: name.to_string(),
        blocks: blocks.iter().map(lift_block).collect(),
    }
}

fn lift_block(b: &InputBlock) -> Block {
    let mut instrs = Vec::with_capacity(b.ops.len());
    let mut temp_counter: u32 = 0;
    let mut i = 0;
    while i < b.ops.len() {
        let cur = &b.ops[i];
        let mnemonic = split_mnemonic(strip_comment(&cur.disasm))
            .0
            .to_ascii_lowercase();

        if matches!(mnemonic.as_str(), "cmp" | "test") {
            if let Some(next) = b.ops.get(i + 1) {
                if next.kind.as_deref() == Some("cjmp") {
                    if let Some(fused) = fuse_cmp_jcc(cur, next, &mut temp_counter) {
                        instrs.extend(fused);
                        i += 2;
                        continue;
                    }
                }
            }
        }

        instrs.extend(lift_single(cur));
        i += 1;
    }
    Block {
        addr: b.addr,
        instrs,
        jump: b.jump,
        fail: b.fail,
        targets: b.targets.clone(),
    }
}

/// Recognise the `cmp`/`test` + `Jcc` idiom and raise it to VTIL's own
/// `t*` + `js` pair, discarding the native flags register entirely — the
/// `t*` instruction becomes the sole carrier of the comparison's result.
/// Returns `None` when the pattern is not one this lifter models exactly
/// (an unrecognised `Jcc` suffix, a `test a, b` with `a != b`, or an operand
/// count mismatch), leaving both native instructions to lift independently.
fn fuse_cmp_jcc(cmp: &InputInsn, jcc: &InputInsn, temp_counter: &mut u32) -> Option<Vec<Instr>> {
    let cmp_text = strip_comment(&cmp.disasm);
    let (cmp_mnemonic, cmp_operand_str) = split_mnemonic(cmp_text);
    let cmp_mnemonic = cmp_mnemonic.to_ascii_lowercase();
    let raw = split_operands(cmp_operand_str);
    if raw.len() != 2 {
        return None;
    }

    let jcc_text = strip_comment(&jcc.disasm);
    let (jcc_mnemonic, _) = split_mnemonic(jcc_text);
    let cond = Cond::from_jcc(&jcc_mnemonic.to_ascii_lowercase())?;

    let (lhs, rhs) = match cmp_mnemonic.as_str() {
        "cmp" => (parse_operand(&raw[0]), parse_operand(&raw[1])),
        // `test x, x` ; `jz`/`jnz` is the common zero/non-zero idiom
        // (`test` computes `x & x` and only ZF has an exact, sign-agnostic
        // meaning for that result). Any other `test`/condition combination
        // is left unlifted rather than guessed at.
        "test" if raw[0] == raw[1] && matches!(cond, Cond::Eq | Cond::Ne) => {
            (parse_operand(&raw[0]), Operand::Imm(0))
        }
        _ => return None,
    };

    let temp = *temp_counter;
    *temp_counter += 1;
    Some(vec![
        Instr {
            addr: cmp.addr,
            op: Op::SetCond(cond),
            operands: vec![Operand::Reg(Register::Temp(temp)), lhs, rhs],
            target: None,
            fallthrough: None,
            native: cmp_text.to_string(),
        },
        Instr {
            addr: jcc.addr,
            op: Op::Js,
            operands: vec![Operand::Reg(Register::Temp(temp))],
            target: jcc.jump,
            fallthrough: jcc.fail,
            native: jcc_text.to_string(),
        },
    ])
}

/// Lift one native instruction on its own (no lookahead/lookbehind fusion).
/// Returns more than one [`Instr`] for `push`/`pop`, which this lifter
/// decomposes into their `str`/`ldd` + stack-pointer adjustment — VTIL has
/// no dedicated stack opcode of its own; the virtual stack is a property of
/// the optimizer, not the base instruction set.
fn lift_single(insn: &InputInsn) -> Vec<Instr> {
    let text = strip_comment(&insn.disasm);
    let (mnemonic, operand_str) = split_mnemonic(text);
    let mnemonic = mnemonic.to_ascii_lowercase();
    let raw = split_operands(operand_str);
    let operands: Vec<Operand> = raw.iter().map(|s| parse_operand(s)).collect();

    let vemit = |target: Option<u64>, fallthrough: Option<u64>| {
        vec![Instr {
            addr: insn.addr,
            op: Op::Vemit,
            operands: vec![],
            target,
            fallthrough,
            native: text.to_string(),
        }]
    };

    // Control flow is driven by the backend-neutral `kind`, not the
    // mnemonic, so it is correct on every architecture the active engine
    // disassembles.
    match insn.kind.as_deref() {
        Some("ret") => {
            return vec![Instr {
                addr: insn.addr,
                op: Op::Vexit,
                operands: vec![],
                target: None,
                fallthrough: None,
                native: text.to_string(),
            }];
        }
        Some("call") => {
            let target_operand = match insn.jump {
                Some(t) => Operand::Imm(t as i64),
                None => match operands.first() {
                    Some(op) => op.clone(),
                    None => return vemit(insn.jump, insn.fail),
                },
            };
            return vec![Instr {
                addr: insn.addr,
                op: Op::Vxcall,
                operands: vec![target_operand],
                target: insn.jump,
                fallthrough: None,
                native: text.to_string(),
            }];
        }
        Some("jmp") => {
            let target_operand = match insn.jump {
                Some(t) => Operand::Imm(t as i64),
                None => match operands.first() {
                    Some(op) => op.clone(),
                    None => return vemit(insn.jump, insn.fail),
                },
            };
            return vec![Instr {
                addr: insn.addr,
                op: Op::Jmp,
                operands: vec![target_operand],
                target: insn.jump,
                fallthrough: None,
                native: text.to_string(),
            }];
        }
        Some("cjmp") => {
            // Reached only when `fuse_cmp_jcc` did not apply. Still records
            // the recovered condition when the suffix is one of the ten
            // relations this crate models; both edges are kept regardless.
            return vec![Instr {
                addr: insn.addr,
                op: match Cond::from_jcc(&mnemonic) {
                    Some(cond) => Op::Jcc(cond),
                    None => Op::Vemit,
                },
                operands: vec![],
                target: insn.jump,
                fallthrough: insn.fail,
                native: text.to_string(),
            }];
        }
        _ => {}
    }

    if mnemonic == "nop" {
        return vec![Instr {
            addr: insn.addr,
            op: Op::Nop,
            operands: vec![],
            target: None,
            fallthrough: None,
            native: text.to_string(),
        }];
    }

    let one = |op: Op, operands: Vec<Operand>| {
        vec![Instr {
            addr: insn.addr,
            op,
            operands,
            target: None,
            fallthrough: None,
            native: text.to_string(),
        }]
    };
    let reg = |name: &str| Operand::Reg(Register::Physical(name.to_string()));
    // Stack width assumption: x86-64. A 32-bit target's `push`/`pop` would
    // need a 4-byte adjustment instead; bitness is not threaded through
    // `InputInsn` today, so this lifter's stack decomposition targets
    // x86-64 only (everything else it models is width-agnostic).
    let sp_step = Operand::Imm(8);
    let stack_slot = Operand::Mem("[rsp]".to_string());

    match (mnemonic.as_str(), operands.len()) {
        ("mov" | "movabs", 2) => {
            let op = if matches!(operands[0], Operand::Mem(_)) {
                Op::Str
            } else if matches!(operands[1], Operand::Mem(_)) {
                Op::Ldd
            } else {
                Op::Mov
            };
            one(op, operands)
        }
        // Upstream VTIL's `mov` is defined as a zero-extending write, so a
        // native zero-extend lifts to plain `Op::Mov` (see `Op::Movzx`'s
        // doc comment).
        ("movzx", 2) => one(Op::Mov, operands),
        ("movsx" | "movsxd", 2) => one(Op::Movsx, operands),
        ("lea", 2) => one(Op::Lea, operands),
        ("neg", 1) => one(Op::Neg, operands),
        ("not", 1) => one(Op::Not, operands),
        ("bsf", 2) => one(Op::Bsf, operands),
        ("bsr", 2) => one(Op::Bsr, operands),
        ("popcnt", 2) => one(Op::Popcnt, operands),
        ("inc", 1) => one(Op::Add, vec![operands[0].clone(), Operand::Imm(1)]),
        ("dec", 1) => one(Op::Sub, vec![operands[0].clone(), Operand::Imm(1)]),
        ("add", 2) => one(Op::Add, operands),
        ("sub", 2) => one(Op::Sub, operands),
        ("and", 2) => one(Op::And, operands),
        ("or", 2) => one(Op::Or, operands),
        ("xor", 2) => one(Op::Xor, operands),
        ("shl" | "sal", 2) => one(Op::Shl, operands),
        ("shr", 2) => one(Op::Shr, operands),
        ("sar", 2) => one(Op::Sar, operands),
        ("ror", 2) => one(Op::Ror, operands),
        ("rol", 2) => one(Op::Rol, operands),
        // x86's 1-operand `mul`/`imul`/`div`/`idiv` implicitly use `rax`
        // (and, for `div`/`idiv`, `rdx` as the high half / remainder side —
        // not modelled, same simplification upstream VTIL documents by
        // keeping `mulhi`/`imulhi`/`rem`/`irem` separate opcodes this
        // lifter does not emit).
        ("mul", 1) => one(Op::Mul, vec![reg("rax"), operands[0].clone()]),
        ("imul", 1) => one(Op::IMul, vec![reg("rax"), operands[0].clone()]),
        ("imul", 2) => one(Op::IMul, operands),
        ("imul", 3) => one(Op::IMul, operands),
        ("div", 1) => one(Op::Div, vec![reg("rax"), operands[0].clone()]),
        ("idiv", 1) => one(Op::IDiv, vec![reg("rax"), operands[0].clone()]),
        ("push", 1) => vec![
            Instr {
                addr: insn.addr,
                op: Op::Sub,
                operands: vec![reg("rsp"), sp_step],
                target: None,
                fallthrough: None,
                native: text.to_string(),
            },
            Instr {
                addr: insn.addr,
                op: Op::Str,
                operands: vec![stack_slot, operands[0].clone()],
                target: None,
                fallthrough: None,
                native: text.to_string(),
            },
        ],
        ("pop", 1) => vec![
            Instr {
                addr: insn.addr,
                op: Op::Ldd,
                operands: vec![operands[0].clone(), stack_slot],
                target: None,
                fallthrough: None,
                native: text.to_string(),
            },
            Instr {
                addr: insn.addr,
                op: Op::Add,
                operands: vec![reg("rsp"), sp_step],
                target: None,
                fallthrough: None,
                native: text.to_string(),
            },
        ],
        _ => vemit(None, None),
    }
}

/// Strip a `" ; comment"` annotation (see
/// `recurse_static::native::format_insn` / disassembly annotation) before
/// parsing, so the lifter works the same whether or not the engine
/// annotated the instruction.
fn strip_comment(disasm: &str) -> &str {
    disasm.split(" ; ").next().unwrap_or(disasm).trim()
}

/// Split `"mnemonic operand, operand"` into `(mnemonic, "operand, operand")`.
fn split_mnemonic(text: &str) -> (&str, &str) {
    match text.find(char::is_whitespace) {
        Some(idx) => (&text[..idx], text[idx..].trim()),
        None => (text, ""),
    }
}

/// Split an Intel-syntax operand list on top-level commas — a memory operand
/// (`[rax + rbx*4]`) never contains one, so this only needs bracket-depth
/// tracking, not a full parser.
fn split_operands(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth <= 0 => {
                let t = cur.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let t = cur.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
    out
}

/// Classify one already-split operand token as a register, immediate, or
/// memory expression.
fn parse_operand(tok: &str) -> Operand {
    let t = tok.trim();
    if t.contains('[') {
        return Operand::Mem(strip_size_prefix(t).to_string());
    }
    if let Some(v) = parse_immediate(t) {
        return Operand::Imm(v);
    }
    Operand::Reg(Register::Physical(t.to_ascii_lowercase()))
}

const SIZE_PREFIXES: &[&str] = &[
    "byte ptr ",
    "word ptr ",
    "dword ptr ",
    "qword ptr ",
    "xmmword ptr ",
    "ymmword ptr ",
    "tbyte ptr ",
    "ptr ",
];

fn strip_size_prefix(t: &str) -> &str {
    for prefix in SIZE_PREFIXES {
        if let Some(rest) = t.strip_prefix(prefix) {
            return rest;
        }
    }
    t
}

/// Parse a decimal or `0x`-prefixed (optionally negative) integer literal.
/// `None` for anything else — in particular every register name, so this
/// doubles as the register/immediate discriminator in [`parse_operand`].
fn parse_immediate(t: &str) -> Option<i64> {
    let (neg, body) = match t.strip_prefix('-') {
        Some(rest) => (true, rest.trim()),
        None => (false, t),
    };
    let value: u64 = if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()?
    } else if !body.is_empty() && body.bytes().all(|c| c.is_ascii_digit()) {
        body.parse().ok()?
    } else {
        return None;
    };
    let signed = i64::try_from(value).ok()?;
    Some(if neg { -signed } else { signed })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn insn(addr: u64, disasm: &str) -> InputInsn {
        InputInsn {
            addr,
            disasm: disasm.to_string(),
            kind: None,
            jump: None,
            fail: None,
        }
    }

    fn ctrl(
        addr: u64,
        disasm: &str,
        kind: &str,
        jump: Option<u64>,
        fail: Option<u64>,
    ) -> InputInsn {
        InputInsn {
            addr,
            disasm: disasm.to_string(),
            kind: Some(kind.to_string()),
            jump,
            fail,
        }
    }

    #[test]
    fn splits_mnemonic_and_operands() {
        assert_eq!(split_mnemonic("ret"), ("ret", ""));
        assert_eq!(split_mnemonic("mov rax, rbx"), ("mov", "rax, rbx"));
        assert_eq!(
            split_operands("rax, qword ptr [rbx + rcx*4 + 0x10]"),
            vec!["rax", "qword ptr [rbx + rcx*4 + 0x10]"]
        );
    }

    #[test]
    fn parses_operands() {
        assert_eq!(
            parse_operand("rax"),
            Operand::Reg(Register::Physical("rax".into()))
        );
        assert_eq!(parse_operand("0x10"), Operand::Imm(0x10));
        assert_eq!(parse_operand("-8"), Operand::Imm(-8));
        assert_eq!(
            parse_operand("qword ptr [rip + 0x10]"),
            Operand::Mem("[rip + 0x10]".into())
        );
    }

    #[test]
    fn lifts_plain_mov_and_arithmetic() {
        let out = lift_single(&insn(0x1000, "mov rax, rbx"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Mov);

        let out = lift_single(&insn(0x1003, "add rax, 0x5"));
        assert_eq!(out[0].op, Op::Add);
        assert_eq!(out[0].operands[1], Operand::Imm(5));
    }

    #[test]
    fn distinguishes_load_and_store() {
        let out = lift_single(&insn(0x1000, "mov rax, qword ptr [rbx]"));
        assert_eq!(out[0].op, Op::Ldd);
        let out = lift_single(&insn(0x1000, "mov qword ptr [rbx], rax"));
        assert_eq!(out[0].op, Op::Str);
    }

    #[test]
    fn decomposes_push_and_pop() {
        let out = lift_single(&insn(0x1000, "push rbp"));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].op, Op::Sub);
        assert_eq!(out[1].op, Op::Str);

        let out = lift_single(&insn(0x1000, "pop rbp"));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].op, Op::Ldd);
        assert_eq!(out[1].op, Op::Add);
    }

    #[test]
    fn fuses_cmp_and_conditional_jump_into_setcond_js() {
        let block = InputBlock {
            addr: 0x1000,
            jump: None,
            fail: None,
            targets: vec![],
            ops: vec![
                insn(0x1000, "mov eax, edi"),
                insn(0x1002, "cmp eax, 0x2a"),
                ctrl(0x1005, "jge 0x2000", "cjmp", Some(0x2000), Some(0x1007)),
            ],
        };
        let lifted = lift_block(&block);
        let ops: Vec<&Op> = lifted.instrs.iter().map(|i| &i.op).collect();
        assert_eq!(
            ops,
            vec![&Op::Mov, &Op::SetCond(Cond::Ge), &Op::Js],
            "got {ops:?}"
        );
        let js = &lifted.instrs[2];
        assert_eq!(js.target, Some(0x2000));
        assert_eq!(js.fallthrough, Some(0x1007));
    }

    #[test]
    fn fuses_test_self_zero_check() {
        let block = InputBlock {
            addr: 0x1000,
            jump: None,
            fail: None,
            targets: vec![],
            ops: vec![
                insn(0x1000, "test eax, eax"),
                ctrl(0x1002, "je 0x2000", "cjmp", Some(0x2000), Some(0x1004)),
            ],
        };
        let lifted = lift_block(&block);
        assert_eq!(lifted.instrs.len(), 2);
        assert_eq!(lifted.instrs[0].op, Op::SetCond(Cond::Eq));
        assert_eq!(lifted.instrs[0].operands[2], Operand::Imm(0));
    }

    #[test]
    fn unrecognised_instructions_fall_back_to_vemit_and_stay_total() {
        let out = lift_single(&insn(0x1000, "vfmadd231ps ymm0, ymm1, ymm2"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Vemit);
        assert_eq!(out[0].native, "vfmadd231ps ymm0, ymm1, ymm2");
    }

    #[test]
    fn ret_and_jmp_and_call_map_to_vexit_jmp_vxcall() {
        assert_eq!(
            lift_single(&ctrl(0x1000, "ret", "ret", None, None))[0].op,
            Op::Vexit
        );
        let j = lift_single(&ctrl(0x1000, "jmp 0x2000", "jmp", Some(0x2000), None));
        assert_eq!(j[0].op, Op::Jmp);
        assert_eq!(j[0].target, Some(0x2000));
        let c = lift_single(&ctrl(0x1000, "call 0x3000", "call", Some(0x3000), None));
        assert_eq!(c[0].op, Op::Vxcall);
        assert_eq!(c[0].operands[0], Operand::Imm(0x3000));
    }

    #[test]
    fn whole_routine_lifts_every_block() {
        let routine = lift_routine(
            0x1000,
            "f",
            &[InputBlock {
                addr: 0x1000,
                jump: None,
                fail: None,
                targets: vec![],
                ops: vec![insn(0x1000, "nop"), ctrl(0x1001, "ret", "ret", None, None)],
            }],
        );
        assert_eq!(routine.blocks.len(), 1);
        assert_eq!(routine.instr_count(), 2);
    }
}
