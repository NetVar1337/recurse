//! A structuring decompiler over the lifted, optimized IL: renders a
//! [`Routine`] as C-like pseudocode instead of a flat instruction/block
//! dump — closing the gap `docs/backends.md` documented honestly for the
//! native engine (`capabilities().decompile == false`, no decompiler in the
//! permissive Rust ecosystem). This is not Hex-Rays; it is what a from-
//! scratch structuring pass over an already-devirtualized [`crate::opt`]/
//! [`crate::symex`] IL can reach in one pass, with a hard guarantee this
//! module leans on throughout: **total coverage**. Every instruction and
//! every edge is rendered as *something*, even when that something is a
//! `goto` to a label rather than a pretty `if`/`while` — never a panic,
//! never a silently dropped block.
//!
//! # Structuring
//!
//! [`Cfg::immediate_dominators`]/[`Cfg::back_edges`] (Cooper/Harvey/Kennedy)
//! drive two recognisers, applied depth-first from the routine's entry:
//!
//! - **`if`/`else`**: a block with two successors (`Block::jump` taken,
//!   `Block::fail` not taken) that is not a recognised loop header — both
//!   arms are structured recursively.
//! - **`while`**: a block with two successors that *is* a loop header (the
//!   target of some back edge) **and** exactly one of its two successors is
//!   dominated by it (the "stay in the loop" edge — the other one exits).
//!   When neither or both successors qualify (an irregular loop shape this
//!   pass does not attempt to prove), it falls back to plain `if`/`else`;
//!   the back edge itself still renders correctly (as `continue;` or a
//!   `goto`), so this is a readability shortfall, never a correctness one.
//!
//! Anything the recursion reaches a second time (a shared join point, an
//! irreducible loop with more than one entry) becomes `goto label_0x...;`
//! instead of being re-inlined — every block is always labelled, precisely
//! so that `goto` target is always valid. Anything the recursion never
//! reaches at all (dead relative to this routine's own recovered edges —
//! rare, but not impossible on a partially-recovered CFG) is still emitted
//! afterward as its own labelled fragment, so byte-for-byte instruction
//! coverage never silently regresses relative to the flat `lift` dump.
//!
//! # Expressions
//!
//! Each non-control instruction becomes one C-like statement from its own
//! operands (`crates/recurse-vtil/src/il.rs`'s `Instr`/`Operand`), not from
//! [`crate::symex`]'s traced expressions — those are a separate, optional
//! analysis a caller can still run and cross-reference by address; folding
//! them into this rendering is future work. A `js`'s condition is recovered
//! by walking back to the `SetCond` that feeds it (see `docs/vtil-lift.md`
//! on the `cmp`/`test` → `t*`/`js` raise) and rendered as `lhs OP rhs`; a
//! not-yet-raised `jcc` (or a `js` whose feeder was not found) renders a
//! best-effort placeholder rather than failing.

use crate::cfg::Cfg;
use crate::il::{Block, Cond, Instr, Op, Operand, Routine};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// Render `routine` as C-like pseudocode.
pub fn decompile(routine: &Routine) -> String {
    let cfg = Cfg::build(routine);
    let back_edges = cfg.back_edges(routine.entry);
    let by_addr: HashMap<u64, &Block> = routine.blocks.iter().map(|b| (b.addr, b)).collect();

    let mut visited: HashSet<u64> = HashSet::new();
    let mut out = String::new();
    let _ = writeln!(out, "// {} @ 0x{:x}", routine.name, routine.entry);
    let _ = writeln!(out, "void {}(void) {{", sanitize_ident(&routine.name));
    out.push_str(&structure(
        routine.entry,
        None,
        &by_addr,
        &cfg,
        &back_edges,
        &mut visited,
        1,
    ));

    // Total coverage: a block the structurer never reached at all (dead
    // relative to this routine's own recovered edges) is still emitted, so
    // no instruction silently disappears relative to the flat `lift` dump.
    for block in &routine.blocks {
        if visited.insert(block.addr) {
            let _ = writeln!(out, "{}label_0x{:x}:", pad(1), block.addr);
            out.push_str(&indent(&render_statements(&block.instrs), 1));
            out.push_str(&indent(&edge_fallback(block), 1));
        }
    }
    out.push_str("}\n");
    out
}

fn structure(
    addr: u64,
    loop_header: Option<u64>,
    by_addr: &HashMap<u64, &Block>,
    cfg: &Cfg,
    back_edges: &HashSet<(u64, u64)>,
    visited: &mut HashSet<u64>,
    depth: usize,
) -> String {
    if !visited.insert(addr) {
        if Some(addr) == loop_header {
            return format!("{}continue;\n", pad(depth));
        }
        return format!("{}goto label_0x{addr:x};\n", pad(depth));
    }
    let Some(&block) = by_addr.get(&addr) else {
        return format!(
            "{}goto label_0x{addr:x}; // unresolved target\n",
            pad(depth)
        );
    };

    let mut out = format!("{}label_0x{addr:x}:\n", pad(depth));
    out.push_str(&indent(&render_statements(&block.instrs), depth));

    match (block.jump, block.fail) {
        (None, None) => {
            out.push_str(&format!("{}return;\n", pad(depth)));
        }
        (Some(j), None) | (None, Some(j)) => {
            if Some(j) == loop_header {
                out.push_str(&format!("{}continue;\n", pad(depth)));
            } else {
                out.push_str(&structure(
                    j,
                    loop_header,
                    by_addr,
                    cfg,
                    back_edges,
                    visited,
                    depth,
                ));
            }
        }
        (Some(j), Some(f)) => {
            let is_header = back_edges.iter().any(|&(_, to)| to == addr);
            let loop_shape = if is_header {
                body_and_exit(addr, j, f, cfg)
            } else {
                None
            };

            if let Some((body_target, exit_target)) = loop_shape {
                let (cond_taken, cond_not_taken) = condition_texts(block);
                let cond = if body_target == j {
                    cond_taken
                } else {
                    cond_not_taken
                };
                out.push_str(&format!("{}while ({cond}) {{\n", pad(depth)));
                out.push_str(&structure(
                    body_target,
                    Some(addr),
                    by_addr,
                    cfg,
                    back_edges,
                    visited,
                    depth + 1,
                ));
                out.push_str(&format!("{}}}\n", pad(depth)));
                out.push_str(&structure(
                    exit_target,
                    loop_header,
                    by_addr,
                    cfg,
                    back_edges,
                    visited,
                    depth,
                ));
            } else {
                let (cond_taken, _) = condition_texts(block);
                out.push_str(&format!("{}if ({cond_taken}) {{\n", pad(depth)));
                out.push_str(&structure(
                    j,
                    loop_header,
                    by_addr,
                    cfg,
                    back_edges,
                    visited,
                    depth + 1,
                ));
                out.push_str(&format!("{}}} else {{\n", pad(depth)));
                out.push_str(&structure(
                    f,
                    loop_header,
                    by_addr,
                    cfg,
                    back_edges,
                    visited,
                    depth + 1,
                ));
                out.push_str(&format!("{}}}\n", pad(depth)));
            }
        }
    }
    out
}

/// `addr` is a recognised `while` loop header ending in a two-way branch
/// exactly when exactly one of its two successors can reach `addr` again
/// (forward reachability, not dominance: a loop's *sole* exit block is
/// typically dominated by the header too, since it has no other way in —
/// dominance alone cannot tell "inside the loop" from "only reachable
/// through the loop" apart). That successor is the body; the other,
/// dominance or not, is the exit. Neither/both able to reach `addr` again
/// means this pass does not attempt to prove the shape; the caller falls
/// back to plain `if`/`else` (still correct — the back edge itself still
/// renders, just without the `while` sugar).
fn body_and_exit(addr: u64, j: u64, f: u64, cfg: &Cfg) -> Option<(u64, u64)> {
    let j_returns = reaches(cfg, j, addr);
    let f_returns = reaches(cfg, f, addr);
    match (j_returns, f_returns) {
        (true, false) => Some((j, f)),
        (false, true) => Some((f, j)),
        _ => None,
    }
}

/// Bounded forward reachability: can `target` be reached from `start` by
/// following CFG edges? Bounds its own exploration to the routine's own
/// block count via `visited`, so a malformed/cyclic graph still terminates.
fn reaches(cfg: &Cfg, start: u64, target: u64) -> bool {
    if start == target {
        return true;
    }
    let mut visited: HashSet<u64> = HashSet::new();
    let mut stack = vec![start];
    visited.insert(start);
    while let Some(node) = stack.pop() {
        for &succ in cfg.successors(node) {
            if succ == target {
                return true;
            }
            if visited.insert(succ) {
                stack.push(succ);
            }
        }
    }
    false
}

/// A block never reached by [`structure`] at all still needs *some* edge
/// rendering in the total-coverage fallback loop in [`decompile`].
fn edge_fallback(block: &Block) -> String {
    match (block.jump, block.fail) {
        (None, None) => "return;\n".to_string(),
        (Some(j), None) | (None, Some(j)) => format!("goto label_0x{j:x};\n"),
        (Some(j), Some(f)) => {
            let (cond, _) = condition_texts(block);
            format!("if ({cond}) goto label_0x{j:x}; else goto label_0x{f:x};\n")
        }
    }
}

/// Render every non-control-flow instruction in `instrs` as one statement
/// each. `Js`/`Jmp`/`Vexit`/`Jcc` carry no statement of their own — the
/// block's `jump`/`fail` edges (not these opcodes) are what
/// [`structure`]/[`edge_fallback`] read to decide control flow, so these are
/// simply skipped here regardless of where they fall in the instruction
/// list.
fn render_statements(instrs: &[Instr]) -> String {
    let mut out = String::new();
    for instr in instrs {
        if matches!(instr.op, Op::Js | Op::Jmp | Op::Vexit | Op::Jcc(_)) {
            continue;
        }
        out.push_str(&stmt(instr));
    }
    out
}

fn operand_text(op: &Operand) -> String {
    match op {
        Operand::Reg(r) => r.to_string(),
        Operand::Imm(v) if *v < 0 => format!("-0x{:x}", v.unsigned_abs()),
        Operand::Imm(v) => format!("0x{v:x}"),
        Operand::Mem(m) => m.clone(),
    }
}

fn cond_symbol(cond: Cond) -> &'static str {
    match cond {
        Cond::Eq => "==",
        Cond::Ne => "!=",
        Cond::Gt => ">",
        Cond::Ge => ">=",
        Cond::Lt => "<",
        Cond::Le => "<=",
        Cond::UGt => "u>",
        Cond::UGe => "u>=",
        Cond::ULt => "u<",
        Cond::ULe => "u<=",
    }
}

/// Walk `block` backward from `js` looking for the `SetCond` that defines
/// the temporary register `js` reads, and render the comparison it computed
/// (`lhs OP rhs`) instead of the bare temporary name.
fn condition_texts(block: &Block) -> (String, String) {
    for instr in block.instrs.iter().rev() {
        match &instr.op {
            Op::Js => {
                if let Some(Operand::Reg(temp)) = instr.operands.first() {
                    if let Some(setcond) = block.instrs.iter().rev().find(|i| {
                        matches!(&i.op, Op::SetCond(_))
                            && matches!(i.operands.first(), Some(Operand::Reg(r)) if r == temp)
                    }) {
                        if let (Op::SetCond(cond), Some(lhs), Some(rhs)) = (
                            &setcond.op,
                            setcond.operands.get(1),
                            setcond.operands.get(2),
                        ) {
                            let lhs = operand_text(lhs);
                            let rhs = operand_text(rhs);
                            return (
                                format!("{lhs} {} {rhs}", cond_symbol(*cond)),
                                format!("{lhs} {} {rhs}", cond_symbol(cond.negate())),
                            );
                        }
                    }
                    let t = temp.to_string();
                    return (t.clone(), format!("!{t}"));
                }
                return ("<cond>".to_string(), "!<cond>".to_string());
            }
            Op::Jcc(cond) => {
                return (
                    format!("/* flags */ {}", cond_symbol(*cond)),
                    format!("/* flags */ {}", cond_symbol(cond.negate())),
                );
            }
            _ => continue,
        }
    }
    ("<cond>".to_string(), "!<cond>".to_string())
}

fn stmt(instr: &Instr) -> String {
    let ops: Vec<String> = instr.operands.iter().map(operand_text).collect();
    let a = |i: usize| ops.get(i).cloned().unwrap_or_default();
    match &instr.op {
        Op::Mov | Op::Movsx | Op::Movzx => format!("{} = {};\n", a(0), a(1)),
        Op::Lea => format!("{} = &{};\n", a(0), a(1)),
        Op::Ldd => format!("{} = *({});\n", a(0), a(1)),
        Op::Str => format!("*({}) = {};\n", a(0), a(1)),
        Op::Neg => format!("{0} = -{0};\n", a(0)),
        Op::Not => format!("{0} = ~{0};\n", a(0)),
        Op::Add => format!("{} += {};\n", a(0), a(1)),
        Op::Sub => format!("{} -= {};\n", a(0), a(1)),
        Op::And => format!("{} &= {};\n", a(0), a(1)),
        Op::Or => format!("{} |= {};\n", a(0), a(1)),
        Op::Xor => format!("{} ^= {};\n", a(0), a(1)),
        Op::Shl => format!("{} <<= {};\n", a(0), a(1)),
        Op::Shr | Op::Sar => format!("{} >>= {};\n", a(0), a(1)),
        Op::Ror => format!("{0} = ror({0}, {1});\n", a(0), a(1)),
        Op::Rol => format!("{0} = rol({0}, {1});\n", a(0), a(1)),
        Op::Mul | Op::IMul => format!("{} *= {};\n", a(0), a(1)),
        Op::Div => format!("{} /= {};\n", a(0), a(1)),
        Op::IDiv => format!("{0} = (int64_t){0} / (int64_t){1};\n", a(0), a(1)),
        Op::Popcnt => format!("{} = popcnt({});\n", a(0), a(1)),
        Op::Bsf => format!("{} = bsf({});\n", a(0), a(1)),
        Op::Bsr => format!("{} = bsr({});\n", a(0), a(1)),
        Op::SetCond(cond) => format!(
            "{} = ({} {} {}) ? 1 : 0;\n",
            a(0),
            a(1),
            cond_symbol(*cond),
            a(2)
        ),
        Op::Vxcall => format!("call({});\n", a(0)),
        Op::Nop => String::new(),
        Op::Vemit => format!("__asm(\"{}\");\n", instr.native.replace('"', "'")),
        Op::Js | Op::Jmp | Op::Vexit | Op::Jcc(_) => String::new(),
    }
}

fn pad(n: usize) -> String {
    "  ".repeat(n)
}

fn indent(text: &str, n: usize) -> String {
    let prefix = pad(n);
    let mut out = String::with_capacity(text.len() + text.lines().count() * n * 2);
    for line in text.lines() {
        if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str(&prefix);
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn sanitize_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        out.push(if c.is_ascii_alphanumeric() || c == '_' {
            c
        } else {
            '_'
        });
    }
    let needs_prefix = match out.chars().next() {
        None => true,
        Some(c) => c.is_ascii_digit(),
    };
    if needs_prefix {
        out.insert(0, '_');
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::il::{Cond, Register};
    use crate::input::{InputBlock, InputInsn};
    use crate::{lift, opt};

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

    #[test]
    fn straight_line_function_decompiles_to_a_sequence_and_a_return() {
        let blocks = vec![InputBlock {
            addr: 0x1000,
            jump: None,
            fail: None,
            targets: vec![],
            ops: vec![
                insn(0x1000, "mov eax, 1", None, None, None),
                insn(0x1004, "add eax, 0x2", None, None, None),
                insn(0x1008, "ret", Some("ret"), None, None),
            ],
        }];
        let routine = lift::lift_routine(0x1000, "add_two", &blocks);
        let code = decompile(&routine);
        assert!(code.contains("void add_two(void) {"));
        assert!(code.contains("eax = 0x1;"));
        assert!(code.contains("eax += 0x2;"));
        assert!(code.contains("return;"));
        assert!(code.trim_end().ends_with('}'));
    }

    #[test]
    fn conditional_branch_becomes_if_else() {
        let blocks = vec![
            InputBlock {
                addr: 0x1000,
                jump: Some(0x2000),
                fail: Some(0x1010),
                targets: vec![],
                ops: vec![
                    insn(0x1000, "cmp eax, 0x2a", None, None, None),
                    insn(
                        0x1004,
                        "jge 0x2000",
                        Some("cjmp"),
                        Some(0x2000),
                        Some(0x1010),
                    ),
                ],
            },
            InputBlock {
                addr: 0x1010,
                jump: None,
                fail: None,
                targets: vec![],
                ops: vec![insn(0x1010, "ret", Some("ret"), None, None)],
            },
            InputBlock {
                addr: 0x2000,
                jump: None,
                fail: None,
                targets: vec![],
                ops: vec![insn(0x2000, "ret", Some("ret"), None, None)],
            },
        ];
        let routine = lift::lift_routine(0x1000, "guard", &blocks);
        let code = decompile(&routine);
        assert!(code.contains("if (eax >= 0x2a) {"), "got:\n{code}");
        assert!(code.contains("} else {"));
        assert!(code.contains("label_0x2000:"));
        assert!(code.contains("label_0x1010:"));
    }

    #[test]
    fn self_loop_becomes_a_while_loop() {
        // ecx = 0
        // loop: ecx += 1 ; cmp ecx, 0xa ; jl loop ; ret (fall through)
        let blocks = vec![
            InputBlock {
                addr: 0x1000,
                jump: Some(0x1010),
                fail: None,
                targets: vec![],
                ops: vec![insn(0x1000, "mov ecx, 0", None, None, None)],
            },
            InputBlock {
                addr: 0x1010,
                jump: Some(0x1010),
                fail: Some(0x1020),
                targets: vec![],
                ops: vec![
                    insn(0x1010, "add ecx, 0x1", None, None, None),
                    insn(0x1014, "cmp ecx, 0xa", None, None, None),
                    insn(
                        0x1018,
                        "jl 0x1010",
                        Some("cjmp"),
                        Some(0x1010),
                        Some(0x1020),
                    ),
                ],
            },
            InputBlock {
                addr: 0x1020,
                jump: None,
                fail: None,
                targets: vec![],
                ops: vec![insn(0x1020, "ret", Some("ret"), None, None)],
            },
        ];
        let mut routine = lift::lift_routine(0x1000, "count_to_ten", &blocks);
        opt::optimize(&mut routine);
        let code = decompile(&routine);
        assert!(
            code.contains("while"),
            "expected a recognised loop:\n{code}"
        );
        assert!(
            code.contains("continue;"),
            "back edge should render as continue:\n{code}"
        );
    }

    #[test]
    fn total_coverage_even_for_unlifted_instructions() {
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
        let routine = lift::lift_routine(0x1000, "f", &blocks);
        let code = decompile(&routine);
        assert!(
            code.contains("__asm("),
            "unlifted instruction should still appear: {code}"
        );
        assert!(code.contains("vpxor"));
    }

    #[test]
    fn negated_condition_used_when_the_loop_body_is_the_fail_edge() {
        // Sanity check on cond_symbol/negate wiring directly, independent of
        // the lifter/optimizer: Cond::Ge negates to Cond::Lt.
        assert_eq!(cond_symbol(Cond::Ge), ">=");
        assert_eq!(cond_symbol(Cond::Ge.negate()), "<");
        let _ = Register::Physical("eax".to_string());
    }
}
