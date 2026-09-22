//! Render a [`Routine`] as VTIL-style text — the same shape as the
//! `begin_routine` / `block_0x...` / `end_routine` dumps VTIL-Core's own
//! `Sample Routines/*.vtil` files use, so output from this lifter is
//! recognisable to anyone who has read a real `.vtil` dump. Not a byte-exact
//! implementation of VTIL's binary/text container format — this crate has
//! no reason to round-trip through VTIL-Core's own tools — just the same
//! reading convention: one block per label, one instruction per line,
//! explicit successor edges.

use crate::il::{Instr, Op, Operand, Routine};
use std::fmt::Write as _;

/// Render `routine` as a VTIL-style text listing.
pub fn to_vtil_text(routine: &Routine) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "begin_routine 0x{:x} \"{}\"",
        routine.entry, routine.name
    );
    for block in &routine.blocks {
        let _ = writeln!(out, "block_0x{:x}:", block.addr);
        for instr in &block.instrs {
            let _ = writeln!(out, "  {:#018x}: {}", instr.addr, format_instr(instr));
        }
        match (block.jump, block.fail) {
            (Some(j), Some(f)) => {
                let _ = writeln!(out, "  -> 0x{j:x}, 0x{f:x}");
            }
            (Some(j), None) => {
                let _ = writeln!(out, "  -> 0x{j:x}");
            }
            (None, Some(f)) => {
                let _ = writeln!(out, "  -> 0x{f:x}");
            }
            (None, None) => {}
        }
        if !block.targets.is_empty() {
            let list = block
                .targets
                .iter()
                .map(|t| format!("0x{t:x}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "  -> {{{list}}}");
        }
        out.push('\n');
    }
    out.push_str("end_routine\n");
    out
}

fn format_instr(instr: &Instr) -> String {
    let mnemonic = instr.op.mnemonic();
    let operands = instr
        .operands
        .iter()
        .map(Operand::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut line = if operands.is_empty() {
        format!("{mnemonic:<7}")
    } else {
        format!("{mnemonic:<7} {operands}")
    };
    // `vemit` carries no modelled operands of its own — the native text is
    // its entire payload, not a comment on top of one.
    if matches!(instr.op, Op::Vemit) {
        line = format!("{mnemonic:<7} {{{}}}", instr.native);
    } else if !instr.native.is_empty() {
        let _ = write!(line, "  ; {}", instr.native);
    }
    line
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::il::{Block, Register};

    #[test]
    fn renders_a_minimal_routine() {
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![Block {
                addr: 0x1000,
                instrs: vec![Instr {
                    addr: 0x1000,
                    op: Op::Mov,
                    operands: vec![
                        Operand::Reg(Register::Physical("rax".into())),
                        Operand::Imm(1),
                    ],
                    target: None,
                    fallthrough: None,
                    native: "mov rax, 1".into(),
                }],
                jump: None,
                fail: None,
                targets: vec![],
            }],
        };
        let text = to_vtil_text(&routine);
        assert!(text.starts_with("begin_routine 0x1000 \"f\""));
        assert!(text.contains("block_0x1000:"));
        assert!(text.contains("mov"));
        assert!(text.trim_end().ends_with("end_routine"));
    }
}
