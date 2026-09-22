//! Whole-routine liveness: which canonical registers a block's successors
//! might still read. Feeds [`crate::opt::eliminate_dead_stores_with_live_out`],
//! which is allowed to delete a write that reaches a block's *end* only when
//! this says nothing downstream needs it — the block-local
//! [`crate::opt::eliminate_dead_stores`] has to assume every such write might
//! matter, since it has no CFG to consult.
//!
//! Standard backward gen/kill dataflow: `live_in[B] = gen[B] ∪ (live_out[B] \
//! kill[B])`, `live_out[B] = ⋃ live_in[S]` over successors `S`, iterated to a
//! fixpoint (routines can have loops, so this is not one backward pass).
//! Registers are tracked under [`crate::regalias::canonical`] identity — see
//! that module for why.
//!
//! `Op::Vemit`/`Op::Vxcall` never appear in a block's `kill` set (they have
//! no [`crate::il::Instr::written`] operand by construction), so they can
//! never make a write *look* dead across them at the whole-routine level;
//! the complementary protection — never treating a write as provably dead
//! across a `vemit`/`vxcall` even when it reaches the block's own end — is
//! the forward "clear everything tracked" rule already in
//! `opt::eliminate_dead_stores_scoped`. The two rules compose: this module
//! only ever *permits* a deletion at block end, `opt` still has the last
//! word on whether that specific write survived to the end at all.

use crate::cfg::Cfg;
use crate::il::{Instr, Operand, Register, Routine};
use crate::regalias::canonical;
use std::collections::{HashMap, HashSet};

/// Bound on fixpoint rounds — routines are bounded in size by the engine
/// that discovered them ([`recurse_static`]'s `MAX_BLOCKS`/
/// `MAX_FUNCTION_INSNS`), so this is a safety net, not expected to bind.
const MAX_ROUNDS: usize = 256;

/// `live_out[block.addr]` for every block in `routine`.
pub fn compute_live_out(routine: &Routine, cfg: &Cfg) -> HashMap<u64, HashSet<Register>> {
    let mut gen: HashMap<u64, HashSet<Register>> = HashMap::new();
    let mut kill: HashMap<u64, HashSet<Register>> = HashMap::new();
    for block in &routine.blocks {
        let (g, k) = block_gen_kill(&block.instrs);
        gen.insert(block.addr, g);
        kill.insert(block.addr, k);
    }

    let mut live_in: HashMap<u64, HashSet<Register>> =
        cfg.order.iter().map(|&a| (a, HashSet::new())).collect();
    let mut live_out: HashMap<u64, HashSet<Register>> =
        cfg.order.iter().map(|&a| (a, HashSet::new())).collect();

    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        // Reverse block order tends to converge faster for a backward
        // analysis (successors are usually later in `order`), but any order
        // is correct since we iterate to a fixpoint regardless.
        for &addr in cfg.order.iter().rev() {
            let mut out: HashSet<Register> = HashSet::new();
            for &succ in cfg.successors(addr) {
                if let Some(s) = live_in.get(&succ) {
                    out.extend(s.iter().cloned());
                }
            }
            let empty = HashSet::new();
            let g = gen.get(&addr).unwrap_or(&empty);
            let k = kill.get(&addr).unwrap_or(&empty);
            let mut new_in: HashSet<Register> = out.difference(k).cloned().collect();
            new_in.extend(g.iter().cloned());

            if live_out.get(&addr) != Some(&out) {
                live_out.insert(addr, out);
                changed = true;
            }
            if live_in.get(&addr) != Some(&new_in) {
                live_in.insert(addr, new_in);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    live_out
}

/// Upward-exposed uses (`gen`) and unconditional redefinitions (`kill`) of
/// one block, under canonical register identity.
fn block_gen_kill(instrs: &[Instr]) -> (HashSet<Register>, HashSet<Register>) {
    let mut gen = HashSet::new();
    let mut kill = HashSet::new();
    for instr in instrs {
        for r in instr.read_registers() {
            let cr = canonical(r);
            if !kill.contains(&cr) {
                gen.insert(cr);
            }
        }
        if let Some(Operand::Reg(w)) = instr.written() {
            kill.insert(canonical(w));
        }
    }
    (gen, kill)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::il::{Block, Op};

    fn mov_imm(addr: u64, reg: &str, v: i64) -> Instr {
        Instr {
            addr,
            op: Op::Mov,
            operands: vec![
                Operand::Reg(Register::Physical(reg.into())),
                Operand::Imm(v),
            ],
            target: None,
            fallthrough: None,
            native: String::new(),
        }
    }

    fn add_reg(addr: u64, dst: &str, src: &str) -> Instr {
        Instr {
            addr,
            op: Op::Add,
            operands: vec![
                Operand::Reg(Register::Physical(dst.into())),
                Operand::Reg(Register::Physical(src.into())),
            ],
            target: None,
            fallthrough: None,
            native: String::new(),
        }
    }

    fn vexit(addr: u64) -> Instr {
        Instr {
            addr,
            op: Op::Vexit,
            operands: vec![],
            target: None,
            fallthrough: None,
            native: "ret".into(),
        }
    }

    #[test]
    fn a_register_used_in_a_successor_is_live_out_of_its_predecessor() {
        // B0: eax = 1 ; jmp B1
        // B1: ebx = eax + ebx ; vexit
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![
                Block {
                    addr: 0x1000,
                    instrs: vec![mov_imm(0x1000, "eax", 1)],
                    jump: Some(0x1010),
                    fail: None,
                    targets: vec![],
                },
                Block {
                    addr: 0x1010,
                    instrs: vec![add_reg(0x1010, "ebx", "eax"), vexit(0x1014)],
                    jump: None,
                    fail: None,
                    targets: vec![],
                },
            ],
        };
        let cfg = Cfg::build(&routine);
        let live_out = compute_live_out(&routine, &cfg);
        assert!(live_out[&0x1000].contains(&Register::Physical("rax".into())));
        // Nothing reads ebx after B1's own use of it, and it has no successor.
        assert!(live_out[&0x1010].is_empty());
    }

    #[test]
    fn sub_register_write_keeps_a_full_register_read_live() {
        // B0: eax = 1 ; jmp B1     (write via the 32-bit name)
        // B1: ecx = rax + 1 ; vexit (read via the 64-bit name)
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![
                Block {
                    addr: 0x1000,
                    instrs: vec![mov_imm(0x1000, "eax", 1)],
                    jump: Some(0x1010),
                    fail: None,
                    targets: vec![],
                },
                Block {
                    addr: 0x1010,
                    instrs: vec![
                        Instr {
                            addr: 0x1010,
                            op: Op::Add,
                            operands: vec![
                                Operand::Reg(Register::Physical("ecx".into())),
                                Operand::Reg(Register::Physical("rax".into())),
                            ],
                            target: None,
                            fallthrough: None,
                            native: String::new(),
                        },
                        vexit(0x1014),
                    ],
                    jump: None,
                    fail: None,
                    targets: vec![],
                },
            ],
        };
        let cfg = Cfg::build(&routine);
        let live_out = compute_live_out(&routine, &cfg);
        assert!(
            live_out[&0x1000].contains(&Register::Physical("rax".into())),
            "eax write must stay live across the rax read in the successor: {:?}",
            live_out[&0x1000]
        );
    }

    #[test]
    fn a_write_never_read_by_any_successor_is_not_live_out() {
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![Block {
                addr: 0x1000,
                instrs: vec![mov_imm(0x1000, "eax", 1), vexit(0x1004)],
                jump: None,
                fail: None,
                targets: vec![],
            }],
        };
        let cfg = Cfg::build(&routine);
        let live_out = compute_live_out(&routine, &cfg);
        assert!(live_out[&0x1000].is_empty());
    }

    #[test]
    fn loop_back_edge_keeps_a_counter_live() {
        // B0 (entry): ecx = 0 ; jmp B1
        // B1 (loop header): ecx = ecx + 1 ; jmp B1 (self-loop)
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![
                Block {
                    addr: 0x1000,
                    instrs: vec![mov_imm(0x1000, "ecx", 0)],
                    jump: Some(0x1010),
                    fail: None,
                    targets: vec![],
                },
                Block {
                    addr: 0x1010,
                    instrs: vec![Instr {
                        addr: 0x1010,
                        op: Op::Add,
                        operands: vec![
                            Operand::Reg(Register::Physical("ecx".into())),
                            Operand::Imm(1),
                        ],
                        target: None,
                        fallthrough: None,
                        native: String::new(),
                    }],
                    jump: Some(0x1010),
                    fail: None,
                    targets: vec![],
                },
            ],
        };
        let cfg = Cfg::build(&routine);
        let live_out = compute_live_out(&routine, &cfg);
        // The loop header reads its own `ecx` on the next iteration (the
        // back edge), so `ecx` must be live out of the entry block and live
        // out of the header itself.
        assert!(live_out[&0x1000].contains(&Register::Physical("rcx".into())));
        assert!(live_out[&0x1010].contains(&Register::Physical("rcx".into())));
    }
}
