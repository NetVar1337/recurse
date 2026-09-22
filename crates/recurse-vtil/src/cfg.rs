//! Control-flow graph utilities shared by the optimizer's whole-routine
//! passes ([`crate::opt`], [`crate::liveness`]) and, eventually, any pass
//! that needs reachability over a [`Routine`] — a future decompiler's
//! structuring pass, chief among them.

use crate::il::Routine;
use std::collections::{HashMap, HashSet};

/// The successor/predecessor edges of a [`Routine`], keyed by block address.
/// A target that is not itself a block address in this routine (a tail call,
/// an indirect jump leaving the function, a `vexit`, an unresolved computed
/// jump) is simply absent — as far as this routine's own control flow is
/// concerned, it ends there.
#[derive(Clone, Debug, Default)]
pub struct Cfg {
    /// Block addresses in the routine's original order (entry first).
    pub order: Vec<u64>,
    pub succ: HashMap<u64, Vec<u64>>,
    pub pred: HashMap<u64, Vec<u64>>,
}

impl Cfg {
    /// Build the graph from each block's `jump`/`fail`/`targets` edges.
    pub fn build(routine: &Routine) -> Self {
        let known: HashSet<u64> = routine.blocks.iter().map(|b| b.addr).collect();
        let mut succ: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut order = Vec::with_capacity(routine.blocks.len());

        for block in &routine.blocks {
            order.push(block.addr);
            let mut outs: Vec<u64> = Vec::new();
            let push = |addr: u64, outs: &mut Vec<u64>| {
                if known.contains(&addr) && !outs.contains(&addr) {
                    outs.push(addr);
                }
            };
            if let Some(j) = block.jump {
                push(j, &mut outs);
            }
            if let Some(f) = block.fail {
                push(f, &mut outs);
            }
            for &t in &block.targets {
                push(t, &mut outs);
            }
            succ.insert(block.addr, outs);
        }

        let mut pred: HashMap<u64, Vec<u64>> = HashMap::new();
        for (&from, outs) in &succ {
            for &to in outs {
                pred.entry(to).or_default().push(from);
            }
        }

        Cfg { order, succ, pred }
    }

    pub fn successors(&self, addr: u64) -> &[u64] {
        self.succ.get(&addr).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn predecessors(&self, addr: u64) -> &[u64] {
        self.pred.get(&addr).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::il::Block;

    fn block(addr: u64, jump: Option<u64>, fail: Option<u64>) -> Block {
        Block {
            addr,
            instrs: vec![],
            jump,
            fail,
            targets: vec![],
        }
    }

    #[test]
    fn builds_edges_and_ignores_out_of_routine_targets() {
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![
                block(0x1000, Some(0x2000), Some(0x1010)),
                block(0x1010, Some(0x2000), None),
                block(0x2000, None, None),
            ],
        };
        let cfg = Cfg::build(&routine);
        assert_eq!(cfg.successors(0x1000), &[0x2000, 0x1010]);
        assert_eq!(cfg.successors(0x1010), &[0x2000]);
        assert_eq!(cfg.successors(0x2000), &[] as &[u64]);
        let mut preds_2000 = cfg.predecessors(0x2000).to_vec();
        preds_2000.sort_unstable();
        assert_eq!(preds_2000, vec![0x1000, 0x1010]);

        // A jump to an address with no block in this routine (tail call,
        // indirect target left unresolved) is simply not an edge.
        let escapes = Routine {
            entry: 0x3000,
            name: "g".into(),
            blocks: vec![block(0x3000, Some(0x9999), None)],
        };
        assert_eq!(Cfg::build(&escapes).successors(0x3000), &[] as &[u64]);
    }
}
