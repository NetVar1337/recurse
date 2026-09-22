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

    /// Immediate dominators of every block reachable from `entry`, via the
    /// standard Cooper/Harvey/Kennedy iterative algorithm over a reverse
    /// postorder numbering. `idom[entry] == entry` (the conventional
    /// self-loop marking the root); a block unreachable from `entry` is
    /// simply absent — used by [`crate::decompile`] to structure `if`/`while`
    /// and by [`back_edges`](Self::back_edges) to find loop headers.
    pub fn immediate_dominators(&self, entry: u64) -> HashMap<u64, u64> {
        let rpo = self.reverse_postorder(entry);
        let index_of: HashMap<u64, usize> = rpo.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        let mut idom: HashMap<u64, u64> = HashMap::new();
        idom.insert(entry, entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &node in rpo.iter().skip(1) {
                let preds: Vec<u64> = self
                    .predecessors(node)
                    .iter()
                    .copied()
                    .filter(|p| idom.contains_key(p))
                    .collect();
                let Some(&first) = preds.first() else {
                    continue;
                };
                let mut new_idom = first;
                for &p in preds.iter().skip(1) {
                    new_idom = intersect(&idom, &index_of, new_idom, p);
                }
                if idom.get(&node) != Some(&new_idom) {
                    idom.insert(node, new_idom);
                    changed = true;
                }
            }
        }
        idom
    }

    /// Every back edge `(from, to)` — an edge whose target dominates its
    /// source — reachable from `entry`. `to` is a loop header exactly when
    /// it appears as some edge's target here.
    pub fn back_edges(&self, entry: u64) -> HashSet<(u64, u64)> {
        let idom = self.immediate_dominators(entry);
        let mut out = HashSet::new();
        for &from in &self.order {
            for &to in self.successors(from) {
                if dominates(&idom, to, from) {
                    out.insert((from, to));
                }
            }
        }
        out
    }

    fn reverse_postorder(&self, entry: u64) -> Vec<u64> {
        let mut visited: HashSet<u64> = HashSet::new();
        let mut postorder: Vec<u64> = Vec::new();
        let mut stack: Vec<(u64, usize)> = Vec::new();
        visited.insert(entry);
        stack.push((entry, 0));

        while let Some(top) = stack.last_mut() {
            let (node, idx) = (top.0, top.1);
            let succs = self.successors(node);
            if idx < succs.len() {
                let child = succs[idx];
                top.1 += 1;
                if visited.insert(child) {
                    stack.push((child, 0));
                }
            } else {
                postorder.push(node);
                stack.pop();
            }
        }
        postorder.reverse();
        postorder
    }
}

fn intersect(idom: &HashMap<u64, u64>, index_of: &HashMap<u64, usize>, a: u64, b: u64) -> u64 {
    let mut a = a;
    let mut b = b;
    loop {
        if a == b {
            return a;
        }
        let ia = *index_of.get(&a).unwrap_or(&usize::MAX);
        let ib = *index_of.get(&b).unwrap_or(&usize::MAX);
        if ia > ib {
            a = *idom.get(&a).unwrap_or(&a);
        } else {
            b = *idom.get(&b).unwrap_or(&b);
        }
    }
}

/// True when `a` dominates `b` in `idom` (every path from the routine's
/// entry to `b` passes through `a`) — `a == b` counts as dominating itself.
pub fn dominates(idom: &HashMap<u64, u64>, a: u64, b: u64) -> bool {
    if a == b {
        return true;
    }
    let mut cur = b;
    let mut guard = 0usize;
    while let Some(&next) = idom.get(&cur) {
        if next == cur {
            break;
        }
        if next == a {
            return true;
        }
        cur = next;
        guard += 1;
        if guard > 1_000_000 {
            break;
        }
    }
    false
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

    #[test]
    fn diamond_dominators_and_no_back_edges() {
        // 0x1000 -> {0x1010, 0x1020} -> 0x1030
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![
                block(0x1000, Some(0x1010), Some(0x1020)),
                block(0x1010, Some(0x1030), None),
                block(0x1020, Some(0x1030), None),
                block(0x1030, None, None),
            ],
        };
        let cfg = Cfg::build(&routine);
        let idom = cfg.immediate_dominators(0x1000);
        assert_eq!(idom[&0x1000], 0x1000);
        assert_eq!(idom[&0x1010], 0x1000);
        assert_eq!(idom[&0x1020], 0x1000);
        // The merge point is dominated by the header, not by either arm.
        assert_eq!(idom[&0x1030], 0x1000);
        assert!(dominates(&idom, 0x1000, 0x1030));
        assert!(!dominates(&idom, 0x1010, 0x1030));
        assert!(cfg.back_edges(0x1000).is_empty());
    }

    #[test]
    fn self_loop_is_its_own_back_edge_and_header() {
        let routine = Routine {
            entry: 0x1000,
            name: "f".into(),
            blocks: vec![
                block(0x1000, Some(0x1010), None),
                block(0x1010, Some(0x1010), Some(0x1020)),
                block(0x1020, None, None),
            ],
        };
        let cfg = Cfg::build(&routine);
        let back_edges = cfg.back_edges(0x1000);
        assert!(back_edges.contains(&(0x1010, 0x1010)));
        assert_eq!(back_edges.len(), 1);
    }
}
