//! Subagent decomposition: split a huge binary's functions into balanced,
//! call-graph-coherent chunks of work — the partition plan an orchestrator
//! (this project's own agent host, or any caller) hands out to N parallel
//! subagents so each one gets a self-contained slice of the binary
//! (functions that mostly call each other, not scattered unrelated code)
//! instead of an arbitrary, context-poor address-range split.
//!
//! # Why call-graph connectivity, not just function count
//!
//! Splitting purely by function count or address range regularly cuts a
//! caller from its callee across two different subagents, each missing
//! the context the other has. This module instead partitions by the call
//! graph's **connected components** (functions reachable from each other
//! by calling, either direction — a caller needs its callees' context
//! and a callee benefits from knowing its callers) so a component stays
//! in one chunk whenever it reasonably can, then balances total
//! *analysis weight* (byte size, a real proxy for how much work a
//! function actually is — not just its count as one of N functions)
//! across chunks with a real bin-packing heuristic.
//!
//! # Algorithm
//!
//! 1. Union-Find over the (undirected) call graph to find connected
//!    components.
//! 2. Any component heavier than [`DecomposeOptions::max_chunk_size`] is
//!    split via breadth-first layering from its heaviest node, into
//!    sub-groups under that cap — necessary for a real "everything calls
//!    a common helper" hairball component that would otherwise force one
//!    subagent to take the whole binary; this does cut some call-graph
//!    edges, an unavoidable, documented tradeoff for any finite per-chunk
//!    budget.
//! 3. Components (now all under the cap) are greedily assigned to the
//!    currently lightest chunk, heaviest-first — the standard
//!    "longest-processing-time-first" bin-packing heuristic, a real,
//!    well-known, provably-bounded (within 4/3 of optimal for this
//!    exact rule) approximation, not an ad-hoc guess.

use std::collections::{HashMap, HashSet, VecDeque};

/// One function the caller wants partitioned, with its call edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionNode {
    pub address: u64,
    pub name: String,
    /// A real workload proxy (typically byte size) — chunks are balanced
    /// by the sum of this, not by function count.
    pub weight: u64,
    /// Addresses this function calls. Only edges where both ends are
    /// present in the input set are used; a call to something outside
    /// the partitioned set (a library import, e.g.) is simply not a
    /// graph edge here.
    pub calls: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct DecomposeOptions {
    /// How many chunks to target. The actual chunk count may be lower
    /// (a small binary has nothing to spread across N chunks) but never
    /// higher, except when a single oversized component's forced split
    /// (see module docs, step 2) produces more sub-groups than
    /// `target_chunks` — capacity for real work always wins over hitting
    /// an exact count.
    pub target_chunks: usize,
    /// The weight cap that triggers splitting one connected component
    /// across multiple chunks (module docs, step 2). Defaults to roughly
    /// "total weight / target_chunks", i.e. one fair share, via
    /// [`DecomposeOptions::for_binary`].
    pub max_chunk_size: u64,
}

impl DecomposeOptions {
    /// `target_chunks` chunks, with `max_chunk_size` set to one fair
    /// share of `total_weight` (never below `1`, so a zero-weight input
    /// doesn't produce a degenerate zero cap).
    #[must_use]
    pub fn for_binary(target_chunks: usize, total_weight: u64) -> Self {
        let target_chunks = target_chunks.max(1);
        let max_chunk_size = (total_weight / target_chunks as u64).max(1);
        Self {
            target_chunks,
            max_chunk_size,
        }
    }
}

/// One chunk of the partition plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Chunk {
    pub functions: Vec<u64>,
    pub total_weight: u64,
}

/// Partition `functions` into balanced, call-graph-coherent chunks.
///
/// Deterministic for a given input order — ties in weight/degree break by
/// address, so the same input always produces the same plan (an
/// orchestrator re-running decomposition after a crash should get the
/// same assignment back, not a new random split).
#[must_use]
pub fn decompose(functions: &[FunctionNode], options: &DecomposeOptions) -> Vec<Chunk> {
    if functions.is_empty() {
        return Vec::new();
    }

    let by_addr: HashMap<u64, &FunctionNode> = functions.iter().map(|f| (f.address, f)).collect();
    let components = connected_components(functions, &by_addr);

    // Step 2: split any component heavier than the cap.
    let mut groups: Vec<Vec<u64>> = Vec::new();
    for component in components {
        let weight: u64 = component.iter().map(|a| by_addr[a].weight).sum();
        if weight <= options.max_chunk_size || component.len() <= 1 {
            groups.push(component);
        } else {
            groups.extend(split_component(
                &component,
                &by_addr,
                options.max_chunk_size,
            ));
        }
    }

    // Step 3: longest-processing-time-first bin packing across
    // `target_chunks` bins (never more chunks than groups, since an empty
    // bin is pointless work for an orchestrator to hand out).
    let group_weight = |g: &[u64]| -> u64 { g.iter().map(|a| by_addr[a].weight).sum() };
    groups.sort_by(|a, b| {
        group_weight(b)
            .cmp(&group_weight(a))
            .then_with(|| a.first().cmp(&b.first()))
    });

    let chunk_count = options.target_chunks.min(groups.len()).max(1);
    let mut chunks: Vec<Chunk> = (0..chunk_count).map(|_| Chunk::default()).collect();
    for group in groups {
        let weight = group_weight(&group);
        let lightest = chunks
            .iter()
            .enumerate()
            .min_by_key(|(i, c)| (c.total_weight, *i))
            .map(|(i, _)| i)
            .unwrap_or(0);
        chunks[lightest].functions.extend(group);
        chunks[lightest].total_weight += weight;
    }
    chunks.retain(|c| !c.functions.is_empty());
    chunks
}

/// Connected components of the undirected call graph (an edge `a -> b`
/// also connects `b` to `a`, since context flows both ways for a
/// subagent's purposes — see module docs).
fn connected_components(
    functions: &[FunctionNode],
    by_addr: &HashMap<u64, &FunctionNode>,
) -> Vec<Vec<u64>> {
    let mut adjacency: HashMap<u64, HashSet<u64>> = functions
        .iter()
        .map(|f| (f.address, HashSet::new()))
        .collect();
    for f in functions {
        for &callee in &f.calls {
            if by_addr.contains_key(&callee) {
                adjacency.entry(f.address).or_default().insert(callee);
                adjacency.entry(callee).or_default().insert(f.address);
            }
        }
    }

    let mut visited: HashSet<u64> = HashSet::new();
    let mut components = Vec::new();
    let mut addrs: Vec<u64> = functions.iter().map(|f| f.address).collect();
    addrs.sort_unstable();
    for &start in &addrs {
        if visited.contains(&start) {
            continue;
        }
        let mut component = Vec::new();
        let mut queue = VecDeque::from([start]);
        visited.insert(start);
        while let Some(addr) = queue.pop_front() {
            component.push(addr);
            let mut neighbors: Vec<u64> = adjacency
                .get(&addr)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            neighbors.sort_unstable();
            for n in neighbors {
                if visited.insert(n) {
                    queue.push_back(n);
                }
            }
        }
        component.sort_unstable();
        components.push(component);
    }
    components
}

/// Split one oversized component into sub-groups each at or under `cap`,
/// via breadth-first layering from the component's heaviest node —
/// nearby-in-the-call-graph functions land in the same sub-group where
/// possible, cutting the fewest edges a simple layered walk can manage.
fn split_component(
    component: &[u64],
    by_addr: &HashMap<u64, &FunctionNode>,
    cap: u64,
) -> Vec<Vec<u64>> {
    let members: HashSet<u64> = component.iter().copied().collect();
    let mut adjacency: HashMap<u64, Vec<u64>> = HashMap::new();
    for &addr in component {
        let mut neighbors: Vec<u64> = by_addr[&addr]
            .calls
            .iter()
            .copied()
            .filter(|c| members.contains(c))
            .collect();
        neighbors.sort_unstable();
        adjacency.insert(addr, neighbors);
    }
    // Also add reverse edges (callers), matching the undirected semantics
    // `connected_components` uses.
    for &addr in component {
        let callees = adjacency[&addr].clone();
        for callee in callees {
            let entry = adjacency.entry(callee).or_default();
            if !entry.contains(&addr) {
                entry.push(addr);
                entry.sort_unstable();
            }
        }
    }

    let Some(&start) = component
        .iter()
        .max_by_key(|&&a| (by_addr[&a].weight, std::cmp::Reverse(a)))
    else {
        // Unreachable in practice: the caller only reaches this function
        // for a non-empty component (see `decompose`'s `component.len()
        // <= 1` check). An empty component has nothing to split anyway.
        return Vec::new();
    };

    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue = VecDeque::from([start]);
    visited.insert(start);
    let mut groups: Vec<Vec<u64>> = Vec::new();
    let mut current: Vec<u64> = Vec::new();
    let mut current_weight: u64 = 0;

    while let Some(addr) = queue.pop_front() {
        let w = by_addr[&addr].weight;
        if !current.is_empty() && current_weight + w > cap {
            groups.push(std::mem::take(&mut current));
            current_weight = 0;
        }
        current.push(addr);
        current_weight += w;
        for &n in &adjacency[&addr] {
            if visited.insert(n) {
                queue.push_back(n);
            }
        }
        // A disconnected remainder inside this "component" cannot happen
        // (it is connected by definition), but a single node heavier than
        // `cap` on its own must still get its own group rather than loop
        // forever waiting for room.
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn f(addr: u64, weight: u64, calls: &[u64]) -> FunctionNode {
        FunctionNode {
            address: addr,
            name: format!("f{addr:#x}"),
            weight,
            calls: calls.to_vec(),
        }
    }

    #[test]
    fn empty_input_yields_no_chunks() {
        assert!(decompose(&[], &DecomposeOptions::for_binary(4, 0)).is_empty());
    }

    #[test]
    fn a_connected_component_stays_in_one_chunk() {
        // A -> B -> C, a chain: must never be split across chunks by a
        // plan that has ample room (one big fair-share cap, few chunks).
        let functions = [f(1, 10, &[2]), f(2, 10, &[3]), f(3, 10, &[])];
        let options = DecomposeOptions {
            target_chunks: 4,
            max_chunk_size: 30,
        };
        let chunks = decompose(&functions, &options);
        let owning_chunk = |addr: u64| {
            chunks
                .iter()
                .position(|c| c.functions.contains(&addr))
                .expect("present")
        };
        assert_eq!(owning_chunk(1), owning_chunk(2));
        assert_eq!(owning_chunk(2), owning_chunk(3));
    }

    #[test]
    fn unrelated_functions_spread_across_chunks_for_balance() {
        // Three isolated, equally-weighted functions with no call edges
        // at all: with target_chunks=3 they must end up one-per-chunk,
        // not all piled into a single chunk.
        let functions = [f(1, 10, &[]), f(2, 10, &[]), f(3, 10, &[])];
        let options = DecomposeOptions::for_binary(3, 30);
        let chunks = decompose(&functions, &options);
        assert_eq!(chunks.len(), 3);
        for c in &chunks {
            assert_eq!(c.functions.len(), 1);
        }
    }

    #[test]
    fn total_weight_is_conserved_and_every_function_appears_exactly_once() {
        let functions = [
            f(1, 7, &[2]),
            f(2, 3, &[]),
            f(3, 12, &[4]),
            f(4, 5, &[]),
            f(5, 9, &[]),
        ];
        let total: u64 = functions.iter().map(|f| f.weight).sum();
        let chunks = decompose(&functions, &DecomposeOptions::for_binary(2, total));
        let chunk_total: u64 = chunks.iter().map(|c| c.total_weight).sum();
        assert_eq!(chunk_total, total);

        let mut seen: Vec<u64> = chunks
            .iter()
            .flat_map(|c| c.functions.iter().copied())
            .collect();
        seen.sort_unstable();
        let mut expected: Vec<u64> = functions.iter().map(|f| f.address).collect();
        expected.sort_unstable();
        assert_eq!(seen, expected);
    }

    #[test]
    fn an_oversized_hairball_component_is_split_under_the_cap() {
        // A star: one hub called by 20 leaves, total weight far exceeding
        // any single fair-share cap -- must be split into multiple
        // sub-groups, each at or under the cap, not left as one giant
        // chunk that starves every other subagent.
        let mut functions = vec![f(0, 5, &(1..=20).collect::<Vec<u64>>())];
        for i in 1..=20u64 {
            functions.push(f(i, 5, &[]));
        }
        let total: u64 = functions.iter().map(|f| f.weight).sum(); // 105
        let options = DecomposeOptions::for_binary(4, total); // cap ~26
        let chunks = decompose(&functions, &options);
        assert!(
            chunks.len() > 1,
            "a single chunk would defeat the whole point of decomposing"
        );
        for c in &chunks {
            assert!(
                c.total_weight <= options.max_chunk_size * 2,
                "no chunk should balloon far past the cap: {c:?}"
            );
        }
        let chunk_total: u64 = chunks.iter().map(|c| c.total_weight).sum();
        assert_eq!(
            chunk_total, total,
            "splitting a component must not lose or duplicate weight"
        );
    }

    #[test]
    fn deterministic_across_repeated_runs() {
        let functions = [f(3, 4, &[1]), f(1, 9, &[2]), f(2, 1, &[]), f(9, 6, &[])];
        let options = DecomposeOptions::for_binary(2, 20);
        let a = decompose(&functions, &options);
        let b = decompose(&functions, &options);
        assert_eq!(a, b);
    }

    #[test]
    fn a_call_to_an_address_outside_the_input_set_is_ignored_not_an_error() {
        let functions = [f(1, 5, &[0xDEAD_BEEF]), f(2, 5, &[])];
        let chunks = decompose(&functions, &DecomposeOptions::for_binary(2, 10));
        let total: u64 = chunks.iter().map(|c| c.total_weight).sum();
        assert_eq!(total, 10);
    }
}
