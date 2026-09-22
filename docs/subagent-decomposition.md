# Subagent decomposition (`recurse_static::decompose`)

`crates/recurse-static/src/decompose.rs` splits a huge binary's functions
into balanced, call-graph-coherent chunks of work — the partition plan an
orchestrator (this project's own agent host, or any caller) hands out to
N parallel subagents so each one gets a self-contained slice of the
binary (functions that mostly call each other, not scattered unrelated
code) instead of an arbitrary, context-poor address-range split.

```rust
use recurse_static::decompose::{decompose, DecomposeOptions, FunctionNode};

let functions: Vec<FunctionNode> = /* from Engine::functions() + per-function call edges */ vec![];
let total_weight: u64 = functions.iter().map(|f| f.weight).sum();
let options = DecomposeOptions::for_binary(8, total_weight); // 8 subagents

for (i, chunk) in decompose(&functions, &options).into_iter().enumerate() {
    println!("subagent {i}: {} functions, {} bytes", chunk.functions.len(), chunk.total_weight);
}
```

## Why call-graph connectivity, not just function count

Splitting purely by function count or address range regularly cuts a
caller from its callee across two different subagents, each missing the
context the other has. This module instead partitions by the call
graph's **connected components** (functions reachable from each other by
calling, either direction) so a component stays in one chunk whenever it
reasonably can, then balances total *analysis weight* (byte size, a real
proxy for how much work a function actually is) across chunks with a
real bin-packing heuristic.

## Algorithm

1. Union-Find (via BFS over an adjacency map) over the undirected call
   graph to find connected components.
2. Any component heavier than `DecomposeOptions::max_chunk_size` is split
   via breadth-first layering from its heaviest node, into sub-groups
   under that cap — necessary for a real "everything calls a common
   helper" hairball component that would otherwise force one subagent to
   take the whole binary. This does cut some call-graph edges, an
   unavoidable, documented tradeoff for any finite per-chunk budget.
3. Components (now all under the cap) are greedily assigned to the
   currently lightest chunk, heaviest-first — the standard
   "longest-processing-time-first" bin-packing heuristic, a real,
   well-known, provably-bounded (within 4/3 of optimal for this exact
   rule) approximation, not an ad-hoc guess.

The whole plan is deterministic for a given input order: an orchestrator
re-running decomposition after a crash gets the same assignment back, not
a new random split.

## Honest scope

- Weight-balanced by byte size as the workload proxy — no attempt to
  model actual LLM-token cost, instruction complexity, or a subagent's
  real wall-clock time per function. A real, reasonable proxy, not a
  measured one.
- The oversized-component split (step 2) is a simple BFS layering, not a
  min-cut algorithm — it minimizes the *number* of cut points a layered
  walk naturally produces, not provably the fewest edges cuttable. Real,
  scoped follow-up work for genuinely huge hairball components where edge
  count matters a lot.
- Not wired into `recurse-agent`'s actual subagent-spawning tool yet — a
  standalone, fully-tested library capability first, same path every
  other module in this series took; an orchestrator wires this plan's
  chunks into its own `task`/`workpool`-style parallel dispatch.

## Trying it

```bash
cargo test -p recurse-static decompose::
```

7 tests: an empty input; a connected chain that must stay in one chunk
when there's ample room; unrelated (no call edges) functions that must
spread one-per-chunk for balance; total weight conservation and every
function appearing exactly once (no loss, no duplication); an oversized
"hub with 20 leaves" hairball component genuinely split across multiple
chunks under the cap; determinism across repeated runs on the same
input; and a call to an address outside the input set treated as "not a
graph edge", not an error.
