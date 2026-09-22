# VTIL-style lifting (`analyze op:"lift"`)

`crates/recurse-vtil` lifts a function's backend-neutral disassembly into a
small, [VTIL](https://github.com/vtil-project)-inspired intermediate
language, runs an optimizer pass pipeline over it, and renders VTIL-style
text. It is exposed through the existing single analysis tool as
`analyze op:"lift" addr:<target>` — no new tool, no UI-specific wiring,
consistent with [backends.md](backends.md)'s "one backend-neutral tool"
design.

```text
$ analyze op:"lift" addr:"check_key"
{
  "op": "lift",
  "addr": 4198400,
  "name": "check_key",
  "instructions": 11,
  "vtil": "begin_routine 0x401000 \"check_key\"\nblock_0x401000:\n  ...\nend_routine\n",
  "optimized": { "rounds": 3, "propagated": 4, "folded": 2, "simplified": 1, "dead_stores_removed": 1, "branches_resolved": 1 }
}
```

## Why

VM-based obfuscators (VMProtect and similar) and hand-rolled opaque
predicates turn a small amount of real logic into a lot of dispatcher noise:
flags juggling, stack shuffling, and conditional branches whose condition is
actually a compile-time constant once you trace it. Reading that directly as
x86 disassembly is exactly the workload
[VTIL-Core](https://github.com/vtil-project/VTIL-Core) — "Virtual-machine
Translation Intermediate Language" — was built to strip away: lift native
code into a small IL that keeps physical registers and the stack intact
(unlike LLVM, which abstracts them into an infinite SSA register file and is
therefore a poor fit for *this* direction of the problem — see
[llvm-project](https://github.com/llvm/llvm-project) for what that
alternative shape looks like), then run classic optimizer passes
(propagation, folding, dead-code elimination, branch correction) over it
until only the real control flow and the real computation survive.

## What's actually implemented, and what isn't

VTIL-Core ships the IR (`VTIL-Architecture`), an optimizer pass pipeline
(`VTIL-Optimizer`, referenced from its history — not present in the current
public tree), a symbolic VM, and an amd64 disassembler/assembler utility. By
its own README ("this repository is currently incomplete"), it never shipped
the x86-to-VTIL *lifter* — the part that actually reads native instructions
and produces `vtil::instruction`s. The organization's other public
repositories ([vtil-project/\*](https://github.com/orgs/vtil-project/repositories))
and the community C# continuation [vtil2](https://github.com/pop-rip/vtil2)
inherit the same gap: the IR and optimizer pass *names* are public and
well-documented; the lifter is not.

`recurse-vtil` is an independent, from-scratch implementation of that
missing half, written for Recurse specifically:

- **`il.rs`** — the IL types. Opcode names follow VTIL-Architecture's public
  [`instruction_set.hpp`](https://github.com/vtil-project/VTIL-Core/blob/master/VTIL-Architecture/arch/instruction_set.hpp)
  exactly where a semantic matches (`mov`, `movsx`, `str`, `ldd`, `neg`,
  `add`/`sub`/`mul`/`imul`/`div`/`idiv`, the bitwise family, the `t*`
  relational family, `js`/`jmp`/`vexit`/`vxcall`, `nop`/`vemit`). A handful
  of opcodes are this crate's own extensions where upstream's instruction
  set doesn't need to distinguish a case Recurse's input does (`lea`,
  `movzx`, `sar`, and the not-yet-raised `jcc`) — each is called out in its
  doc comment.
- **`lift.rs`** — parses the same `"mnemonic operand, operand"` text every
  `Engine::function_graph` already returns (not Capstone details), so it
  runs unchanged against the native backend or r2. Control-flow shape comes
  from the backend-neutral `kind` classification (architecture-independent);
  the mnemonic dispatch that recovers data semantics targets x86/x86-64.
  `cmp`/`test` + `Jcc` pairs are raised to VTIL's own `t*` + `js` — the
  native flags register never appears in the IL at all. `push`/`pop` are
  decomposed into `sub`/`str` and `ldd`/`add`, since VTIL has no dedicated
  stack opcode (the virtual stack is a property of its optimizer, not its
  base instruction set). Anything not modelled yet — `adc`/`sbb`, `xchg`,
  `cmov*`/`set*`, SIMD, other architectures' mnemonics — becomes `vemit`
  (VTIL's own escape hatch), carrying the original text verbatim. The
  translation is total: nothing is dropped, just left opaque.
- **`opt.rs`** — copy/constant propagation with folding
  (`MovPropagationPass`/`CollectivePropagationPass`), dead-store elimination
  (`DeadCodeEliminationPass`), single/two-instruction algebraic identities
  (`SymbolicRewritePass`, narrow end: idempotence, the identity element, the
  annihilator, self-inverses, double negation/complement), and constant
  branch resolution (`BranchCorrectionPass`) — collapsing a `js` whose
  condition folded to a literal into the one real `jmp`. Propagation and
  dead-store elimination run over the **whole routine**
  (`crates/recurse-vtil/src/cfg.rs`, `liveness.rs`, `regalias.rs`): a
  constant known on every path into a block is known inside it (forward
  "must" dataflow with a worklist fixpoint, merging — keeping a fact only
  where every predecessor agrees — at joins), and a write that reaches a
  block's end is deleted once whole-routine liveness proves no reachable
  successor can read it, under a register-aliasing model (`eax`/`ax`/`al`
  are the same storage as `rax`) so that check is sound. This is what makes
  a VM dispatcher's opcode compare chain actually resolvable: the opcode
  fetch and the compare it feeds are almost never in the same block. See
  the module doc in `crates/recurse-vtil/src/opt.rs` for where this still
  stops short of VTIL's real optimizer — no memory/alias analysis
  (`Ldd`/`Str` are opaque to every pass here).
- **`symex.rs`** — VTIL's own `symex` (`tracer`/`variable`/`pointer`/
  `memory`/`context`) is the part of the real project this crate had not
  attempted until now: registers tracked as symbolic expression trees
  (`Expr`), not just a literal-or-copy fact, over the same whole-routine
  `Cfg`/worklist shape `opt.rs` uses. This resolves identities constant
  folding structurally cannot see — `(a ^ b) ^ b` collapses to `a`
  symbolically even when `a`/`b` are never literal on any path, which is
  exactly the double-XOR-with-the-same-key idiom RE keeps running into.
  Every `Expr::Unknown` (a load, a call result, an unmodelled opcode) is a
  fresh, distinct value — never treated as equal to any other unknown —
  which is what keeps the simplifier sound; see the module doc for the
  regression test that guards exactly that. Still registers only: a
  computed jump/call target is never resolved, since nothing read from
  memory is more than opaque input here (VTIL's own `pointer`/`memory`
  machinery is what would move that boundary, and remains future work for
  this crate too).
- **`decompile.rs`** — a structuring decompiler over the optimized IL,
  wired into `NativeEngine::decompile` (`capabilities().decompile` is now
  `true` for the native backend — the single biggest gap the original
  improvement list named: "`Engine::decompile` on native is a hard `Err`").
  Cooper/Harvey/Kennedy dominators plus back-edge detection
  (`cfg.rs`) drive two recognisers: `if`/`else` (a two-successor block that
  isn't a loop header) and `while` (a two-successor block that *is* a loop
  header, where exactly one successor can reach the header again — forward
  reachability, not dominance: a loop's sole exit block is typically
  dominated by the header too, since it has no other way in, so dominance
  alone can't tell "inside the loop" from "only reachable through the
  loop" apart). Whatever isn't recognised (irreducible control flow, a
  shared join point already emitted) falls back to a labelled `goto` —
  never wrong, just not prettified — and every block is always labelled
  for exactly that reason. No type/variable recovery, no calling-convention
  awareness: this reads operands and renders `dst = dst OP rhs;`-shaped
  statements directly from the IL, not from `symex::Expr` (a caller can
  still run that separately and cross-reference by address; folding it into
  this rendering is future work). Total coverage holds here too: an
  unlifted instruction still appears, as an `__asm("...")` line.
- **`text.rs`** — a VTIL-style `begin_routine`/`block_0x...`/`end_routine`
  dump, the same reading convention as VTIL-Core's own
  `Sample Routines/*.vtil` files.

### A soundness bug the decompiler's own tests caught

Worth recording plainly: writing `decompile.rs`'s loop-recognition test
(a real `for`-shaped counter loop) surfaced a genuine bug in
`opt::propagate_and_fold_global` from the whole-routine dataflow work —
not a decompiler bug. The original implementation mutated instructions
*during* the fixpoint, from whatever `known_in` a block's first visit
happened to see. A loop header's first visit only ever sees its entry
edge (the back edge's predecessor state doesn't exist yet), so a
loop-carried counter looked constant for exactly one premature pass —
long enough to rewrite `add ecx, 1` down to `mov ecx, 1` before the
analysis ever widened to the correct "unknown across the loop" fact,
at which point the increment was already gone and unrecoverable,
producing a folded-to-always-true condition and an infinite loop in the
*rendered* pseudocode. The fix (now in `opt.rs`) separates the two
phases every dataflow-with-transformation pass needs: converge
`known_in`/`known_out` first, over throwaway clones of each block's
instructions (no mutation of `routine` at all), then rewrite each block
exactly once from its final, fully-converged state. See
`propagate_and_fold_global`'s doc comment for the full explanation, and
`decompile::tests::self_loop_becomes_a_while_loop` /
`opt::tests::constant_setcond_resolves_js_to_unconditional_jmp` for the
regression coverage.

## Trying it

```bash
cargo test -p recurse-vtil
cargo test -p recurse-static lift
```

`crates/recurse-vtil/src/lib.rs` has two end-to-end tests:
`lifts_and_folds_an_opaque_predicate_to_one_edge` (single block) and
`resolves_a_branch_whose_constant_flows_through_an_unrelated_block`, which
is the whole-routine case — a value set in one block, passed through a
block that never mentions it, resolves a compare in a third block, and the
now-dead setup instruction in the first block is removed once nothing
reachable still needs it.
