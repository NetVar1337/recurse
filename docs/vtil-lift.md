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
  (`MovPropagationPass`/`CollectivePropagationPass`), local dead-store
  elimination (`DeadCodeEliminationPass`, the sound-without-whole-routine-
  liveness subset), single/two-instruction algebraic identities
  (`SymbolicRewritePass`, narrow end: idempotence, the identity element, the
  annihilator, self-inverses, double negation/complement), and constant
  branch resolution (`BranchCorrectionPass`) — collapsing a `js` whose
  condition folded to a literal into the one real `jmp`, which is the
  concrete, testable version of "the dispatcher's opaque predicate
  disappears." Every pass is block-local by design; see the module doc in
  `crates/recurse-vtil/src/opt.rs` for exactly where that stops being sound
  and why (no CFG dominance/liveness analysis is built here — that is
  VTIL's real optimizer's job, and future work for this crate).
- **`text.rs`** — a VTIL-style `begin_routine`/`block_0x...`/`end_routine`
  dump, the same reading convention as VTIL-Core's own
  `Sample Routines/*.vtil` files.

## Mixed Boolean-Arithmetic: honest scope

[A²MBA-LLVM](https://github.com/xqzme69/A2MBA-LLVM) is an LLVM pass that
*hardens* expressions against exactly the kind of algebraic simplification
`opt::simplify_algebraic` performs — composing bitwise/arithmetic terms that
are equal by idempotence, the identity element, or a self-inverse law into
something that looks nontrivial. This crate uses that same small identity
set in the *simplifying* direction (deobfuscation, not obfuscation), and
stops there deliberately: recognising the general multi-term MBA identities
A²MBA-LLVM's paper mapping documents, or running the kind of bounded
equality-saturation search its own hybrid mode (and tools like GAMBA/ProMBA)
use, needs an expression-tree/e-graph pass over the block. That is real,
scoped future work, not something this PR claims to solve — see the
`Identity` doc comment in `opt.rs` for the exact line.

## Related tooling this PR does not fold in as code

A few more repositories worth naming, and why they stayed out of the diff:

- [`bl4ckr0ss3/knife`](https://github.com/bl4ckr0ss3/knife) is a complete,
  separate Rust RE toolkit (its own triage/CFG/audit/TUI, its own MCP
  server) — a sibling tool, not a library Recurse depends on. Its
  `analysis/ir.rs` pseudocode lifter is a different, complementary point in
  the design space (decompiler-shaped output) from VTIL's IL (optimizer-
  shaped, physical-register-preserving output); worth a closer look as
  *prior art* for a future decompile-style pass, not something to vendor.
- [`OrbitCurve/firmware-reverse-engineering`](https://github.com/OrbitCurve/firmware-reverse-engineering)
  and [`zhaoxuya520/reverse-skill`](https://github.com/zhaoxuya520/reverse-skill)
  are agent-skill packs (Claude Code / Codex plugin markdown + scripts), not
  Rust crates — nothing in them is a dependency Recurse's workspace can
  build against. They're a documentation/workflow layer that sits *above*
  Recurse (or any RE tool), independent of this crate.

## Trying it

```bash
cargo test -p recurse-vtil
cargo test -p recurse-static lift
```

`crates/recurse-vtil/src/lib.rs` has an end-to-end test
(`lifts_and_folds_an_opaque_predicate_to_one_edge`) that lifts a
`mov ; cmp ; je` opaque-predicate idiom and asserts it folds to a single
unconditional edge — the smallest possible demonstration of the
devirtualization use case above.
