# Emulation-based deobfuscation (`recurse_vtil::emu`)

`crates/recurse-vtil/src/emu.rs` concretely executes a code region under
CPU emulation ([unicorn](https://www.unicorn-engine.org/)) and records the
exact instructions actually taken. Behind the `unicorn-engine` cargo
feature (off by default — pulls in `bindgen`/`cmake` to build unicorn from
source, a real native toolchain dependency the rest of this crate
doesn't have).

```rust
use recurse_vtil::emu::trace_x86_64;

let trace = trace_x86_64(&code_bytes, 0x1000, /* entry */ 0, /* until */ code_bytes.len() as u64, 10_000, &[])?;
if trace.reached(0x1000 + suspected_dead_branch_offset) {
    println!("not actually dead");
}
println!("rbx ended up {:#x}", trace.final_registers["rbx"]);
```

Enable with:

```bash
cargo test -p recurse-vtil --features unicorn-engine emu::
```

## Why concrete execution, alongside `opt`'s dataflow and `symex`'s symbolic execution

`crate::opt`'s dataflow and `crate::symex`'s symbolic execution both
reason about *every statically possible* path through a routine — exactly
wrong for the obfuscation techniques this module targets:

- An **opaque predicate** (`cmp eax, eax; je real_branch` — a condition
  that's always true/false for *every* real input, but looks
  data-dependent to static analysis) presents two branches where only one
  is ever real.
- A **VM-style dispatcher loop** (one indirect-jump block executed
  repeatedly, `state = next_state(state)`, with a different real handler
  address each iteration) presents an enormous, mostly-fake static
  control-flow graph — every handler *could* follow every other handler,
  statically.

Actually running the code with concrete inputs collapses that fake graph
down to the one real path/handler sequence that ever executes. This is
the whole premise unicorn-based devirtualization tools operate on:
reason about traces, not the static (and often deliberately misleading)
CFG.

## What `trace_x86_64` does

Maps `code` at a caller-chosen page-aligned `base`, maps a separate stack
region so `push`/`call`/local writes can't collide with the code mapping,
optionally seeds specific GPRs to a concrete value
(`initial_registers`), then emulates from `base + entry_offset` until
either `base + until_offset` is reached or `max_instructions` executes —
whichever first (an obfuscated/adversarial routine is exactly the case
where "run until it naturally stops" isn't safe, so the instruction cap
is mandatory, not optional). An `add_code_hook` records every executed
instruction's address and size, in the order it actually ran (a loop
body executed twice is recorded twice) — `ExecutionTrace::reached(addr)`
answers "did this code actually run", the concrete-execution counterpart
to static reachability.

## Honest scope

- **x86-64 only.** Other architectures unicorn itself supports (ARM,
  AArch64, MIPS, …) are real, scoped follow-up work — the tracing logic
  isn't x86-specific, only `trace_x86_64`'s setup is.
- **No automatic loop/dispatcher unrolling.** A VM dispatcher needs the
  caller to drive multiple `trace_x86_64` calls (one per iteration,
  feeding the recovered handler address back in as the next entry point)
  and stitch the results — this module provides the single-shot trace
  primitive that workflow is built from, not the workflow itself.
- **No memory-region auto-sizing/relocation handling** — the caller picks
  `base`, no attempt to infer a real image's preferred load address or
  fix up absolute references into other sections.
- **Not wired into `Engine`/`analyze` yet** — a standalone, fully-tested
  library capability first, same path this crate's other modules took.

## Trying it

```bash
cargo test -p recurse-vtil --features unicorn-engine emu::
```

5 tests, against real hand-assembled x86-64 machine code (not a mock —
these bytes really execute under unicorn):

- `concrete_execution_resolves_the_opaque_predicate_to_the_real_branch` —
  an always-true `cmp`/`je` opaque predicate; asserts the real branch's
  address was reached, the dead branch's was not, and the final register
  value proves which code path actually ran.
- `initial_register_seeding_changes_which_branch_is_taken` — the same
  shape but data-dependent on a seeded register, run twice with two
  different seed values, proving `initial_registers` genuinely reaches
  the emulated CPU state and changes real execution.
- `instruction_count_limit_stops_execution_early` — the instruction cap
  is honored, not just accepted as a parameter.
- `rejects_a_non_page_aligned_base` / `rejects_a_zero_instruction_limit` —
  input validation.

Building `unicorn-engine-sys` from source needs `cmake` and a C toolchain
with standard headers available (on Windows, an MSVC "Developer" — i.e.
`vcvars64.bat` — environment; this module's own tests were verified
against a real `cargo test` run under that environment in this repo's own
CI-equivalent sandbox).
