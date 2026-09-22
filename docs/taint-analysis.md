# Vulnerability sink / taint analysis (`recurse_vtil::taint`)

`crates/recurse-vtil/src/taint.rs` tracks data flowing from an untrusted
source call (`recv`, `getenv`, `argv`, …) through a routine's lifted IL,
and flags a sink call (`strcpy`, `system`, `memcpy`, …) reached with a
tainted argument and no sanitizer in between — the same class of static
audit a `knife`-style vulnerability scanner runs.

```rust
use recurse_vtil::taint::{analyze, TaintSpec};
use std::collections::HashMap;

let spec = TaintSpec::win64(
    vec!["recv".to_string()],
    vec!["strcpy".to_string()],
    vec!["validate_input".to_string()],
);
let resolve_call: HashMap<u64, String> = /* from Engine::imports(), keyed by call target address */ HashMap::new();

for finding in analyze(&routine, &resolve_call, &spec) {
    println!("{:#x}: tainted data reaches {} via {:?}", finding.sink_addr, finding.sink_name, finding.tainted_arguments);
}
```

## Design

A whole-CFG, flow-sensitive, forward register-taint dataflow, built on
the same `crate::cfg::Cfg` worklist shape `crate::opt`/`crate::liveness`
already use — including the same non-destructive-analysis-then-final-
report split those modules settled on after `crate::opt`'s own back-edge
soundness fix earlier in this series: taint sets are only ever unioned
(monotone) during the fixpoint, and `Finding`s are collected in one
final pass from the converged per-block entry state, so a loop body is
never analyzed against a premature, not-yet-widened taint set.

## Call semantics are the caller's to provide

`Op::Vxcall`'s only operand is the call target itself — VTIL deliberately
does not model calling-convention argument registers as instruction
operands, since those live in the ABI, not the `call` instruction. So
this module needs, and `TaintSpec` carries, the calling convention
explicitly: `return_register` (which register a call leaves its result
in) and `argument_registers` (which registers hold arguments at a call
site). `TaintSpec::win64`/`TaintSpec::sysv64` are the two common x86-64
conventions, ready to use; anything else is a plain struct literal away.

A sink `Finding` fires when *any* argument register is tainted at that
call — an over-approximation of "the tainted value is the specific
argument that matters", the same one every practical static taint tool
makes without full symbolic argument-binding.

Call targets are resolved to names via a caller-supplied
`resolve_call: &HashMap<u64, String>` (a call instruction's target
address to an import/symbol name) — the same "caller wires in their own
already-resolved data" shape `crate::diff`/`crate::capa` use. An
unresolved target passes taint through unchanged (neither taints nor
sanitizes) — conservative, since this analysis has no basis to assume
either about code it can't identify.

## Honest scope

- **Register-level taint only, no memory-taint model.** A `str` (memory
  store) does not propagate taint into the stored-to memory; a `ldd`
  (memory load) uses a real but textual heuristic — its destination
  register is tainted only when the load's own (unparsed,
  `Operand::Mem(String)`-shaped) address expression textually mentions an
  already-tainted register's name. Structured pointer-expression modeling
  (base/index/scale, so a load could be checked against the *value*
  written there rather than a text match on the address expression) is
  real, scoped follow-up work — the same status `crate::il::Operand::Mem`
  itself already documents.
- **Argument-register-at-call-site, not per-argument-slot precision.**
  See "call semantics" above.
- **No interprocedural analysis** — one routine's CFG at a time; taint
  does not follow a call into a callee's own body and back out through
  its actual return-value computation (a source/sink/sanitizer name list
  models exactly that boundary instead, for the specific calls the list
  names).
- **Not wired into `Engine`/`analyze` yet** — a standalone, fully-tested
  library capability first, same path every other module in this series
  took.

## Trying it

```bash
cargo test -p recurse-vtil taint::
```

6 tests: straight-line source-to-sink taint is flagged; an untainted
call to the same sink is not; a sanitizer call genuinely clears taint
before the sink (not just "the rule exists"); taint survives a loop
back-edge (the actual soundness property this module's fixpoint design
exists to guarantee — a destructive single-pass analysis would lose it);
an unresolved call target neither taints nor sanitizes; and an empty
routine yields no findings without panicking.
