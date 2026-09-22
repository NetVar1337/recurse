# Self-verifying agent execution harness (`recurse_agent::verify`)

`crates/recurse-agent/src/verify.rs` re-derives ground truth for every
factual claim an agent makes about a binary from the same `Engine` it
used, independent of whatever the agent said — the automated version of
"never fabricate a finding; verify it for real" applied to the agent's
own output.

```rust
use recurse_agent::verify::{Claim, Harness};

let claims = vec![
    Claim::FunctionAt { addr: 0x1400, name: Some("parse_config".to_string()) },
    Claim::ImportPresent { name: "strcpy".to_string() },
    Claim::CapabilityMatches { rule_name: "read/write files".to_string() },
];

let report = Harness::new().run(engine.as_ref(), &claims);
if !report.all_verified() {
    for f in report.failed() {
        eprintln!("UNVERIFIED: {:?} -- {}", f.claim, f.evidence);
    }
}
```

## Why this matters for an LLM-driven analysis agent specifically

An LLM can state a finding ("function `parse_config` at `0x1400` calls
`strcpy` with unchecked user input") that sounds precise and confident
while being subtly or entirely wrong — a hallucinated address, a
function that doesn't exist, an import that was never actually called.
A report full of such claims is worse than no report: it looks
verified. `Harness::run` re-checks each `Claim` against the real
`Engine` the agent had access to — functions/strings/imports/
disassembly are queried the same way whether the harness or the agent
asks — and reports which claims are actually backed by the binary. A
claim that fails becomes visible as a **failure**, not a silently
accepted line in a report.

## Claim kinds

- `FunctionAt { addr, name }` — re-checked against `Engine::functions()`.
- `StringContains { substring }` — re-checked against `Engine::strings()`.
- `ImportPresent { name }` — re-checked against `Engine::imports()`.
- `MnemonicAt { addr, mnemonic }` — re-checked against
  `Engine::disassemble()`.
- `CapabilityMatches { rule_name }` — composes with `recurse_static::capa`
  from earlier in this series: re-runs the named built-in rule against
  the binary's *real* imports/strings, rather than trusting the agent's
  "I found capability X" statement at face value.

Every `Engine` call failing is itself treated as "not verified" (with
the error as evidence) rather than propagated — a harness must always
finish and report on a whole batch, not abort partway through because
one lookup failed.

## The pass/fail gate

`Report::all_verified()` is `true` only when every claim in the batch
verified **and** the batch was non-empty — an agent that makes zero
verifiable claims does not get to look "clean" by default; an empty
report fails the gate just as loudly as a report with one wrong claim.

## Honest scope

- Five claim kinds, matching the fact shapes this project's own earlier
  modules already produce (functions, strings, imports, disassembly,
  capa rules). Claims about `crate::diff`/`crate::taint`/
  `crate::decompose` findings, or multi-step claims ("A calls B calls
  C"), are real, scoped follow-up work — the same composition pattern
  (`CapabilityMatches` re-running a real `capa` rule) extends
  straightforwardly to them.
- Not wired into the actual agent run loop's report-generation path yet
  — a standalone, fully-tested verification primitive first, ready for a
  host to call after collecting an agent's claims and before presenting
  them as a finished report.

## Trying it

```bash
cargo test -p recurse-agent verify::
```

10 tests, against a fully in-memory stub `Engine` (a small, fixed
functions/strings/imports/instructions set — this module's own logic is
what's under test, not binary parsing, which is already tested with real
fixtures elsewhere in this series): a true function claim verifies; a
hallucinated address fails; a right-address-wrong-name claim fails; true/
false string, import, and mnemonic claims each verify/fail correctly; a
capability claim genuinely re-evaluates the real rule (not just checking
the name exists); `Harness::run` produces an accurate pass/fail gate over
a mixed batch; an all-true batch reports fully verified; and an empty
claim batch is explicitly rejected rather than trivially "passing".
