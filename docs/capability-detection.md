# Capability detection (`recurse_static::capa`)

`crates/recurse-static/src/capa.rs` is a small
[capa](https://github.com/mandiant/capa)-class rules engine: it turns
"this function imports `RegSetValueExA` and the string
`\Software\...\Run`" into "this function establishes persistence" —
human-readable capability labels instead of a raw import/string list an
analyst has to interpret themselves.

```rust
use recurse_static::capa::{built_in_rules, Evidence};

let evidence = Evidence::new()
    .with_imports(["RegSetValueExA"])
    .with_strings([r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]);

for rule in built_in_rules().evaluate(&evidence) {
    println!("{} [{}]: {}", rule.name, rule.namespace, rule.description);
}
// -> "persist via the Run key [persistence/registry-run-key]: ..."
```

## Model

A `Rule` is a name/namespace/description plus a `Predicate` tree over
`Feature`s (import name, string substring, numeric constant, instruction
mnemonic, mnemonic-occurs-at-least-N-times). `Predicate` supports the
boolean combinators capa rules use: `and`/`or`/`not`/`at_least` ("N of
these M sub-predicates are true"). `RuleSet::evaluate` checks every rule
against a caller-built `Evidence` snapshot and returns every rule that
matched, in declaration order.

A real bug this module's own tests caught while writing it:
`Predicate::AtLeast(2, vec![mnemonic("xor"); 3])` does **not** mean
"xor occurs at least twice" — `AtLeast` counts true *sub-predicates*, and
all three copies evaluate the same underlying fact, so a single `xor`
anywhere satisfies all three at once. Genuine repetition counting needed
a real `Feature::MnemonicCount(name, n)` backed by an actual occurrence
count in `Evidence` (a multiset, not a `BTreeSet`) — `AtLeast` and
"occurs N times" are different questions, and conflating them silently
produces an always-satisfied rule. `Predicate::mnemonic_count_at_least`
is the correct primitive for the latter.

## Decoupled from any particular disassembler

Like `crate::diff` and `crate::sig`, this module takes a plain `Evidence`
value rather than an `Engine` or raw bytes — the caller extracts
imports/strings/numbers/mnemonics from whichever backend they're already
using.

## The built-in rule pack: real API names, not a curated corpus

`built_in_rules()` ships ~13 rules, each naming real, documented Win32
API functions (`CreateProcessA`, `RegSetValueExA`, `VirtualAllocEx`,
`WSAStartup`, `CryptEncrypt`, `IsDebuggerPresent`, …), covering process
creation/injection, registry access, persistence, file I/O, HTTP/socket
communication, encryption, anti-debugging, executable-memory allocation,
dynamic API resolution, and XOR-based obfuscation.

This is categorically different from `crate::sig`'s or
`crate::winpdb`'s explicit refusal to ship a fabricated "real-world"
signature/symbol database: "calling `CreateProcessA` is process-creation
capability" is a documented fact about the Win32 API, not an empirical
claim about some malware corpus that would need curation to back up.
What these rules do **not** claim: that matching one means the binary is
malicious, or that this is a complete list of every way to exhibit a
capability — both real, stated limits (see each rule's `description`).

## Honest scope

- No feature kinds beyond import/string/number/mnemonic(-count) — real
  capa also matches basic-block/function characteristics (e.g. "loop"),
  offset-of-a-field-in-a-struct features, and OS/architecture
  qualifiers. Not implemented; real follow-up work.
- No rule-text (YAML) parser/serializer — rules are constructed through
  the Rust API only. `crate::sig`'s `to_text`/`from_text` pattern would
  be the natural next step; not implemented here.
- Not wired into `Engine`/`analyze` yet — a standalone, fully-tested
  library capability first, same path every other Tier-2 module here
  took.

## Trying it

```bash
cargo test -p recurse-static capa::
```

11 tests: each `Feature` kind in isolation, all four combinators
(`and`/`or`/`not`/`at_least`), `RuleSet::evaluate` ordering, an empty
ruleset, and — importantly — three tests against the real built-in rule
pack itself proving it isn't just decorative: the process-injection rule
genuinely needs all three APIs (not any one alone), the persistence rule
genuinely needs both the API and the registry-path string, and the XOR
rule genuinely needs two real occurrences (catching the `AtLeast`-vs-count
bug described above).
