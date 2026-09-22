# Automatic finding/report generation (`recurse_agent::report`)

`crates/recurse-agent/src/report.rs` turns structured analysis output
(capability matches, verified claims, or any other caller-built
`Finding`) into one coherent Markdown report — deterministic, algorithmic
document assembly, not LLM-generated narrative text.

```rust
use recurse_agent::report::ReportDoc;
use recurse_agent::verify::{Claim, Harness};

let claims = vec![Claim::ImportPresent { name: "RegSetValueExA".to_string() }];
let verification = Harness::new().run(engine.as_ref(), &claims);
let report = ReportDoc::from_verification("sample.exe", &verification);
println!("{}", report.to_markdown());
```

## Why algorithmic, not LLM-generated

An LLM call to "write up these findings nicely" is unverifiable and
non-deterministic — this project's own standard (real, tested,
reproducible output) rules it out as the mechanism here. `ReportDoc`
instead assembles a plain, structured document from data every field of
which traces back to something a caller already computed and can point
to: `recurse_agent::verify`'s pass/fail claims, `recurse_static::capa`'s
rule matches, or any other analysis this project's earlier modules
produce. "Automatic" means "no human hand-assembling Markdown sections",
not "written by a model with no ground truth behind it".

## Composes with `verify` and `capa`

`ReportDoc::from_verification` builds a report directly from a
`recurse_agent::verify::Report`: every *verified* claim becomes a
confirmed `Finding`; every failed claim is kept, visibly, in
`ReportDoc::unconfirmed` instead of being silently dropped — a report
that hides what it couldn't confirm is exactly the kind of overclaiming
this whole series has refused to ship.

`capability_findings` turns `recurse_static::capa::Rule` matches into
`Finding`s with a namespace-derived `Severity` (`severity_for_capa_
namespace` — a real, simple, explicitly-documented-as-simple heuristic:
`process/inject*`, `anti-analysis*`, and `persistence*` namespaces are
Medium; other `process/*` and dynamic-resolution rules are Low;
everything else is Info).

## Rendering

`ReportDoc::to_markdown()` renders an H1 title, findings grouped by
descending severity (each with its evidence as a bullet list and, when
set, its address), and — only when non-empty — an "Unconfirmed" section
at the end. Deterministic: the same `ReportDoc` always renders to the
same text.

## Honest scope

- `Severity` is a rough, deterministic band from *where a finding came
  from* (a capa rule's namespace, or "verified: true"), not a real
  risk/exploitability score — documented explicitly rather than
  presented as one.
- No taint-analysis (`recurse_vtil::taint`) or binary-diff
  (`recurse_static::diff`) convenience constructor yet, unlike
  `capability_findings` for `capa` — `recurse-agent` does not currently
  depend on `recurse-vtil`; a caller builds `Finding`s from those
  modules' output directly today (the same decoupled shape
  `capability_findings` itself uses, just without a dedicated
  convenience wrapper). Real, scoped follow-up work.
- Markdown only — no HTML/PDF rendering.
- Not wired into the agent run loop's actual output path yet — a
  standalone, fully-tested report-assembly primitive first.

## Trying it

```bash
cargo test -p recurse-agent report::
```

8 tests: an empty report renders a clean "no findings" message; findings
render grouped by descending severity in the right order; evidence and
address both appear in the rendered text; unconfirmed claims stay
visible rather than being dropped; a report with no unconfirmed claims
omits that section entirely (not an empty header); `from_verification`
correctly splits a mixed verified/failed batch; `capability_findings`
assigns the documented namespace-based severities; and rendering is
deterministic across repeated calls on the same `ReportDoc`.
