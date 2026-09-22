# Publishing `recurse-static` and `recurse-vtil` as libraries

`recurse-static` (the `Engine` trait, the native backend, the r2 backend)
and `recurse-vtil` (the VTIL-inspired IL) have no Tauri, UI, or
`recurse-agent` dependency — either already works as a standalone Rust
library. `crates/recurse-mcp` and `crates/recurse-py` are proof: both are
independent consumers of `recurse-static::engine::Engine` with zero access
to anything Tauri-specific.

## What's verified

Both crates' manifests now carry real publish metadata (`repository`,
`keywords`, `categories`) and `recurse-static`'s path dependency on
`recurse-vtil` carries a `version` alongside its `path`, which is what
`cargo publish` needs to resolve it once `recurse-vtil` is actually on
crates.io:

```bash
cargo publish --dry-run -p recurse-vtil --allow-dirty
# Packaging recurse-vtil v0.1.0 ...
# Verifying recurse-vtil v0.1.0 ...
# Compiling recurse-vtil v0.1.0 (.../target/package/recurse-vtil-0.1.0)
#     Finished `dev` profile [unoptimized + debuginfo] target(s)
# warning: aborting upload due to dry run
```

Packages, verifies, and compiles cleanly end to end.

`cargo publish --dry-run -p recurse-static` cannot fully succeed yet —
not because of anything wrong with its manifest, but because dry-run
resolves dependencies against the *real* crates.io index, and
`recurse-vtil` genuinely isn't there yet:

```text
error: failed to prepare local package for uploading
Caused by:
  no matching package named `recurse-vtil` found
```

That is the expected, honest state of a not-yet-published dependency chain,
not a packaging bug — `recurse-vtil` needs to actually publish first, then
`recurse-static`'s dry-run (and real publish) will resolve it normally.

## What's deliberately not done here

Actually running `cargo publish` (for real, against the real registry,
under the `Recurse-Labs` crates.io namespace) is a maintainer decision, not
something a PR should do unilaterally — it is a one-way action (crates.io
has no unpublish) against someone else's package namespace. This PR gets
both manifests to a state where a maintainer with the right crates.io
credentials can run:

```bash
cargo publish -p recurse-vtil
cargo publish -p recurse-static   # after the above lands on crates.io
```

with no further manifest changes needed.
