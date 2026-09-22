# FLIRT-equivalent signature matching (`recurse_static::sig`)

`crates/recurse-static/src/sig.rs` identifies statically-linked library
functions in a stripped binary by their byte pattern — the technique IDA's
FLIRT and Ghidra's FunctionID use. A byte-for-byte comparison does not
work: two binaries that both statically link the exact same library
function are not byte-identical at that function's address, even with the
same compiler and flags, because any `call`/`jmp`/branch inside the
function encodes a relative displacement to whatever else got linked
alongside it — and link layouts differ.

```rust
use recurse_static::sig::{generate_signature, InsnShape, SignatureDatabase};

// From a build of some library, with its own function boundaries known:
let ops = [
    InsnShape { len: 1, has_resolved_target: false }, // push rbp
    InsnShape { len: 3, has_resolved_target: false }, // mov rbp, rsp
    InsnShape { len: 5, has_resolved_target: true },  // call rel32
    InsnShape { len: 1, has_resolved_target: false }, // pop rbp
    InsnShape { len: 1, has_resolved_target: false }, // ret
];
let signature = generate_signature("helper", &function_bytes, &ops);

let mut db = SignatureDatabase::new();
db.add(signature);
std::fs::write("helper.sig", db.to_text())?;

// Later, against a *different* binary that also links `helper`:
let db = SignatureDatabase::from_text(&std::fs::read_to_string("helper.sig")?)?;
if let Some(hit) = db.match_at(&candidate_function_bytes, /* min_concrete_bytes */ 8) {
    println!("{} looks like {}", candidate_addr, hit.name);
}
```

## How wildcarding works

[`generate_signature`] wildcards the trailing bytes of any instruction with
a resolved branch/call target — up to 4 bytes (a `rel32` operand), never
more than `len - 1` (the opcode byte itself always stays concrete). That
covers x86's common `call rel32`/`jmp rel32`/`Jcc rel32` (5–6 byte
instruction, 4-byte trailing operand) and `jmp rel8`/`Jcc rel8` (2-byte
instruction, 1-byte trailing operand) encodings alike.

This reads the *shape* of each instruction (length + "does it have a
resolved target", exactly what `Engine`'s own `Instruction::jump` already
tells you) rather than a relocation table on purpose: by the time you have
a final linked executable, an *intra-module* call has already been resolved
to its link-time-relative encoding — there is no live relocation entry left
to read. Disassembly-shape-based wildcarding is what actually generalizes
across link layouts; a relocation table would miss almost every case that
matters.

## Honest scope

- **No pre-populated signature database ships here.** Building one
  correctly for real libraries (glibc, zlib, OpenSSL, …) needs a curated
  corpus across many compiler/version/flag combinations — a data-curation
  project of its own, not something to fabricate. `to_text`/`from_text`
  give a real database (built by a caller from their own library builds)
  somewhere to live, in a plain, readable text format
  (`name<TAB>XX XX ?? XX …`).
- **No cross-reference disambiguation.** Real FLIRT also uses *other*
  already-recognised functions to disambiguate an identical prologue two
  different functions happen to share (does the ambiguous match's body call
  something shaped like `malloc`?). Not implemented — `Signature::confidence`
  (fraction of the pattern that's concrete) and `SignatureDatabase::match_at`'s
  `min_concrete_bytes` threshold are this module's much simpler substitute
  for rejecting unreliable matches.
- **Not wired into `Engine`/`analyze` yet** — a standalone, fully-tested
  library capability first, the same path `crates/recurse-vtil` and
  `crate::types` both took before landing an `analyze` op.

## Trying it

```bash
cargo test -p recurse-static sig::
```

9 tests, including
`generated_signature_recognises_the_same_function_relinked_elsewhere`: the
same function's bytes, built twice with a different `call` target (a stand-in
for two different binaries linking the same library at different
addresses), are asserted to genuinely differ byte-for-byte — then a
generated signature is shown recognising both, while a literal (non-
generated) signature rejects the second. That's the whole value
proposition, proven, not just asserted.
