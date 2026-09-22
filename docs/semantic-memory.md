# Cross-binary semantic memory (`recurse_static::semantic_memory`)

`crates/recurse-static/src/semantic_memory.rs` is a persistent store of
function fingerprints, searchable by structural similarity — "find every
function across every binary I've ever analyzed that looks like this
one".

```rust
use recurse_static::semantic_memory::{FunctionRecord, Memory};
use recurse_static::diff::normalize_mnemonics;

let mut memory = Memory::new();
memory.add(FunctionRecord::new(
    "libfoo-1.0.so",
    "parse_header",
    0x1000,
    normalize_mnemonics(&disasm_lines_from_binary_a),
));
memory.add(FunctionRecord::new("libfoo-2.0.so", "parse_header", 0x1400, normalize_mnemonics(&disasm_lines_from_binary_b)));

// Persist across sessions:
std::fs::write("corpus.json", memory.to_json()?)?;
let memory = Memory::from_json(&std::fs::read_to_string("corpus.json")?)?;

// Search a whole corpus for whatever looks like `query_instructions`:
for m in memory.find_similar(&query_instructions, 5, 50) {
    println!("{:.2} {} @ {:#x} in {}", m.similarity, m.record.name, m.record.address, m.record.binary);
}
```

## Honest framing: this is not a neural embedding

"Embeddings similarity" usually means a learned vector representation
from a neural model (code2vec-, CodeBERT-, or LLM-embedding-style). This
module does not ship one — there is no offline model available to run in
this environment, and faking inference (returning plausible-looking
vectors from nowhere) would be exactly the kind of fabricated,
unverifiable behavior this project refuses to ship.

Instead, `simhash` is a real, deterministic, classical locality-sensitive
hash ([SimHash](https://en.wikipedia.org/wiki/SimHash) — the technique
search engines have used for near-duplicate detection for two decades)
over a function's normalized-instruction-sequence bigrams. Two
structurally similar functions get fingerprints with a small Hamming
distance, without needing a trained model, GPU, or network call. It
serves the same "fast approximate similarity across a large corpus" role
a learned embedding would; it is not one, and this module never claims
otherwise.

## Two-stage search

`Memory::find_similar` first ranks the whole corpus by SimHash Hamming
distance (cheap: one `u64::count_ones` per candidate, no per-candidate
instruction-sequence comparison), then re-scores only the closest
`candidate_pool` of those with `crate::diff`'s real longest-common-
subsequence ratio for the final, precise similarity score — a
coarse-then-precise pipeline, not a single cheap hash treated as if it
were exact. This is the standard shape a production similarity index
uses (cheap filter, precise re-rank), just without the network/GPU/index
infrastructure a huge corpus would eventually need.

## Persistence

`Memory::to_json`/`Memory::from_json` round-trip a corpus to plain JSON,
so "semantic memory" genuinely persists across analysis sessions rather
than only living for one process's lifetime.

## Honest scope

- Bigram SimHash over *mnemonic shape* only (the same normalization
  `crate::diff` uses) — no operand-value, control-flow-graph-shape, or
  cross-function (caller/callee) context folded into the fingerprint.
  Real, scoped follow-up work.
- No incremental/indexed nearest-neighbor structure (LSH bucketing, an
  actual k-d/ball tree) — `find_similar`'s coarse stage is still a full
  linear scan of the corpus's fingerprints, just a cheap one. Fine for a
  corpus of thousands of functions; a genuinely huge corpus would want a
  real ANN index on top of the same fingerprints.
- Not wired into `Engine`/`analyze` yet — a standalone, fully-tested
  library capability first, same path every other module in this series
  took.

## Trying it

```bash
cargo test -p recurse-static semantic_memory::
```

7 tests: identical sequences hash identically; a near-duplicate (one
instruction inserted, the same fixture shape `crate::diff`'s own tests
use) has a below-random-chance Hamming distance; an unrelated sequence
has a measurably larger distance than the near-duplicate (the real,
relative proof of SimHash's usefulness here, since raw distance
thresholds on short sequences are inherently noisy — documented in the
test itself); `find_similar` ranks an exact self-match first and a
near-duplicate second across a corpus spanning three different binaries;
a JSON round-trip preserves every record; garbage JSON is a clean error;
and an empty query against an empty (or single-empty-record) memory
doesn't panic.
