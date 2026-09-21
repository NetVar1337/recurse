# Lazy analysis

The native engine opens large binaries fast because **discovery builds an
index, not a full program model**. Basic blocks, control-flow graphs, and
switch recovery are decoded *on demand*, the first time a function is actually
looked at — not eagerly for every function when the binary is opened.

Measured on a stripped 8 MB binary (`youki`, x86-64):

| operation | eager (before) | lazy (now) |
| --- | --- | --- |
| open + summary (info, function list, string count) | **~160 s** | **~2.7 s** |
| `functions()` (repeat) | — | ~0.5 ms |
| `function_disasm(one)` | — | ~0.19 ms |
| `function_graph(main)` | — | ~3.4 ms |

The remaining ~2.7 s is the one-time linear sweep: Capstone decoding up to a
million instructions to find function entries in a stripped binary, plus the
string scan. Everything after that is per-function and cached.

## The problem with eager analysis

The first implementation decoded the CFG of every discovered function up front,
so `open` had to finish decoding thousands of functions before the UI could
show anything. Two effects made that cost grow with the product of the function
and block counts (or worse):

- **Tail calls are followed as edges.** A block ending in an unconditional
  `jmp` to another function pulls that function's body into the current decode,
  whose own tail calls pull in more — a single "function" could balloon to the
  block cap.
- **Redundant decoding.** A linear sweep yields many seeds *inside* the same
  real function; decoding each one re-walked the same code.

On `youki`, decoding 4096 functions this way took ~160 s, and almost none of it
was ever displayed.

## How it works now

Analysis is split into two phases.

### Phase 1 — discovery (once, cheap)

`discover()` runs the first time any analysis is requested (`functions`,
`analyze`, `summary`, `xrefs`, …). It builds only the **function index**:

- **Seeds**
  - defined `Text` symbols (the real names),
  - the entry point, plus the `_start`→`main` heuristic (stripped binaries pass
    `main` to libc as a pointer rather than calling it),
  - a bounded **linear sweep** of the executable sections collecting direct
    `call` targets, CET landing pads (`endbr64`/`endbr32`), and classic
    `push rbp; mov rbp, rsp` prologues.
- **Names** — the symbol name, `imp.<name>` when the seed is a forwarding stub
  (one instruction decoded to read its GOT slot), or `fcn_<hex>` otherwise.
- **Sizes** — the next function's address minus this one (last one runs to the
  end of its section).

No basic blocks are decoded, so discovery is proportional to the sweep, not to
`functions × blocks`. The function list is stored in `state.functions` and a
flag (`analyzed`) makes later calls a no-op.

### Phase 2 — block decoding (on demand, cached)

`blocks_for(addr)` decodes a function's CFG the first time that function is
disassembled, graphed, or cross-referenced, and caches it in `state.blocks`.
Repeated views are instant. This is where the expensive work lives:

- a worklist that follows branch and fall-through edges,
- an indexed jump-table resolver, and a switch-idiom matcher (the
  `lea`/`move`/`add`/`jmp reg` pattern),
- a bounded post-pass that searches a 64-instruction lookback window for the
  switch setup.

Because it runs per viewed function, its cost is paid only for functions the
analyst actually opens.

## Bounds

Every phase is bounded so a huge or malformed binary cannot stall a query:

| bound | value | purpose |
| --- | --- | --- |
| `SWEEP_MAX_INSNS` | 1,000,000 | instructions the discovery sweep decodes |
| `MAX_FUNCTIONS` | 4,096 | functions kept (lowest addresses first) |
| `MAX_BLOCKS` | 512 | basic blocks decoded per function |
| `MAX_FUNCTION_INSNS` | 50,000 | instructions decoded per function |
| `MAX_BLOCK_INSNS` | 512 | instructions before a block is treated as data |
| lookback | 64 | instructions the switch matcher scans before a computed jump |

Executable address ranges are computed once per decode and reused, so hot paths
test membership without rescanning every section per instruction.

## What is eager, and why

A few things are still computed up front because they are cheap and needed
immediately:

- **File parse** — `object` reads the headers (milliseconds).
- **Strings** — the string table is scanned once and cached; the UI shows the
  count on open.
- **Function index** — Phase 1 above.
- **Annotation labels** — the name/string index used to comment disassembly is
  built lazily, the first time annotated output is produced, and cached.

## Measuring it

`crates/librecurse/tests/bench_native.rs` is an ignored benchmark that times
each method over the eval corpus and the test executable:

```sh
cargo test -p librecurse --test bench_native -- --ignored --nocapture
```

To reproduce the large-binary numbers, point it at a big stripped binary (or a
one-off probe) and time `open`, `summary`, `functions`, `function_disasm`, and
`function_graph`.
