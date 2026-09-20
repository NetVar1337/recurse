# Analysis backends

Recurse does not depend on any single reverse-engineering engine. The binary
world-model (functions, disassembly, xrefs, strings, imports, CFG) is defined
once in `librecurse::engine`, and each backend is an implementation of that
trait. The agent tool and every UI command go through the seam, so swapping the
engine never touches the agent loop, the storefront, or the eval harness.

## The seam

`crates/librecurse/src/engine.rs` defines:

- `trait Engine` — one method per operation: `analyze`, `summary`, `info`,
  `functions`, `function_at`, `disassemble`, `function_disasm`,
  `function_graph`, `strings`, `imports`, `xrefs`, `decompile`, `raw`,
  `resolve`, plus `pid`/`interrupt`/`force_kill` for out-of-process engines.
- Canonical result types (`FunctionInfo`, `Instruction`, `Disassembly`,
  `FunctionGraph`, `StringRef`, `Import`, `Xref`, `Decompilation`). Their JSON
  field names match what the UI already rendered from radare2, so the frontend
  is backend-agnostic too.
- `BackendKind` (`r2` | `native`), selected from `RECURSE_BACKEND` or the
  stored config, with `r2` as the default for compatibility.
- The backend-neutral agent tool (`analyze`) and its dispatcher,
  `execute_tool(&dyn Engine, args)`. Its `op` vocabulary is
  `analyze | functions | disasm | graph | decompile | xrefs | strings | imports
  | info | raw`. `raw` is the documented escape hatch for backend consoles
  (radare2 syntax when the r2 backend is active).

Hosts own the concrete engine (it needs a target path, and r2 needs a child
process) and box it as `Box<dyn Engine>` (see `tauri/src-tauri/src/engine.rs`).

## Backends

### `r2` — radare2 (default)

`librecurse::r2_backend::R2Engine` drives the `r2` executable over its `-q0`
NUL-framed pipe, one long-lived session per target. Full feature set including
`r2ghidra` decompilation. radare2 is a separate program invoked at runtime and
is **not** linked or bundled, so it stays under its own LGPL-3.0 terms.

### `native` — pure Rust (no copyleft)

`librecurse::native::NativeEngine` parses and disassembles in-process. No child
process, no external tool, and no copyleft dependency anywhere in the chain.
Honest scope:

- ELF / PE / Mach-O parsing, symbols, imports, strings.
- x86 / x86-64 disassembly and control-flow recovery (recursive descent from
  symbols + entry over direct call targets).
- No decompiler (`capabilities().decompile == false`) and no raw console. The
  agent tool answers `op:"decompile"` with a precise "install r2 + r2ghidra and
  set `RECURSE_BACKEND=r2`" message rather than a generic failure.
- Non-x86 code is detected and reported, not disassembled.

## Crates and why

| Crate | License | Used for |
| --- | --- | --- |
| `object` | Apache-2.0 / MIT | ELF/PE/Mach-O/COFF parsing: architecture, bits, endianness, entry point, sections, symbols, imports, exports. |
| `iced-x86` | MIT | x86/x64 instruction decoding + formatting, and flow-control edges (jump/fail/call/ret) for CFG and xref recovery. Pure Rust, no C. |
| `rustc-demangle` | Apache-2.0 / MIT | Rust v0/legacy symbol demangling. |
| `cpp_demangle` | Apache-2.0 / MIT | Itanium C++ symbol demangling. |
| `libc` | MIT / Apache-2.0 | Unix `kill` for `Engine::interrupt` / `force_kill` (r2 backend only). |

Already-present crates that also serve analysis: `serde`/`serde_json` (canonical
envelopes), `regex` (host-side scans).

### Crates considered and rejected

| Candidate | Why not (for the native backend) |
| --- | --- |
| `capstone` | BSD-3 and multi-arch, but links C. Kept out to keep the native backend dependency-light; can be an optional third backend later. |
| `yaxpeax-*` | 0BSD/MIT pure-Rust multi-arch decoders. Viable for ARM/MIPS/RISC-V; deferred until a non-x86 target needs it. |
| `goblin` | MIT, but `object` is the ecosystem standard and what `gimli`/`addr2line` use. |
| `zydis` | MIT but x86-only and bindgen over C++. No advantage over `iced-x86`. |
| `petgraph` | MIT/Apache, but the CFG is a small `Vec<BasicBlock>` and needs no graph library. |
| RetDec / Ghidra / snowman | Decompilers. RetDec is MIT but a large C++ sidecar; Ghidra is Apache but a JVM; snowman is GPL. Decompilation stays with r2ghidra, behind the capability flag. |

If multi-architecture native disassembly becomes a requirement, add
`yaxpeax-arm` / `yaxpeax-mips` / `yaxpeax-riscv` behind the same `Engine`
methods; nothing above the trait changes.

## Licensing posture

Because the engine is a trait:

- The repository can ship the native backend and build/run with **no LGPL
  component present**. radare2 is an optional runtime dependency of one
  implementation, invoked as a separate program (mere aggregation), never
  linked.
- The r2-specific code lives in one module (`r2.rs` command layer and
  `r2_backend.rs` adapter) and can be compiled out or omitted from a
  distribution without touching the rest of the tree.
