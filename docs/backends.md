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
  stored config. The default is `native` (the in-process, permissive,
  multi-architecture backend); `r2` is opt-in.
- The backend-neutral agent tool (`analyze`) and its dispatcher,
  `execute_tool(&dyn Engine, args)`. Its `op` vocabulary is
  `analyze | functions | disasm | graph | decompile | xrefs | strings | imports
  | info | raw`. The vocabulary is filtered by `Engine::capabilities()`: a
  backend with no decompiler or console (native) never advertises those ops in
  the schema or the system prompt, and `execute_tool` rejects them up front.
  `raw` is the documented escape hatch for backend consoles (radare2 syntax
  when the r2 backend is active).

Hosts own the concrete engine (it needs a target path, and r2 needs a child
process) and box it as `Box<dyn Engine>` (see `tauri/src-tauri/src/engine.rs`).

## Backends

### `r2` — radare2 (opt-in, full features)

`librecurse::r2_backend::R2Engine` drives the `r2` executable over its `-q0`
NUL-framed pipe, one long-lived session per target. Full feature set including
`r2ghidra` decompilation. radare2 is a separate program invoked at runtime and
is **not** linked or bundled, so it stays under its own LGPL-3.0 terms.

### `native` — pure Rust (default, no copyleft)

`librecurse::native::NativeEngine` parses and disassembles in-process. No child
process, no external tool, and no copyleft dependency anywhere in the chain.
Honest scope:

- ELF / PE / Mach-O parsing, symbols, imports, strings.
- Multi-architecture disassembly and control-flow recovery (Capstone):
  x86/x86-64, ARM, AArch64, MIPS, PowerPC, RISC-V, SPARC, SystemZ, M68K, BPF.
- Functions are discovered from symbols, the entry point, and direct call
  targets.
- No decompiler (`capabilities().decompile == false`) and no raw console. The
  agent tool answers `op:"decompile"` with a precise "install r2 + r2ghidra and
  set `RECURSE_BACKEND=r2`" message rather than a generic failure.
- Architectures Capstone does not cover (AVR, CSky, LoongArch, Xtensa, …) are
  detected and reported, not disassembled.

## Crates and why

| Crate | License | Used for |
| --- | --- | --- |
| `object` | Apache-2.0 / MIT | ELF/PE/Mach-O/COFF parsing: architecture, bits, endianness, entry point, sections, symbols, imports, exports. |
| `capstone` | BSD-3-Clause | Multi-architecture disassembly + instruction groups (jump/call/ret) for CFG and xref recovery: x86, x86-64, ARM, AArch64, MIPS, PowerPC, RISC-V, SPARC, SystemZ, M68K, BPF, and more. Vendors the Capstone C library (permissive), used behind a safe API. |
| `rustc-demangle` | Apache-2.0 / MIT | Rust v0/legacy symbol demangling. |
| `cpp_demangle` | Apache-2.0 / MIT | Itanium C++ symbol demangling. |
| `nix` | MIT | Safe wrappers (`killpg`/`kill`) for `Engine::interrupt` / `force_kill` (r2 backend only). Replaces any raw `libc` FFI. |

Already-present crates that also serve analysis: `serde`/`serde_json` (canonical
envelopes), `regex` (host-side scans).

### Crates considered and rejected

| Candidate | Why not (for the native backend) |
| --- | --- |
| `iced-x86` | MIT and excellent, but x86-only. Capstone supersedes it for a multi-arch backend behind one API; keeps a single decode path. |
| `yaxpeax-*` | 0BSD/MIT pure-Rust multi-arch decoders. Kept as the fallback if linking the Capstone C library (via `cc`) is ever undesirable; coverage is currently narrower. |
| `goblin` | MIT, but `object` is the ecosystem standard and what `gimli`/`addr2line` use. |
| `zydis` | MIT but x86-only and bindgen over C++. No advantage over Capstone. |
| `petgraph` | MIT/Apache, but the CFG is a small `Vec<BasicBlock>` and needs no graph library. |
| RetDec / Ghidra / snowman | Decompilers. RetDec is MIT but a large C++ sidecar; Ghidra is Apache but a JVM; snowman is GPL. Decompilation stays with r2ghidra, behind the capability flag. |

If linking a C library at all is unacceptable, swap `capstone` for the
`yaxpeax-*` decoders behind the same `Engine` methods; nothing above the trait
changes.

## Licensing posture

Because the engine is a trait:

- The repository can ship the native backend and build/run with **no LGPL
  component present**. radare2 is an optional runtime dependency of one
  implementation, invoked as a separate program (mere aggregation), never
  linked.
- The r2-specific code is isolated in one module (`r2.rs` command layer and
  `r2_backend.rs` adapter), never links radare2, and only runs when the r2
  backend is selected — so a distribution can omit r2 without touching the
  rest of the tree.
