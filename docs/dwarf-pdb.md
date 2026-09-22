# Debug info ingestion: DWARF (`recurse_static::dwarf`) and PDB (`recurse_static::winpdb`)

Two independent modules that pull real names — function names, parameter
names, types — out of a binary's own debug info when it has some, rather
than relying purely on static analysis. ELF/Mach-O binaries carry DWARF in
`.debug_info`/`.debug_abbrev`/`.debug_str` sections; PE binaries built with
MSVC instead point at a separate `.pdb` file. Different formats, different
crates (`gimli` vs `pdb`), so two modules, not one.

## DWARF (`crates/recurse-static/src/dwarf.rs`)

```rust
use recurse_static::dwarf::load_functions;

let functions = load_functions(&object_file_bytes)?;
for f in &functions {
    println!("{} @ {:#x}..{:#x} -> {}", f.name, f.low_pc, f.high_pc, f.return_type);
    for p in &f.parameters {
        println!("  {}: {}", p.name, p.ty);
    }
}
```

Walks each compile unit's DIE tree (via `gimli`) looking for
`DW_TAG_subprogram` entries, reading name, `DW_AT_low_pc`/`DW_AT_high_pc`,
return type, and `DW_TAG_formal_parameter` children. A type-name renderer
resolves the `DW_AT_type` reference chain through pointer/const/struct/
union/enum/array/typedef DIEs into a C-like string (`"int *"`,
`"const Foo &"`-shaped output, minus references since DWARF C support
doesn't need them).

A binary with no debug info at all yields `Ok(vec![])`, not an error —
"no DWARF" is an expected, common case (stripped or release binaries),
not a failure.

### Honest scope

- `DW_AT_decl_file` is read but left as a raw file-table index
  (`decl_file_index: Option<u64>`); resolving it to an actual source path
  needs the line-number program's file table, not implemented yet.
- No local-variable or inlined-call recovery — parameters and the function
  envelope only.

### Trying it

```bash
cargo test -p recurse-static dwarf::
```

3 tests, against a **hand-built real DWARF v4 byte fixture** — encoded
directly with `gimli`'s own exported tag/attr/form constants (not
memorized hex), not `gimli::write` (a much larger API this module doesn't
otherwise need) and not a fabricated/mocked reader:
`recovers_function_name_address_range_and_return_type`,
`recovers_parameter_names_and_types_including_a_pointer`,
`binary_with_no_debug_info_yields_an_empty_ok_not_an_error`.

## PDB (`crates/recurse-static/src/winpdb.rs`)

```rust
use recurse_static::winpdb::load_public_symbols;

let symbols = load_public_symbols(std::path::Path::new("app.pdb"))?;
for s in &symbols {
    println!("{:#x} {}", s.rva, s.name); // rva is relative to the module's own base
}
```

Opens the PDB's MSF container (via the `pdb` crate), reads the global
symbol stream, and keeps every `SymbolData::Public` entry — name plus RVA
(resolved through the PDB's own address map, so it's already a flat
module-relative offset, not a segment:offset pair). This is the module
named `winpdb`, not `pdb`, specifically so it never shadows the crate it
wraps.

### Honest scope

Public symbols only. A PDB's actual *type* information (function
signatures, local variables — the PDB-side equivalent of what
`dwarf.rs` recovers for ELF/Mach-O) lives in the TPI/IPI type-information
streams, a much more involved part of the format this module does not
parse. Public-symbol-to-name recovery (turning `sub_140001000` into its
real name) is nonetheless the single highest-value PDB use case for RE,
and the one this module delivers.

### Trying it

```bash
cargo test -p recurse-static winpdb::
```

3 tests:

- `garbage_input_is_a_clean_error_not_a_panic` / `empty_input_is_a_clean_error_not_a_panic`
  — malformed input is a clean `Err`, never a panic.
- `real_pdb_alongside_the_test_binary_when_present` — a genuine
  end-to-end test against a **real PDB**, not a mock: an MSVC debug build
  (the default on this target) always writes the test binary's own
  `.pdb` right next to it, so the test locates it via
  `std::env::current_exe().with_extension("pdb")` and asserts real
  symbols come back (thousands, in practice — this crate's own Rust
  v0-mangled function names). Skips (does not fail) when no sibling
  `.pdb` exists — a release build, or a non-Windows/non-MSVC target,
  legitimately has none; there is nothing to prove there and nothing
  wrong either.

## Neither is wired into `Engine`/`analyze` yet

Both stay standalone, fully-tested library modules for now — the same
path `crates/recurse-vtil`, `crate::types`, and `crate::sig` all took
before landing an `analyze` op. Wiring either in (feeding recovered names
through `Engine::set_renames`, exposing `dwarf`/`pdb` as `analyze` ops in
`Capabilities`/`tool_schema`/`execute_tool` across all three `Engine`
impls) is real, separate follow-up work.
