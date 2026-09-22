# C++ vtable/RTTI recovery (`recurse_static::cpp`)

`crates/recurse-static/src/cpp.rs` recovers polymorphic classes from a
binary built with the Itanium C++ ABI (every non-MSVC C++ compiler — GCC,
Clang — on ELF and Mach-O): class names, virtual function tables (with
resolved target addresses and, where available, demangled names), and RTTI
base-class relationships.

```rust
use recurse_static::cpp::recover_classes;

let classes = recover_classes(&binary_bytes)?;
for c in &classes {
    println!("class {} : {:?}", c.name, c.bases);
    for f in &c.virtual_functions {
        println!("  [{}] {:#x} {}", f.slot, f.address, f.name.as_deref().unwrap_or("?"));
    }
}
```

## The relocation problem, and why it's the whole point of this module

A vtable's function-pointer slots hold directly resolved addresses in a
non-PIC linked executable — reading the raw bytes is enough. In a
position-independent shared library or PIE executable (the overwhelmingly
common case for real C++ binaries today), the compiler cannot bake in a
load-address-dependent pointer at compile time: the linker leaves those
slots **zeroed** and emits a dynamic relocation (`R_X86_64_64`/
`R_X86_64_RELATIVE` in `.rela.dyn`) that the runtime loader applies. Read
only the raw file bytes and every vtable in a real-world shared library
comes back all-zero. This module builds an `offset -> resolved address`
map from `Object::dynamic_relocations` up front and prefers it at every
pointer-sized read, falling back to raw bytes when no relocation applies
at that offset (the non-PIC case).

A second, sharper trap inside that: **dynamic relocations' symbol indices
index the dynamic symbol table (`.dynsym`), not the regular/static one**
`Object::symbol_by_index` resolves against. Using the wrong table doesn't
error — it silently hands back some other, unrelated symbol at that index,
producing vtable entries that point at the wrong functions entirely (this
was a real bug caught by this module's own tests: the fixture's Derived
vtable initially came back as `[None, Derived::foo, None, Base::foo,
Base::bar]`, an impossible/scrambled shape, until switching to
`Object::dynamic_symbol_table().symbol_by_index()` fixed it).

## RTTI base-class recovery

A `type_info` object's own first word is a vtable pointer identifying
which of the three `__cxxabiv1` RTTI shapes it is
(`__class_type_info`/no bases, `__si_class_type_info`/single non-virtual
base, `__vmi_class_type_info`/multiple or virtual bases). This module
resolves that identification two ways:

1. If a dynamic relocation applies to that word, read the relocation's
   target **symbol name** directly — this is the primary path and works
   even when the target is an *unresolved external* symbol (e.g.
   `__cxxabiv1::__class_type_info`'s vtable lives in libstdc++, not the
   analyzed module): every unresolved external symbol nominally sits at
   address 0, so an address-based comparison would be ambiguous between
   "no base" and "single base" in exactly that (common, `-nostdlib` or
   statically-import-only) situation.
2. Otherwise, fall back to comparing the resolved address against every
   `_ZTVN...type_infoE` symbol the binary actually defines/resolves, in
   both symbol tables — the non-PIC case.

For `__si_class_type_info`, the base's own `type_info` object address is
read directly and matched against known `_ZTI*` symbols to recover the
base class's demangled name.

## Honest scope

- **Symbol-driven, not blind pattern-scanning.** Vtables are found via
  `_ZTV*`/`_ZTI*` symbol table entries. Real-world C++ shared libraries
  almost always keep these even in an otherwise-stripped release build,
  because cross-DSO `dynamic_cast`/exception matching require external
  visibility — so this covers the common case. A fully stripped static
  executable with no `_ZTV`/`_ZTI` symbols at all needs a heuristic scan
  for pointer-array-shaped data in read-only sections instead; not
  implemented, real follow-up work.
- **`__vmi_class_type_info` (multiple/virtual inheritance)** is parsed
  per the documented Itanium ABI layout (flags + base-class array) but
  has no end-to-end test fixture in this module's own test suite — real,
  scoped follow-up work to build a multi-base-class fixture.
- **MSVC RTTI (`RTTICompleteObjectLocator`/`??_7`) is not implemented** —
  a different ABI entirely (COFF/PE, no `_ZTV`/`_ZTI` naming); real
  separate follow-up work.
- **64-bit little-endian pointers only.**
- **Not wired into `Engine`/`analyze` yet** — a standalone, fully-tested
  library capability first, same path `crate::dwarf`/`crate::sig` took.

## Trying it

```bash
cargo test -p recurse-static cpp::
```

7 tests. Two are clean-error-not-panic tests on garbage/empty input. The
other five run against a **real binary test fixture** —
`crates/recurse-static/tests/fixtures/vtable_single_inheritance.so`, an
actual `clang++`-compiled, `ld.lld`-linked x86_64 ELF shared object built
from:

```cpp
struct Base {
  virtual int foo() { return 1; }
  virtual int bar() { return 2; }
  virtual ~Base() {}
  int x;
};
struct Derived : Base {
  int foo() override { return 3; }
  virtual int baz() { return 4; }
  int y;
};
```

compiled `-fPIC` and linked `-shared`, so its vtable slots are genuinely
`R_X86_64_64`-relocated zero placeholders in the file — proving this
module actually reads and resolves relocations, not just raw bytes:
`recovers_both_classes_with_correct_names`,
`derived_reports_base_as_its_rtti_base_class`,
`base_has_no_rtti_base_class`,
`derived_vtable_overrides_foo_and_adds_baz_while_keeping_bar` (verifies
`Derived::foo` overrides, inherited `Base::bar` is kept, and new
`Derived::baz` is added — real vtable-slot-content assertions, not just
counts), `base_vtable_has_foo_bar_and_two_destructor_slots`.
