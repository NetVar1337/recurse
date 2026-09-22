# C-like type system (`recurse_static::types`)

`crates/recurse-static/src/types.rs` adds a small C-like type system to the
static-analysis crate: structs, unions, enums, typedefs, pointers, and
arrays, with real layout (member offsets, size, alignment computed under
the C ABI's natural-alignment-plus-padding rule) — plus a from-scratch
parser that imports declarations straight from a `.h` file's text, so a
type library can be built the way an analyst actually works ("paste this
struct from the vendor SDK header") instead of only by hand, field by
field.

```rust
use recurse_static::types::{TypeLibrary, Type};

let mut lib = TypeLibrary::new(64); // pointer width
lib.import_header(r#"
    struct Header { uint32_t magic; uint16_t version; };
    struct Node {
        struct Header header;
        char name[16];
        struct Node *next;
    };
"#)?;

let node = lib.get_struct("Node").unwrap();
for field in &node.fields {
    println!("+0x{:x} {} : {}", field.offset, field.name, field.ty);
}
// +0x0 header : Header
// +0x8 name : int8_t[16]
// +0x18 next : Node*
```

## Scope, honestly

- **No preprocessor.** `#include`/`#define`/`#ifdef`/… lines are dropped,
  not expanded — run `cpp`/`clang -E` first if a header needs macros
  resolved. Comments (`//`, `/* … */`) *are* stripped.
- **No function pointers, no bitfields, no `#pragma pack`.** Every field is
  a scalar, a pointer, an array, or a named struct/union/enum — covers the
  overwhelming majority of real SDK/vendor headers, not the full C grammar.
  A field declared with C's `(*fn)(args)` function-pointer declarator syntax
  will fail to parse; splitting it into a `typedef` first (`typedef void
  (*Callback)(int);` then `Callback cb;`) is not yet supported either — real
  future work, not silently mishandled (the parser errors, it does not
  guess).
- **Declaration order matters.** A struct that embeds another struct *by
  value* must be declared after the type it embeds (the normal C rule); by
  *pointer* there is no such restriction, since a pointer's size never
  depends on what it points to (see
  `struct_containing_a_pointer_to_itself_does_not_need_its_own_size` in the
  module's tests).
- **`long`/`long long` assume LP64** (8 bytes) — the common case for the
  x86-64/AArch64 binaries this workspace otherwise targets; `size_t` takes
  the pointer width passed to `TypeLibrary::new` instead of a fixed guess.

## Not wired into `Engine`/`analyze` yet

This module is a standalone, fully-tested library capability
(`TypeLibrary`/`parse_header`), the same way `crates/recurse-vtil` started
as a library before `Engine::lift` wired it into the `analyze` tool. Adding
an `analyze op:"types"` (import a header, list/query defined types, maybe
annotate a `Mem` operand in `decompile`'s pseudocode with a bound struct's
field name instead of a raw offset) is real, valuable follow-up work with a
much larger blast radius — it touches `Capabilities`, `tool_schema`,
`execute_tool`, and all three `Engine` implementations (`native`, `r2`,
`wasm`) for per-session type-library storage — kept out of this PR to land
the type system itself first, reviewable and tested on its own.

## Trying it

```bash
cargo test -p recurse-static types::
```

11 tests: primitive sizing, struct padding, self-referential-by-pointer
structs, union layout, an unknown-type reference reported as an `Err` (not
a panic), and header parsing (nested struct/pointer/array fields, enums
with explicit and implicit values, typedef of a pointer-to-struct,
preprocessor/comment stripping, multi-declarator member lines, and a
multi-keyword `unsigned long long` combo).
