# Kernel driver IOCTL + LOLDrivers analysis (`recurse_static::driver`)

`crates/recurse-static/src/driver.rs` recovers the IOCTL codes a Windows
kernel driver's `IRP_MJ_DEVICE_CONTROL` dispatch routine handles — the
first step of any driver vulnerability hunt, since every "arbitrary
read/write via a signed driver" finding starts by knowing which IOCTLs
exist and how they're dispatched — and checks a driver's hash against a
caller-supplied known-driver list in the same shape the
[LOLDrivers](https://www.loldrivers.io/) project publishes.

```rust
use recurse_static::driver::{recover_ioctl_handlers, sha256_hex, check_known_driver, KnownDriver};

let handlers = recover_ioctl_handlers(&dispatch_function_instructions);
for h in &handlers {
    println!("{:#x}: IOCTL {:#x} (method {:?}, access {:?}) -> {:?}",
        h.compare_addr, h.code.raw, h.code.method, h.code.access, h.handler_addr);
}

let hash = sha256_hex(&driver_bytes);
if let Some(known) = check_known_driver(&hash, &loldrivers_list) {
    println!("known driver: {} ({})", known.name, known.category);
}
```

## IOCTL recovery

`recover_ioctl_handlers` scans a function's disassembly (any
`&[recurse_static::engine::Instruction]` — the same shape
`Engine::function_disasm`/`Engine::disassemble` already return) for the
classic dispatch shape: a `cmp <reg-or-mem>, <immediate>` comparing the
IRP's `IoControlCode` field against a candidate IOCTL code, followed
within a small window by a conditional branch to that code's handler.
Real, lightweight *textual* pattern matching over already-disassembled
instructions.

`IoctlCode::decode` breaks a raw 32-bit code down using the real,
documented Windows `CTL_CODE` bitfield layout (`(DeviceType << 16) |
(Access << 14) | (Function << 2) | Method`) — definitional Windows ABI
knowledge, the same honesty class as `crate::capa`'s Win32 API rules:
not an empirical claim needing a curated corpus, a documented fact about
how `CTL_CODE` packs its four fields. `TransferMethod::Neither` is worth
an analyst's attention on sight: it hands the driver raw, unvalidated
user-mode pointers directly — the shape behind most "arbitrary kernel
read/write" driver vulnerabilities.

## LOLDrivers-style known-driver lookup

`check_known_driver` matches a driver's SHA-256 (`sha256_hex`) against a
caller-supplied `KnownDriver` list — the same shape (hash, name,
category/verdict) the community LOLDrivers project publishes for
known-vulnerable and known-malicious signed drivers. **No such list ships
here**: like `crate::sig`'s explicit refusal to ship a fabricated
"real-world" signature database, curating and keeping a hash list like
this current is a data-maintenance project of its own, not something to
hardcode as a handful of entries and call complete. A caller feeds in a
real, currently-maintained list (e.g. LOLDrivers' own published JSON,
converted to `KnownDriver`s) — this module provides the real matching
mechanism, honestly, with nothing behind it invented.

## Honest scope

- **Textual pattern matching, not a dataflow proof.** `recover_ioctl_
  handlers` does not verify the compared register/memory actually holds
  `IoControlCode` — a driver comparing some *other* field for an
  unrelated reason produces a false positive; a jump-table or
  binary-search dispatch (a `switch` compiled as an indexed jump rather
  than a `cmp` chain) produces false negatives. The resulting candidate
  list is exactly that — candidates for an analyst (or a follow-up
  dataflow pass) to confirm.
- **No embedded LOLDrivers data** — see above.
- Not wired into `Engine`/`analyze` yet — a standalone, fully-tested
  library capability first, same path every other module in this series
  took.

## Trying it

```bash
cargo test -p recurse-static driver::
```

9 tests: `CTL_CODE`'s documented bit layout decodes correctly for a real
Windows IOCTL constant (`IOCTL_STORAGE_QUERY_PROPERTY`) and for a
`METHOD_NEITHER` code; a simple `cmp`-then-branch dispatch chain
recovers two real handler entries with correct codes and targets; a
`cmp` between two registers (not an immediate) correctly yields no
candidate; a branch outside the search window still yields a candidate
but with no associated handler address; an unconditional `jmp` correctly
does not count as the dispatch branch; hex/decimal immediate parsing;
and a real SHA-256 test vector (`SHA-256("")`) plus case-insensitive
known-driver matching (and a clean miss for an unknown hash).
