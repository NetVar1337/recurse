//! C++ vtable/RTTI recovery for the Itanium C++ ABI (the ABI every
//! non-MSVC C++ compiler — GCC, Clang, on ELF and Mach-O — uses).
//!
//! Turns `_ZTV7Derived` + a pile of anonymous function addresses into
//! `class Derived : Base { foo() -> 0x1050, baz() -> 0x1090, ... }`: the
//! same "identify polymorphic classes and their virtual dispatch tables"
//! job as IDA's/Ghidra's C++ vtable analyzers.
//!
//! # How this works, and why it needs both raw bytes and relocations
//!
//! A vtable's function-pointer slots hold *resolved addresses* in a
//! non-PIC linked executable — reading the raw bytes is enough. In a
//! position-independent shared library / PIE executable, though, the
//! compiler cannot bake in a load-address-dependent pointer at compile
//! time: the linker instead leaves those slots **zeroed** and emits a
//! `R_*_RELATIVE`/`R_*_64` dynamic relocation (in `.rela.dyn`) that the
//! *runtime* loader applies. The file's raw bytes at that slot are 0; the
//! real value only exists in the relocation table's addend. This module
//! builds an `offset -> resolved address` map from
//! [`object::Object::dynamic_relocations`] up front and prefers it over
//! raw bytes at every pointer-sized read, falling back to the raw bytes
//! when there is no relocation at that offset (the non-PIC case). Getting
//! this wrong — reading only raw bytes — would silently return all-zero
//! vtables for the overwhelmingly common case of a real shared library.
//!
//! # Honest scope
//!
//! - **Symbol-driven, not blind pattern-scanning.** This module finds
//!   vtables via `_ZTV*`/`_ZTI*` **symbol table** entries. Real-world C++
//!   shared libraries almost always keep these in `.dynsym` even in an
//!   otherwise-stripped release build, because cross-DSO `dynamic_cast`
//!   and exception matching require external visibility of RTTI — so this
//!   covers the common case. A fully stripped static executable with no
//!   `_ZTV`/`_ZTI` symbols at all needs a heuristic scan for
//!   pointer-array-shaped data in read-only sections instead; not
//!   implemented here, real follow-up work.
//! - **RTTI base-class recovery** handles the two common shapes:
//!   no inheritance (`__class_type_info`) and single non-virtual
//!   inheritance (`__si_class_type_info`). Multiple/virtual inheritance
//!   (`__vmi_class_type_info`) is parsed per the documented Itanium ABI
//!   layout (flags + base-class array) but has no end-to-end test fixture
//!   in this module's test suite — a real multi-base-class binary to test
//!   it against is real, scoped follow-up work.
//! - **MSVC RTTI (`RTTICompleteObjectLocator`/`??_7`) is not implemented**
//!   — a different ABI entirely (COFF/PE, no `_ZTV`/`_ZTI` naming), real
//!   separate follow-up work.
//! - **64-bit little-endian pointers only.** 32-bit targets are not
//!   handled (a `Vec<VirtualFunction>` reader that assumes 8-byte slots).
//! - **Not wired into `Engine`/`analyze` yet** — a standalone, fully-tested
//!   library capability first, same path `crate::dwarf`/`crate::sig` took.

use std::collections::HashMap;

use object::{Object, ObjectSection, ObjectSymbol, ObjectSymbolTable};

/// One virtual function slot in a vtable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualFunction {
    /// 0-based index among this vtable's function slots (i.e. *not*
    /// counting the offset-to-top/typeinfo header words).
    pub slot: usize,
    pub address: u64,
    /// Demangled name of the function symbol at `address`, when the
    /// binary has one.
    pub name: Option<String>,
}

/// One recovered polymorphic class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassInfo {
    /// Demangled class name, e.g. `"Derived"`.
    pub name: String,
    /// Address of the vtable *array start* (the `offset-to-top` slot —
    /// two pointers before the vptr value objects of this class actually
    /// store; see [`ClassInfo::address_point`]).
    pub vtable_address: u64,
    /// Address objects of this class store as their vptr: two pointers
    /// past `vtable_address`, skipping the offset-to-top and typeinfo
    /// header words.
    pub address_point: u64,
    /// Resolved address of this class's RTTI `type_info` object, if the
    /// vtable's typeinfo slot resolved to one.
    pub typeinfo_address: Option<u64>,
    /// Demangled base-class names, best-effort (see module docs: only
    /// no-inheritance and single-non-virtual-inheritance RTTI shapes are
    /// resolved to base names here).
    pub bases: Vec<String>,
    pub virtual_functions: Vec<VirtualFunction>,
}

const PTR: u64 = 8;

/// Recover every Itanium-ABI polymorphic class this binary defines a
/// vtable for.
pub fn recover_classes(data: &[u8]) -> Result<Vec<ClassInfo>, String> {
    let file = object::File::parse(data).map_err(|e| format!("parse object file: {e}"))?;

    let (relocs, reloc_symbol_names) = dynamic_reloc_targets(&file);
    let vtable_syms = symbols_with_prefix(&file, "_ZTV");
    let typeinfo_syms = symbols_with_prefix(&file, "_ZTI");
    let func_names = function_name_map(&file);

    // Vtable start addresses, sorted, so a vtable's function region can be
    // bounded by "the next vtable begins here" when the symbol carries no
    // usable size.
    let mut vtable_starts: Vec<u64> = vtable_syms.iter().map(|(addr, _)| *addr).collect();
    vtable_starts.sort_unstable();

    let mut classes = Vec::new();
    for (addr, sym_name) in &vtable_syms {
        let class_name = demangled_class_name(sym_name, "{vtable(", ")}");
        let address_point = addr + 2 * PTR;

        let typeinfo_address = read_slot(&file, &relocs, addr + PTR);
        let bases = typeinfo_address
            .map(|ti| recover_bases(&file, &relocs, &reloc_symbol_names, &typeinfo_syms, ti))
            .unwrap_or_default();

        let end = symbol_size_end(&file, sym_name, *addr)
            .or_else(|| next_vtable_start(&vtable_starts, *addr))
            .unwrap_or(u64::MAX);

        let mut virtual_functions = Vec::new();
        let mut slot_addr = address_point;
        let mut slot = 0usize;
        while slot_addr + PTR <= end {
            let Some(target) = read_slot(&file, &relocs, slot_addr) else {
                break;
            };
            if target == 0 {
                break;
            }
            virtual_functions.push(VirtualFunction {
                slot,
                address: target,
                name: func_names.get(&target).cloned(),
            });
            slot += 1;
            slot_addr += PTR;
        }

        classes.push(ClassInfo {
            name: class_name,
            vtable_address: *addr,
            address_point,
            typeinfo_address,
            bases,
            virtual_functions,
        });
    }
    classes.sort_by_key(|c| c.vtable_address);
    Ok(classes)
}

/// Resolve a `type_info` object's base classes, for the RTTI shapes this
/// module understands (see module docs).
fn recover_bases(
    file: &object::File<'_>,
    relocs: &HashMap<u64, u64>,
    reloc_symbol_names: &HashMap<u64, String>,
    typeinfo_syms: &[(u64, String)],
    typeinfo_addr: u64,
) -> Vec<String> {
    // word0 of a type_info object is its own vptr: the address point
    // (post-header) of __class_type_info's / __si_class_type_info's /
    // __vmi_class_type_info's own vtable. Which one it is tells us the
    // RTTI shape; we don't need the actual vtable contents.
    let kind = classify_type_info(file, relocs, reloc_symbol_names, typeinfo_addr);

    match kind {
        TypeInfoKind::SingleInheritance => {
            // word2 (offset 2*PTR: vptr, name, base_type) is a
            // __class_type_info* pointing directly at the base's
            // type_info object (no address-point skip for type_info
            // objects themselves — they have no offset-to-top header).
            let Some(base_ti) = read_slot(file, relocs, typeinfo_addr + 2 * PTR) else {
                return Vec::new();
            };
            match name_for_typeinfo_address(typeinfo_syms, base_ti) {
                Some(name) => vec![name],
                None => Vec::new(),
            }
        }
        TypeInfoKind::MultipleOrVirtualInheritance => {
            // __vmi_class_type_info: word2 = u32 flags, word2+4 = u32
            // base_count, then `base_count` entries of
            // { __base_class_type_info* base_type; long offset_flags; }
            // starting at word3 (offset 3*PTR).
            let Some(header) = read_slot(file, relocs, typeinfo_addr + 2 * PTR) else {
                return Vec::new();
            };
            let base_count = (header >> 32) as u32; // base_count is the high word on a little-endian u64 read of [flags:u32][base_count:u32]
            let mut names = Vec::new();
            for i in 0..base_count as u64 {
                let entry_addr = typeinfo_addr + 3 * PTR + i * 2 * PTR;
                let Some(base_ti) = read_slot(file, relocs, entry_addr) else {
                    break;
                };
                if let Some(name) = name_for_typeinfo_address(typeinfo_syms, base_ti) {
                    names.push(name);
                }
            }
            names
        }
        TypeInfoKind::NoInheritance | TypeInfoKind::Unknown => Vec::new(),
    }
}

enum TypeInfoKind {
    NoInheritance,
    SingleInheritance,
    MultipleOrVirtualInheritance,
    Unknown,
}

const NO_BASE_RTTI_VTABLE: &str = "_ZTVN10__cxxabiv117__class_type_infoE";
const SINGLE_RTTI_VTABLE: &str = "_ZTVN10__cxxabiv120__si_class_type_infoE";
const MULTI_RTTI_VTABLE: &str = "_ZTVN10__cxxabiv121__vmi_class_type_infoE";

fn rtti_kind_for_name(name: &str) -> Option<TypeInfoKind> {
    match name {
        NO_BASE_RTTI_VTABLE => Some(TypeInfoKind::NoInheritance),
        SINGLE_RTTI_VTABLE => Some(TypeInfoKind::SingleInheritance),
        MULTI_RTTI_VTABLE => Some(TypeInfoKind::MultipleOrVirtualInheritance),
        _ => None,
    }
}

/// Identify which of the three `__cxxabiv1` RTTI shapes a type_info
/// object at `typeinfo_addr` uses, by looking at its word0 (own vptr).
///
/// Two strategies, in order:
/// 1. If a dynamic relocation applies at that word0 offset (the PIC/PIE
///    case — the common one), read the relocation's *target symbol name*
///    directly. This works even when that target is itself an unresolved
///    external symbol (e.g. `__cxxabiv1::__class_type_info`'s vtable
///    lives in libstdc++, not this module) — an address-based comparison
///    would be ambiguous there, since every unresolved external symbol
///    nominally sits at address 0.
/// 2. Otherwise (the non-PIC case — raw resolved bytes), fall back to
///    comparing the resolved address point against every `_ZTVN…` symbol
///    (both static and dynamic symbol tables) this binary actually
///    defines or has resolved a real address for.
fn classify_type_info(
    file: &object::File<'_>,
    relocs: &HashMap<u64, u64>,
    reloc_symbol_names: &HashMap<u64, String>,
    typeinfo_addr: u64,
) -> TypeInfoKind {
    if let Some(name) = reloc_symbol_names.get(&typeinfo_addr) {
        if let Some(kind) = rtti_kind_for_name(name) {
            return kind;
        }
    }

    let Some(vptr_address_point) = read_slot(file, relocs, typeinfo_addr) else {
        return TypeInfoKind::Unknown;
    };
    let mut all_symbols: Vec<(u64, String)> = Vec::new();
    for sym in file.symbols() {
        if let Ok(name) = sym.name() {
            all_symbols.push((sym.address(), name.to_string()));
        }
    }
    if let Some(dynsyms) = file.dynamic_symbol_table() {
        for sym in dynsyms.symbols() {
            if let Ok(name) = sym.name() {
                all_symbols.push((sym.address(), name.to_string()));
            }
        }
    }
    for (addr, name) in &all_symbols {
        if addr + 2 * PTR == vptr_address_point {
            if let Some(kind) = rtti_kind_for_name(name) {
                return kind;
            }
        }
    }
    TypeInfoKind::Unknown
}

fn name_for_typeinfo_address(typeinfo_syms: &[(u64, String)], addr: u64) -> Option<String> {
    typeinfo_syms
        .iter()
        .find(|(a, _)| *a == addr)
        .map(|(_, n)| demangled_class_name(n, "typeinfo for ", ""))
}

/// Every dynamic relocation's file offset, resolved to a final target
/// address (`symbol address + addend`) — the values a loader would write
/// into those slots at load-address-0, i.e. exactly what this module
/// wants to read for a PIC/PIE binary's vtable slots.
fn dynamic_reloc_targets(file: &object::File<'_>) -> (HashMap<u64, u64>, HashMap<u64, String>) {
    let mut map = HashMap::new();
    let mut names = HashMap::new();
    let Some(relocs) = file.dynamic_relocations() else {
        return (map, names);
    };
    // Dynamic relocations' symbol indices are indices into the *dynamic*
    // symbol table (.dynsym), a separate table from the regular/static
    // one `Object::symbol_by_index` resolves against — using the wrong
    // table silently returns some other, unrelated symbol at that index.
    let Some(dynsyms) = file.dynamic_symbol_table() else {
        return (map, names);
    };
    for (offset, reloc) in relocs {
        if let object::RelocationTarget::Symbol(idx) = reloc.target() {
            if let Ok(sym) = dynsyms.symbol_by_index(idx) {
                let target = sym.address().wrapping_add(reloc.addend() as u64);
                map.insert(offset, target);
                if let Ok(name) = sym.name() {
                    names.insert(offset, name.to_string());
                }
            }
        }
    }
    (map, names)
}

/// Read the pointer-sized value logically stored at `addr`: the resolved
/// dynamic-relocation target if one applies there, else the raw section
/// bytes (the non-PIC case), else `None` if `addr` isn't backed by any
/// section with enough remaining bytes.
fn read_slot(file: &object::File<'_>, relocs: &HashMap<u64, u64>, addr: u64) -> Option<u64> {
    if let Some(target) = relocs.get(&addr) {
        return Some(*target);
    }
    for section in file.sections() {
        let start = section.address();
        let Ok(data) = section.data() else { continue };
        let end = start + data.len() as u64;
        if addr < start || addr + PTR > end {
            continue;
        }
        let off = (addr - start) as usize;
        let bytes: [u8; 8] = data[off..off + 8].try_into().ok()?;
        let raw = u64::from_le_bytes(bytes);
        return if raw == 0 { None } else { Some(raw) };
    }
    None
}

fn symbols_with_prefix(file: &object::File<'_>, prefix: &str) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    for sym in file.symbols() {
        let Ok(name) = sym.name() else { continue };
        if name.starts_with(prefix) && sym.address() != 0 {
            out.push((sym.address(), name.to_string()));
        }
    }
    out
}

fn function_name_map(file: &object::File<'_>) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    for sym in file.symbols() {
        if !sym.is_definition() || sym.kind() != object::SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        out.insert(sym.address(), demangle(name));
    }
    out
}

fn symbol_size_end(file: &object::File<'_>, name: &str, addr: u64) -> Option<u64> {
    for sym in file.symbols() {
        if sym.address() == addr && sym.name() == Ok(name) && sym.size() > 0 {
            return Some(addr + sym.size());
        }
    }
    None
}

fn next_vtable_start(sorted_starts: &[u64], addr: u64) -> Option<u64> {
    sorted_starts.iter().find(|&&s| s > addr).copied()
}

fn demangle(mangled: &str) -> String {
    cpp_demangle::Symbol::new(mangled)
        .map(|s| s.to_string())
        .unwrap_or_else(|_| mangled.to_string())
}

/// Demangle `mangled`, then strip a known constant prefix/suffix that
/// `cpp_demangle` wraps class names in for vtable/typeinfo symbols,
/// leaving just the class name. Falls back to the full demangled string
/// (still readable) if the wrapping ever doesn't match.
fn demangled_class_name(mangled: &str, prefix: &str, suffix: &str) -> String {
    let full = demangle(mangled);
    match full
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
    {
        Some(inner) => inner.to_string(),
        None => full,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn no_object_file_yields_a_clean_error_not_a_panic() {
        let result = recover_classes(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn empty_input_yields_a_clean_error() {
        let result = recover_classes(&[]);
        assert!(result.is_err());
    }

    // The remaining tests run against a real, clang++-compiled, lld-linked
    // x86_64 ELF shared object (checked in as a binary test fixture) built
    // from:
    //
    //   struct Base {
    //     virtual int foo() { return 1; }
    //     virtual int bar() { return 2; }
    //     virtual ~Base() {}
    //     int x;
    //   };
    //   struct Derived : Base {
    //     int foo() override { return 3; }
    //     virtual int baz() { return 4; }
    //     int y;
    //   };
    //
    // compiled `-fPIC` and linked `-shared`, so its vtable slots are real
    // R_X86_64_RELATIVE-relocated zero placeholders — proving this module
    // reads relocations, not just raw bytes.
    fn fixture() -> Vec<u8> {
        include_bytes!("../tests/fixtures/vtable_single_inheritance.so").to_vec()
    }

    #[test]
    fn recovers_both_classes_with_correct_names() {
        let classes = recover_classes(&fixture()).expect("recover");
        let names: Vec<&str> = classes.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"Base"), "{names:?}");
        assert!(names.contains(&"Derived"), "{names:?}");
    }

    #[test]
    fn derived_reports_base_as_its_rtti_base_class() {
        let classes = recover_classes(&fixture()).expect("recover");
        let derived = classes
            .iter()
            .find(|c| c.name == "Derived")
            .expect("Derived present");
        assert_eq!(derived.bases, vec!["Base".to_string()]);
    }

    #[test]
    fn base_has_no_rtti_base_class() {
        let classes = recover_classes(&fixture()).expect("recover");
        let base = classes
            .iter()
            .find(|c| c.name == "Base")
            .expect("Base present");
        assert!(base.bases.is_empty());
    }

    #[test]
    fn derived_vtable_overrides_foo_and_adds_baz_while_keeping_bar() {
        let classes = recover_classes(&fixture()).expect("recover");
        let derived = classes
            .iter()
            .find(|c| c.name == "Derived")
            .expect("Derived present");
        // Slot layout: [0]=dtor-complete, [1]=dtor-deleting, [2]=foo,
        // [3]=bar, [4]=baz (Itanium always emits both destructor
        // variants before any user virtual function).
        let names: Vec<Option<&str>> = derived
            .virtual_functions
            .iter()
            .map(|f| f.name.as_deref())
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.is_some_and(|n| n.contains("Derived") && n.contains("foo"))),
            "{names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| n.is_some_and(|n| n.contains("Base") && n.contains("bar"))),
            "{names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| n.is_some_and(|n| n.contains("Derived") && n.contains("baz"))),
            "{names:?}"
        );
        assert_eq!(derived.virtual_functions.len(), 5);
    }

    #[test]
    fn base_vtable_has_foo_bar_and_two_destructor_slots() {
        let classes = recover_classes(&fixture()).expect("recover");
        let base = classes
            .iter()
            .find(|c| c.name == "Base")
            .expect("Base present");
        assert_eq!(base.virtual_functions.len(), 4);
    }
}
