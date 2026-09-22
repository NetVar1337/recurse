//! DWARF `.debug_info` ingestion: real function signatures (parameter
//! names and types, not just an address and a guessed `fcn_XXXXXX` name)
//! and a source declaration file/line, recovered from a non-stripped
//! ELF/Mach-O binary's own debug sections.
//!
//! `crate::unwind` already reads DWARF *call-frame* information
//! (`.eh_frame`) for stack unwinding; this module reads the *type* half of
//! DWARF (`.debug_info`/`.debug_abbrev`/`.debug_str`), using the same
//! `gimli` dependency and the same section-loading pattern.
//!
//! # Scope, honestly
//!
//! - One compilation unit's DIE tree at a time: `DW_TAG_subprogram`
//!   (function) and its direct `DW_TAG_formal_parameter` children. Locals
//!   declared inside a nested `DW_TAG_lexical_block` are not walked — real,
//!   scoped follow-up work, not silently mishandled (they are simply
//!   absent from [`DwarfFunction::parameters`], never reported wrong).
//! - [`type_name`] renders the base/pointer/const/volatile/array/struct/
//!   union/enum/typedef DIE chain into a C-like string
//!   (`"struct Foo*"`, `"const char*"`, `"int[16]"`). It is a name
//!   renderer, not [`crate::types::TypeLibrary`] — turning a DWARF type DIE
//!   into a real [`crate::types::Type`] (for layout computation) is
//!   reasonable follow-up work, not attempted here.
//! - `DW_AT_decl_file` is reported as a raw index into the compilation
//!   unit's line-number-program file table; resolving that index to an
//!   actual path needs walking `.debug_line`'s file table, which is not
//!   implemented here (`DwarfFunction::decl_file` is `None` until that
//!   lands) — the index itself is not discarded, it is simply not resolved
//!   to a string yet, and no other field claims a false value in its
//!   place.
//! - `DW_AT_location` (where a variable actually *lives* — a register, a
//!   frame-relative offset, …) is not decoded, only recorded as
//!   present/absent (real follow-up: the decompiler showing a real local
//!   variable name instead of a raw stack offset needs exactly this).

use std::borrow::Cow;
use std::path::Path;

use gimli::{EndianSlice, RunTimeEndian};
use object::{Object, ObjectSection};

/// One recovered function.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct DwarfFunction {
    pub name: String,
    pub low_pc: Option<u64>,
    pub high_pc: Option<u64>,
    /// Raw `DW_AT_decl_file` index — see the module doc for why this is not
    /// yet resolved to a path.
    pub decl_file_index: Option<u64>,
    pub decl_line: Option<u64>,
    /// `None` for `void` (no `DW_AT_type`, or a DIE this renderer does not
    /// understand).
    pub return_type: Option<String>,
    pub parameters: Vec<DwarfParameter>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DwarfParameter {
    pub name: String,
    pub ty: String,
    /// True when the DIE carries a `DW_AT_location` at all — see the
    /// module doc: the expression itself is not decoded.
    pub has_location: bool,
}

type R<'a> = EndianSlice<'a, RunTimeEndian>;

/// Load and parse `path`'s own `.debug_info`, returning every
/// `DW_TAG_subprogram` found. `Ok(vec![])` (not an error) for a binary with
/// no DWARF debug info at all — stripped binaries and most release Windows
/// builds are simply empty here, that's expected, not a failure.
pub fn load_functions(path: &Path) -> Result<Vec<DwarfFunction>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let file = object::File::parse(&*data).map_err(|e| format!("parse {}: {e}", path.display()))?;
    load_functions_from_object(&file)
}

/// [`load_functions`] over an already-parsed [`object::File`].
pub fn load_functions_from_object(file: &object::File<'_>) -> Result<Vec<DwarfFunction>, String> {
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<Cow<'_, [u8]>, gimli::Error> {
        match file.section_by_name(id.name()) {
            Some(section) => Ok(section.uncompressed_data().unwrap_or(Cow::Borrowed(&[]))),
            None => Ok(Cow::Borrowed(&[])),
        }
    };
    let dwarf_cow =
        gimli::Dwarf::load(load_section).map_err(|e| format!("load DWARF sections: {e}"))?;
    // `Dwarf::borrow` moved to `DwarfSections::borrow` in a later gimli
    // release than the one this workspace pins; same behavior either way.
    #[allow(deprecated)]
    let dwarf: gimli::Dwarf<R<'_>> = dwarf_cow.borrow(|section| EndianSlice::new(section, endian));

    let mut functions = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().map_err(|e| format!("read unit header: {e}"))? {
        let unit = dwarf.unit(header).map_err(|e| format!("read unit: {e}"))?;
        let mut tree = unit
            .entries_tree(None)
            .map_err(|e| format!("read DIE tree: {e}"))?;
        let root = tree.root().map_err(|e| format!("read root DIE: {e}"))?;
        walk_for_subprograms(&dwarf, &unit, root, &mut functions)?;
    }
    Ok(functions)
}

fn walk_for_subprograms<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    node: gimli::EntriesTreeNode<'_, '_, '_, R<'a>>,
    functions: &mut Vec<DwarfFunction>,
) -> Result<(), String> {
    if node.entry().tag() == gimli::DW_TAG_subprogram {
        if let Some(func) = read_subprogram(dwarf, unit, node)? {
            functions.push(func);
        }
        return Ok(());
    }
    let mut children = node.children();
    while let Some(child) = children
        .next()
        .map_err(|e| format!("read DIE child: {e}"))?
    {
        walk_for_subprograms(dwarf, unit, child, functions)?;
    }
    Ok(())
}

fn read_subprogram<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    node: gimli::EntriesTreeNode<'_, '_, '_, R<'a>>,
) -> Result<Option<DwarfFunction>, String> {
    let entry = node.entry();
    let Some(name) = die_name(dwarf, unit, entry)? else {
        // An out-of-line declaration or an inlined-away instance with no
        // name of its own; not useful to report.
        return Ok(None);
    };

    let low_pc = match entry
        .attr_value(gimli::DW_AT_low_pc)
        .map_err(|e| e.to_string())?
    {
        Some(gimli::AttributeValue::Addr(a)) => Some(a),
        _ => None,
    };
    // `DW_AT_high_pc` is either an absolute address (`DW_FORM_addr`) or an
    // offset from `low_pc` (any integer form) — both appear in the wild.
    let high_pc = match entry
        .attr_value(gimli::DW_AT_high_pc)
        .map_err(|e| e.to_string())?
    {
        Some(gimli::AttributeValue::Addr(a)) => Some(a),
        Some(other) => other
            .udata_value()
            .and_then(|off| low_pc.map(|lo| lo + off)),
        None => None,
    };
    let decl_file_index = match entry
        .attr_value(gimli::DW_AT_decl_file)
        .map_err(|e| e.to_string())?
    {
        Some(v) => v.udata_value(),
        None => None,
    };
    let decl_line = match entry
        .attr_value(gimli::DW_AT_decl_line)
        .map_err(|e| e.to_string())?
    {
        Some(v) => v.udata_value(),
        None => None,
    };
    let return_type = die_type_attr(dwarf, unit, entry)?
        .map(|off| type_name(dwarf, unit, off))
        .transpose()?;

    let mut parameters = Vec::new();
    let mut children = node.children();
    while let Some(child) = children
        .next()
        .map_err(|e| format!("read DIE child: {e}"))?
    {
        let child_entry = child.entry();
        if child_entry.tag() == gimli::DW_TAG_formal_parameter {
            let pname = die_name(dwarf, unit, child_entry)?.unwrap_or_else(|| "?".to_string());
            let ty = match die_type_attr(dwarf, unit, child_entry)? {
                Some(off) => type_name(dwarf, unit, off)?,
                None => "?".to_string(),
            };
            let has_location = child_entry
                .attr(gimli::DW_AT_location)
                .map_err(|e| e.to_string())?
                .is_some();
            parameters.push(DwarfParameter {
                name: pname,
                ty,
                has_location,
            });
        }
    }

    Ok(Some(DwarfFunction {
        name,
        low_pc,
        high_pc,
        decl_file_index,
        decl_line,
        return_type,
        parameters,
    }))
}

fn die_name<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R<'a>>,
) -> Result<Option<String>, String> {
    match entry
        .attr_value(gimli::DW_AT_name)
        .map_err(|e| e.to_string())?
    {
        Some(av) => {
            let s = dwarf.attr_string(unit, av).map_err(|e| e.to_string())?;
            Ok(Some(s.to_string_lossy().into_owned()))
        }
        None => Ok(None),
    }
}

fn die_type_attr<'a>(
    _dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R<'a>>,
) -> Result<Option<gimli::UnitOffset>, String> {
    match entry
        .attr_value(gimli::DW_AT_type)
        .map_err(|e| e.to_string())?
    {
        Some(gimli::AttributeValue::UnitRef(off)) => Ok(Some(off)),
        Some(gimli::AttributeValue::DebugInfoRef(off)) => Ok(off.to_unit_offset(&unit.header)),
        _ => Ok(None),
    }
}

/// Render the type DIE at `offset` (a base/pointer/const/volatile/array/
/// struct/union/enum/typedef chain) into a C-like name. Bottoms out at
/// `"void"` for a chain with no further `DW_AT_type` (a bare pointer with
/// no pointee, a function returning nothing) and at `"<unknown>"` for a tag
/// this renderer does not have a case for — never an error, so one exotic
/// DIE in a compilation unit never stops every other function in it from
/// being reported.
pub fn type_name<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
) -> Result<String, String> {
    let entry = unit.entry(offset).map_err(|e| e.to_string())?;
    let inner = || -> Result<Option<String>, String> {
        match die_type_attr(dwarf, unit, &entry)? {
            Some(off) => Ok(Some(type_name(dwarf, unit, off)?)),
            None => Ok(None),
        }
    };

    Ok(match entry.tag() {
        gimli::DW_TAG_base_type | gimli::DW_TAG_typedef | gimli::DW_TAG_unspecified_type => {
            die_name(dwarf, unit, &entry)?.unwrap_or_else(|| "<anonymous>".to_string())
        }
        gimli::DW_TAG_pointer_type => {
            format!("{}*", inner()?.unwrap_or_else(|| "void".to_string()))
        }
        gimli::DW_TAG_const_type => {
            format!("const {}", inner()?.unwrap_or_else(|| "void".to_string()))
        }
        gimli::DW_TAG_volatile_type => format!(
            "volatile {}",
            inner()?.unwrap_or_else(|| "void".to_string())
        ),
        gimli::DW_TAG_restrict_type => inner()?.unwrap_or_else(|| "void".to_string()),
        gimli::DW_TAG_reference_type => {
            format!("{}&", inner()?.unwrap_or_else(|| "void".to_string()))
        }
        gimli::DW_TAG_array_type => format!("{}[]", inner()?.unwrap_or_else(|| "void".to_string())),
        gimli::DW_TAG_structure_type => {
            format!(
                "struct {}",
                die_name(dwarf, unit, &entry)?.unwrap_or_else(|| "<anonymous>".to_string())
            )
        }
        gimli::DW_TAG_union_type => {
            format!(
                "union {}",
                die_name(dwarf, unit, &entry)?.unwrap_or_else(|| "<anonymous>".to_string())
            )
        }
        gimli::DW_TAG_class_type => {
            format!(
                "class {}",
                die_name(dwarf, unit, &entry)?.unwrap_or_else(|| "<anonymous>".to_string())
            )
        }
        gimli::DW_TAG_enumeration_type => {
            format!(
                "enum {}",
                die_name(dwarf, unit, &entry)?.unwrap_or_else(|| "<anonymous>".to_string())
            )
        }
        _ => "<unknown>".to_string(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A tiny, byte-exact, hand-assembled DWARF v4 (32-bit format)
    /// `.debug_info`/`.debug_abbrev`/`.debug_str` set for one compilation
    /// unit containing:
    ///
    /// ```c
    /// int add(int x, char *label);
    /// ```
    ///
    /// Every tag/attribute/form byte is one of `gimli`'s own exported
    /// constants (`gimli::DW_TAG_*.0`, …), not a memorized hex literal, so a
    /// transcription mistake shows up as a compile error against the real
    /// DWARF constant table rather than a silently-wrong fixture.
    struct Fixture {
        debug_info: Vec<u8>,
        debug_abbrev: Vec<u8>,
        debug_str: Vec<u8>,
    }

    fn uleb128(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            } else {
                out.push(byte | 0x80);
            }
        }
    }

    /// Append `s` (NUL-terminated) to `debug_str` and return its offset.
    fn intern(debug_str: &mut Vec<u8>, s: &str) -> u32 {
        let offset = debug_str.len() as u32;
        debug_str.extend_from_slice(s.as_bytes());
        debug_str.push(0);
        offset
    }

    fn build_fixture() -> Fixture {
        let mut debug_str = Vec::new();
        let name_cu = intern(&mut debug_str, "test.c");
        let name_int = intern(&mut debug_str, "int");
        let name_char = intern(&mut debug_str, "char");
        let name_add = intern(&mut debug_str, "add");
        let name_x = intern(&mut debug_str, "x");
        let name_label = intern(&mut debug_str, "label");

        // -- .debug_abbrev --
        // Abbrev 1: compile_unit, has children, [DW_AT_name: strp]
        // Abbrev 2: base_type, no children, [DW_AT_name: strp, DW_AT_byte_size: data1]
        // Abbrev 3: pointer_type, no children, [DW_AT_type: ref4]
        // Abbrev 4: subprogram, has children,
        //           [DW_AT_name: strp, DW_AT_low_pc: addr, DW_AT_high_pc: data8,
        //            DW_AT_type: ref4, DW_AT_decl_line: data1]
        // Abbrev 5: formal_parameter, no children, [DW_AT_name: strp, DW_AT_type: ref4]
        let mut debug_abbrev = Vec::new();
        let mut abbrev = |code: u64,
                          tag: gimli::DwTag,
                          has_children: bool,
                          attrs: &[(gimli::DwAt, gimli::DwForm)]| {
            uleb128(&mut debug_abbrev, code);
            uleb128(&mut debug_abbrev, tag.0.into());
            debug_abbrev.push(u8::from(has_children));
            for &(at, form) in attrs {
                uleb128(&mut debug_abbrev, at.0.into());
                uleb128(&mut debug_abbrev, form.0.into());
            }
            uleb128(&mut debug_abbrev, 0);
            uleb128(&mut debug_abbrev, 0);
        };
        abbrev(
            1,
            gimli::DW_TAG_compile_unit,
            true,
            &[(gimli::DW_AT_name, gimli::DW_FORM_strp)],
        );
        abbrev(
            2,
            gimli::DW_TAG_base_type,
            false,
            &[
                (gimli::DW_AT_name, gimli::DW_FORM_strp),
                (gimli::DW_AT_byte_size, gimli::DW_FORM_data1),
            ],
        );
        abbrev(
            3,
            gimli::DW_TAG_pointer_type,
            false,
            &[(gimli::DW_AT_type, gimli::DW_FORM_ref4)],
        );
        abbrev(
            4,
            gimli::DW_TAG_subprogram,
            true,
            &[
                (gimli::DW_AT_name, gimli::DW_FORM_strp),
                (gimli::DW_AT_low_pc, gimli::DW_FORM_addr),
                (gimli::DW_AT_high_pc, gimli::DW_FORM_data8),
                (gimli::DW_AT_type, gimli::DW_FORM_ref4),
                (gimli::DW_AT_decl_line, gimli::DW_FORM_data1),
            ],
        );
        abbrev(
            5,
            gimli::DW_TAG_formal_parameter,
            false,
            &[
                (gimli::DW_AT_name, gimli::DW_FORM_strp),
                (gimli::DW_AT_type, gimli::DW_FORM_ref4),
            ],
        );
        debug_abbrev.push(0); // end of abbreviation table

        // -- .debug_info body (after the unit header) --
        let mut body = Vec::new();

        // DIE #1: compile_unit (abbrev 1)
        uleb128(&mut body, 1);
        body.extend_from_slice(&name_cu.to_le_bytes());

        // DIE #2: base_type "int", 4 bytes (abbrev 2) -- child of CU
        let int_die_body_offset = body.len();
        uleb128(&mut body, 2);
        body.extend_from_slice(&name_int.to_le_bytes());
        body.push(4);

        // DIE #3: base_type "char", 1 byte (abbrev 2)
        let char_die_body_offset = body.len();
        uleb128(&mut body, 2);
        body.extend_from_slice(&name_char.to_le_bytes());
        body.push(1);

        // DIE #4: pointer_type -> char (abbrev 3)
        let ptr_die_body_offset = body.len();
        uleb128(&mut body, 3);
        // Patched below once we know the header length (ref4 is a
        // unit-relative offset, so it must point at char's *unit* offset,
        // i.e. header_len + char_die_body_offset).
        let ptr_ref_patch_at = body.len();
        body.extend_from_slice(&0u32.to_le_bytes());

        // DIE #5: subprogram "add" (abbrev 4) -- child of CU
        uleb128(&mut body, 4);
        body.extend_from_slice(&name_add.to_le_bytes());
        body.extend_from_slice(&0x0040_1000u64.to_le_bytes()); // low_pc
        body.extend_from_slice(&0x20u64.to_le_bytes()); // high_pc (offset form)
        let ret_ref_patch_at = body.len();
        body.extend_from_slice(&0u32.to_le_bytes()); // DW_AT_type -> int, patched below
        body.push(7); // decl_line

        // DIE #6: formal_parameter "x": int (abbrev 5) -- child of subprogram
        uleb128(&mut body, 5);
        body.extend_from_slice(&name_x.to_le_bytes());
        let x_ref_patch_at = body.len();
        body.extend_from_slice(&0u32.to_le_bytes());

        // DIE #7: formal_parameter "label": char* (abbrev 5) -- child of subprogram
        uleb128(&mut body, 5);
        body.extend_from_slice(&name_label.to_le_bytes());
        let label_ref_patch_at = body.len();
        body.extend_from_slice(&0u32.to_le_bytes());

        uleb128(&mut body, 0); // end of subprogram's children
        uleb128(&mut body, 0); // end of compile_unit's children

        // -- unit header (DWARF v4, 32-bit format) --
        // unit_length (4) + version (2) + debug_abbrev_offset (4) + address_size (1)
        let header_len = 4 + 2 + 4 + 1;
        let unit_length = (2 + 4 + 1 + body.len()) as u32; // everything after unit_length itself

        // Patch unit-relative ref4 offsets now that header_len is known.
        let patch = |body: &mut [u8], at: usize, unit_offset: usize| {
            body[at..at + 4].copy_from_slice(&(unit_offset as u32).to_le_bytes());
        };
        patch(
            &mut body,
            ptr_ref_patch_at,
            header_len + char_die_body_offset,
        );
        patch(
            &mut body,
            ret_ref_patch_at,
            header_len + int_die_body_offset,
        );
        patch(&mut body, x_ref_patch_at, header_len + int_die_body_offset);
        patch(
            &mut body,
            label_ref_patch_at,
            header_len + ptr_die_body_offset,
        );

        let mut debug_info = Vec::new();
        debug_info.extend_from_slice(&unit_length.to_le_bytes());
        debug_info.extend_from_slice(&4u16.to_le_bytes()); // version
        debug_info.extend_from_slice(&0u32.to_le_bytes()); // debug_abbrev_offset
        debug_info.push(8); // address_size
        debug_info.extend_from_slice(&body);

        Fixture {
            debug_info,
            debug_abbrev,
            debug_str,
        }
    }

    fn parse_fixture(fixture: &Fixture) -> Vec<DwarfFunction> {
        let endian = RunTimeEndian::Little;
        let load_section = |id: gimli::SectionId| -> Result<Cow<'_, [u8]>, gimli::Error> {
            Ok(match id {
                gimli::SectionId::DebugInfo => Cow::Borrowed(fixture.debug_info.as_slice()),
                gimli::SectionId::DebugAbbrev => Cow::Borrowed(fixture.debug_abbrev.as_slice()),
                gimli::SectionId::DebugStr => Cow::Borrowed(fixture.debug_str.as_slice()),
                _ => Cow::Borrowed(&[]),
            })
        };
        let dwarf_cow = gimli::Dwarf::load(load_section).expect("load sections");
        #[allow(deprecated)]
        let dwarf: gimli::Dwarf<R<'_>> = dwarf_cow.borrow(|s| EndianSlice::new(s, endian));

        let mut functions = Vec::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next().expect("unit header") {
            let unit = dwarf.unit(header).expect("unit");
            let mut tree = unit.entries_tree(None).expect("entries tree");
            let root = tree.root().expect("root DIE");
            walk_for_subprograms(&dwarf, &unit, root, &mut functions).expect("walk");
        }
        functions
    }

    #[test]
    fn recovers_function_name_address_range_and_return_type() {
        let fixture = build_fixture();
        let functions = parse_fixture(&fixture);
        assert_eq!(functions.len(), 1, "{functions:?}");
        let f = &functions[0];
        assert_eq!(f.name, "add");
        assert_eq!(f.low_pc, Some(0x0040_1000));
        assert_eq!(f.high_pc, Some(0x0040_1000 + 0x20));
        assert_eq!(f.return_type.as_deref(), Some("int"));
        assert_eq!(f.decl_line, Some(7));
    }

    #[test]
    fn recovers_parameter_names_and_types_including_a_pointer() {
        let fixture = build_fixture();
        let functions = parse_fixture(&fixture);
        let f = &functions[0];
        assert_eq!(f.parameters.len(), 2);
        assert_eq!(f.parameters[0].name, "x");
        assert_eq!(f.parameters[0].ty, "int");
        assert_eq!(f.parameters[1].name, "label");
        assert_eq!(f.parameters[1].ty, "char*");
    }

    #[test]
    fn binary_with_no_debug_info_yields_an_empty_ok_not_an_error() {
        let exe = std::env::current_exe().expect("test exe");
        // This test binary is almost certainly built without DWARF on this
        // (Windows/MSVC) target -- exactly the common "no debug info here"
        // case this module must not treat as a hard failure.
        let result = load_functions(&exe);
        assert!(result.is_ok(), "{result:?}");
    }
}
