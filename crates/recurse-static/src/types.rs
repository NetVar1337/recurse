//! A small C-like type system: structs, unions, enums, typedefs, pointers,
//! and arrays, with real struct/union layout (member offsets, size,
//! alignment, computed under the C ABI's natural-alignment-plus-padding
//! rule) — plus a from-scratch parser that imports declarations straight
//! from a `.h` file's text, so a type library can be built the same way an
//! analyst would in IDA/Ghidra ("paste this struct from the SDK header")
//! instead of only by hand.
//!
//! Not wired into [`crate::engine::Engine`] yet — this module is a
//! standalone, fully-tested library capability
//! ([`TypeLibrary`]/[`parse_header`]) a future `analyze op:"types"` (or the
//! UI's own type editor) can sit directly on top of, the same way
//! `crates/recurse-vtil` started as a library before `Engine::lift` wired
//! it in. Kept deliberately scoped:
//!
//! - **No preprocessor.** `#include`/`#define`/`#ifdef`/… lines are
//!   dropped, not expanded — pre-process a header with `cpp`/`clang -E`
//!   first if it needs macros resolved. Comments (`//`, `/* … */`) *are*
//!   stripped.
//! - **No function pointers, no bitfields, no `#pragma pack`.** Every field
//!   is a scalar, a pointer, an array, or a named struct/union/enum —
//!   covers the overwhelming majority of real SDK/vendor headers, not the
//!   full C grammar.
//! - **Declaration order matters.** A struct that embeds another struct *by
//!   value* must be declared after the type it embeds (normal C rule); by
//!   *pointer* there is no such restriction, since a pointer's size never
//!   depends on what it points to.
//! - **`long`/`long long` assume LP64** (8 bytes) — the common case for the
//!   x86-64/AArch64 binaries this workspace otherwise targets; `size_t`
//!   takes the pointer width passed to [`TypeLibrary::new`] instead of a
//!   fixed guess.

use std::collections::HashMap;

/// A type: either a fixed primitive, a pointer/array built from another
/// [`Type`], or a reference to a named struct/union/enum/typedef resolved
/// against whichever [`TypeLibrary`] the type is asked about.
#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Void,
    Bool,
    Int {
        bits: u32,
        signed: bool,
    },
    Float {
        bits: u32,
    },
    Pointer(Box<Type>),
    Array(Box<Type>, u64),
    /// A struct, union, enum, or typedef name — looked up in whichever
    /// [`TypeLibrary`] this [`Type`] is asked about, not resolved at parse
    /// time.
    Named(String),
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Void => write!(f, "void"),
            Type::Bool => write!(f, "bool"),
            Type::Int { bits, signed: true } => write!(f, "int{bits}_t"),
            Type::Int {
                bits,
                signed: false,
            } => write!(f, "uint{bits}_t"),
            Type::Float { bits } => write!(f, "float{bits}"),
            Type::Pointer(inner) => write!(f, "{inner}*"),
            Type::Array(inner, n) => write!(f, "{inner}[{n}]"),
            Type::Named(name) => write!(f, "{name}"),
        }
    }
}

/// One member of a [`StructDef`]/[`UnionDef`], with its computed byte
/// offset from the start of the containing type.
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: String,
    pub ty: Type,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
    pub size: u64,
    pub align: u64,
}

/// A union's fields all start at offset 0; `size`/`align` are the widest
/// member's.
#[derive(Clone, Debug, PartialEq)]
pub struct UnionDef {
    pub name: String,
    pub fields: Vec<Field>,
    pub size: u64,
    pub align: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<(String, i64)>,
}

/// A collection of named types, with real layout computation. `pointer_bits`
/// (32 or 64) sizes every [`Type::Pointer`] and resolves `size_t`/`ssize_t`
/// when importing a header.
#[derive(Clone, Debug)]
pub struct TypeLibrary {
    pointer_bits: u32,
    structs: HashMap<String, StructDef>,
    unions: HashMap<String, UnionDef>,
    enums: HashMap<String, EnumDef>,
    typedefs: HashMap<String, Type>,
}

/// Round `offset` up to the next multiple of `align` (`align` of `0`
/// treated as `1`, so a zero-sized/unknown-alignment member never panics or
/// divides by zero).
fn align_up(offset: u64, align: u64) -> u64 {
    let align = align.max(1);
    offset.div_ceil(align) * align
}

impl TypeLibrary {
    pub fn new(pointer_bits: u32) -> Self {
        Self {
            pointer_bits,
            structs: HashMap::new(),
            unions: HashMap::new(),
            enums: HashMap::new(),
            typedefs: HashMap::new(),
        }
    }

    pub fn structs(&self) -> impl Iterator<Item = &StructDef> {
        self.structs.values()
    }
    pub fn unions(&self) -> impl Iterator<Item = &UnionDef> {
        self.unions.values()
    }
    pub fn enums(&self) -> impl Iterator<Item = &EnumDef> {
        self.enums.values()
    }

    pub fn get_struct(&self, name: &str) -> Option<&StructDef> {
        self.structs.get(name)
    }
    pub fn get_union(&self, name: &str) -> Option<&UnionDef> {
        self.unions.get(name)
    }
    pub fn get_enum(&self, name: &str) -> Option<&EnumDef> {
        self.enums.get(name)
    }

    /// `(size, align)` of `ty` in this library, resolving [`Type::Named`]
    /// against whatever has been defined so far. `Err` names the first
    /// unresolvable type — most commonly a struct referenced before it was
    /// defined (see the module doc's declaration-order note).
    pub fn size_align(&self, ty: &Type) -> Result<(u64, u64), String> {
        match ty {
            Type::Void => Ok((0, 1)),
            Type::Bool => Ok((1, 1)),
            Type::Int { bits, .. } => {
                let bytes = u64::from(*bits).div_ceil(8);
                Ok((bytes, bytes.min(8)))
            }
            Type::Float { bits } => {
                let bytes = u64::from(*bits) / 8;
                Ok((bytes, bytes.min(8)))
            }
            Type::Pointer(_) => {
                let bytes = u64::from(self.pointer_bits) / 8;
                Ok((bytes, bytes))
            }
            Type::Array(inner, len) => {
                let (size, align) = self.size_align(inner)?;
                Ok((size * len, align))
            }
            Type::Named(name) => {
                if let Some(s) = self.structs.get(name) {
                    Ok((s.size, s.align))
                } else if let Some(u) = self.unions.get(name) {
                    Ok((u.size, u.align))
                } else if self.enums.contains_key(name) {
                    Ok((4, 4)) // `enum` defaults to `int`-sized.
                } else if let Some(t) = self.typedefs.get(name) {
                    self.size_align(t)
                } else {
                    Err(format!("unknown type `{name}`"))
                }
            }
        }
    }

    /// Define (or redefine) a struct from an ordered list of `(name, type)`
    /// members, computing each member's offset under natural alignment.
    pub fn define_struct(&mut self, name: &str, members: &[(String, Type)]) -> Result<(), String> {
        let mut offset = 0u64;
        let mut max_align = 1u64;
        let mut fields = Vec::with_capacity(members.len());
        for (field_name, ty) in members {
            let (size, align) = self.size_align(ty)?;
            offset = align_up(offset, align);
            fields.push(Field {
                name: field_name.clone(),
                ty: ty.clone(),
                offset,
            });
            offset += size;
            max_align = max_align.max(align.max(1));
        }
        let size = align_up(offset, max_align);
        self.structs.insert(
            name.to_string(),
            StructDef {
                name: name.to_string(),
                fields,
                size,
                align: max_align,
            },
        );
        Ok(())
    }

    /// Define (or redefine) a union: every member starts at offset 0; size
    /// and alignment are the widest/strictest member's.
    pub fn define_union(&mut self, name: &str, members: &[(String, Type)]) -> Result<(), String> {
        let mut size = 0u64;
        let mut align = 1u64;
        let mut fields = Vec::with_capacity(members.len());
        for (field_name, ty) in members {
            let (member_size, member_align) = self.size_align(ty)?;
            fields.push(Field {
                name: field_name.clone(),
                ty: ty.clone(),
                offset: 0,
            });
            size = size.max(member_size);
            align = align.max(member_align.max(1));
        }
        let size = align_up(size, align);
        self.unions.insert(
            name.to_string(),
            UnionDef {
                name: name.to_string(),
                fields,
                size,
                align,
            },
        );
        Ok(())
    }

    pub fn define_enum(&mut self, name: &str, variants: Vec<(String, i64)>) {
        self.enums.insert(
            name.to_string(),
            EnumDef {
                name: name.to_string(),
                variants,
            },
        );
    }

    pub fn define_typedef(&mut self, name: &str, ty: Type) {
        self.typedefs.insert(name.to_string(), ty);
    }

    /// Parse `source` as a (preprocessor-free) C header and define every
    /// struct/union/enum/typedef it declares, in file order. Returns the
    /// names defined, in that same order.
    pub fn import_header(&mut self, source: &str) -> Result<Vec<String>, String> {
        let decls = parse_header(source)?;
        let mut defined = Vec::with_capacity(decls.len());
        for decl in decls {
            match decl {
                Decl::Struct(name, members) => {
                    self.define_struct(&name, &members)?;
                    defined.push(name);
                }
                Decl::Union(name, members) => {
                    self.define_union(&name, &members)?;
                    defined.push(name);
                }
                Decl::Enum(name, variants) => {
                    self.define_enum(&name, variants);
                    defined.push(name);
                }
                Decl::Typedef(name, ty) => {
                    self.define_typedef(&name, ty);
                    defined.push(name);
                }
            }
        }
        Ok(defined)
    }
}

// ---------------------------------------------------------------------------
// C header parsing
// ---------------------------------------------------------------------------

/// One top-level declaration [`parse_header`] recognises.
#[derive(Clone, Debug, PartialEq)]
pub enum Decl {
    Struct(String, Vec<(String, Type)>),
    Union(String, Vec<(String, Type)>),
    Enum(String, Vec<(String, i64)>),
    Typedef(String, Type),
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Number(i64),
    Punct(char),
}

/// Strip `//`/`/* */` comments and drop whole preprocessor-directive lines
/// (anything starting with `#`, after leading whitespace) — see the module
/// doc: this parser does not run a preprocessor.
fn strip_comments_and_directives(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut at_line_start = true;
    while let Some(c) = chars.next() {
        if c == '#' && at_line_start {
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
            }
            at_line_start = true;
            continue;
        }
        if c == '/' && chars.peek() == Some(&'/') {
            for next in chars.by_ref() {
                if next == '\n' {
                    out.push('\n');
                    break;
                }
            }
            at_line_start = true;
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = ' ';
            for next in chars.by_ref() {
                if prev == '*' && next == '/' {
                    break;
                }
                prev = next;
            }
            out.push(' ');
            at_line_start = false;
            continue;
        }
        at_line_start = c == '\n' || (at_line_start && c.is_whitespace());
        out.push(c);
    }
    out
}

fn tokenize(source: &str) -> Vec<Tok> {
    let cleaned = strip_comments_and_directives(source);
    let chars: Vec<char> = cleaned.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            toks.push(Tok::Ident(chars[start..i].iter().collect()));
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            toks.push(Tok::Number(parse_int_literal(&text)));
            continue;
        }
        match c {
            '{' | '}' | '(' | ')' | '[' | ']' | ';' | ',' | '*' | '=' | '-' => {
                toks.push(Tok::Punct(c));
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    toks
}

fn parse_int_literal(text: &str) -> i64 {
    let trimmed = text.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        trimmed.parse().unwrap_or(0)
    }
}

const TYPE_KEYWORDS: &[&str] = &[
    "void", "bool", "_Bool", "char", "short", "int", "long", "unsigned", "signed", "float",
    "double",
];

fn fixed_width(name: &str, pointer_bits: u32) -> Option<Type> {
    Some(match name {
        "int8_t" => Type::Int {
            bits: 8,
            signed: true,
        },
        "uint8_t" | "byte" | "BYTE" => Type::Int {
            bits: 8,
            signed: false,
        },
        "int16_t" => Type::Int {
            bits: 16,
            signed: true,
        },
        "uint16_t" | "WORD" => Type::Int {
            bits: 16,
            signed: false,
        },
        "int32_t" => Type::Int {
            bits: 32,
            signed: true,
        },
        "uint32_t" | "DWORD" => Type::Int {
            bits: 32,
            signed: false,
        },
        "int64_t" => Type::Int {
            bits: 64,
            signed: true,
        },
        "uint64_t" | "QWORD" => Type::Int {
            bits: 64,
            signed: false,
        },
        "size_t" => Type::Int {
            bits: pointer_bits,
            signed: false,
        },
        "ssize_t" | "ptrdiff_t" => Type::Int {
            bits: pointer_bits,
            signed: true,
        },
        _ => return None,
    })
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    pointer_bits: u32,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn peek_ident_is(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(s)) if s == word)
    }

    fn expect_ident(&mut self) -> Result<String, String> {
        let pos = self.pos;
        match self.bump() {
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(format!(
                "expected identifier, found {other:?} near token {pos}"
            )),
        }
    }

    fn expect_punct(&mut self, c: char) -> Result<(), String> {
        let pos = self.pos;
        match self.bump() {
            Some(Tok::Punct(p)) if p == c => Ok(()),
            other => Err(format!("expected '{c}', found {other:?} near token {pos}")),
        }
    }

    fn eat_punct(&mut self, c: char) -> bool {
        if matches!(self.peek(), Some(Tok::Punct(p)) if *p == c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_number(&mut self) -> Result<i64, String> {
        let negative = self.eat_punct('-');
        let pos = self.pos;
        match self.bump() {
            Some(Tok::Number(n)) => Ok(if negative { -n } else { n }),
            other => Err(format!(
                "expected a number, found {other:?} near token {pos}"
            )),
        }
    }

    fn parse_type_spec(&mut self) -> Result<Type, String> {
        if self.peek_ident_is("struct") || self.peek_ident_is("union") || self.peek_ident_is("enum")
        {
            self.bump();
            let name = self.expect_ident()?;
            return Ok(Type::Named(name));
        }
        if let Some(Tok::Ident(first)) = self.peek() {
            if let Some(ty) = fixed_width(first, self.pointer_bits) {
                self.bump();
                return Ok(ty);
            }
        }
        let mut words: Vec<String> = Vec::new();
        while let Some(Tok::Ident(s)) = self.peek() {
            if TYPE_KEYWORDS.contains(&s.as_str()) {
                words.push(s.clone());
                self.bump();
            } else {
                break;
            }
        }
        if words.is_empty() {
            let name = self.expect_ident()?;
            return Ok(Type::Named(name));
        }
        Ok(resolve_builtin_combo(&words))
    }

    /// Zero or more `*`, one identifier, optional `[N]` — the declarator
    /// attached to a type-spec already parsed into `base`.
    fn parse_declarator(&mut self, base: &Type) -> Result<(String, Type), String> {
        let mut ty = base.clone();
        while self.eat_punct('*') {
            ty = Type::Pointer(Box::new(ty));
        }
        let name = self.expect_ident()?;
        if self.eat_punct('[') {
            let len = self.expect_number()? as u64;
            self.expect_punct(']')?;
            ty = Type::Array(Box::new(ty), len);
        }
        Ok((name, ty))
    }

    /// `<type-spec> <declarator> (, <declarator>)* ;` — one member line of a
    /// struct/union body, possibly declaring several fields at once
    /// (`int a, b[4];`).
    fn parse_member_line(&mut self) -> Result<Vec<(String, Type)>, String> {
        let base = self.parse_type_spec()?;
        let mut out = Vec::new();
        loop {
            out.push(self.parse_declarator(&base)?);
            if self.eat_punct(',') {
                continue;
            }
            break;
        }
        self.expect_punct(';')?;
        Ok(out)
    }

    fn parse_struct_or_union_body(&mut self) -> Result<(String, Vec<(String, Type)>), String> {
        self.bump(); // `struct` / `union`
        let name = self.expect_ident()?;
        self.expect_punct('{')?;
        let mut members = Vec::new();
        while !matches!(self.peek(), Some(Tok::Punct('}'))) {
            members.extend(self.parse_member_line()?);
        }
        self.expect_punct('}')?;
        self.expect_punct(';')?;
        Ok((name, members))
    }

    fn parse_enum(&mut self) -> Result<Decl, String> {
        self.bump(); // `enum`
        let name = self.expect_ident()?;
        self.expect_punct('{')?;
        let mut variants = Vec::new();
        let mut next_value = 0i64;
        while !matches!(self.peek(), Some(Tok::Punct('}'))) {
            let variant_name = self.expect_ident()?;
            let value = if self.eat_punct('=') {
                self.expect_number()?
            } else {
                next_value
            };
            variants.push((variant_name, value));
            next_value = value + 1;
            if !self.eat_punct(',') {
                break;
            }
        }
        self.expect_punct('}')?;
        self.expect_punct(';')?;
        Ok(Decl::Enum(name, variants))
    }

    fn parse_typedef(&mut self) -> Result<Decl, String> {
        self.bump(); // `typedef`
        let base = self.parse_type_spec()?;
        let (name, ty) = self.parse_declarator(&base)?;
        self.expect_punct(';')?;
        Ok(Decl::Typedef(name, ty))
    }

    fn parse_decl(&mut self) -> Result<Decl, String> {
        match self.peek() {
            Some(Tok::Ident(s)) if s == "typedef" => self.parse_typedef(),
            Some(Tok::Ident(s)) if s == "struct" => {
                let (name, members) = self.parse_struct_or_union_body()?;
                Ok(Decl::Struct(name, members))
            }
            Some(Tok::Ident(s)) if s == "union" => {
                let (name, members) = self.parse_struct_or_union_body()?;
                Ok(Decl::Union(name, members))
            }
            Some(Tok::Ident(s)) if s == "enum" => self.parse_enum(),
            other => Err(format!(
                "expected typedef/struct/union/enum, found {other:?} near token {}",
                self.pos
            )),
        }
    }
}

fn resolve_builtin_combo(words: &[String]) -> Type {
    let has = |w: &str| words.iter().any(|s| s == w);
    let unsigned = has("unsigned");
    if has("void") {
        return Type::Void;
    }
    if has("bool") || has("_Bool") {
        return Type::Bool;
    }
    if has("double") {
        return Type::Float { bits: 64 };
    }
    if has("float") {
        return Type::Float { bits: 32 };
    }
    if has("char") {
        return Type::Int {
            bits: 8,
            signed: !unsigned,
        };
    }
    if has("short") {
        return Type::Int {
            bits: 16,
            signed: !unsigned,
        };
    }
    if has("long") {
        // `long` and `long long` both assumed 8 bytes (LP64) — see the
        // module doc's honest scope note.
        return Type::Int {
            bits: 64,
            signed: !unsigned,
        };
    }
    Type::Int {
        bits: 32,
        signed: !unsigned,
    }
}

/// Parse `source` (a C header, no preprocessor run over it — see the module
/// doc) into an ordered list of top-level struct/union/enum/typedef
/// declarations. `pointer_bits` resolves `size_t`/`ssize_t` while parsing.
pub fn parse_header(source: &str) -> Result<Vec<Decl>, String> {
    parse_header_for(source, 64)
}

/// [`parse_header`] with an explicit pointer width (32 or 64), for
/// resolving `size_t`/`ssize_t` correctly against a non-64-bit target.
pub fn parse_header_for(source: &str, pointer_bits: u32) -> Result<Vec<Decl>, String> {
    let toks = tokenize(source);
    let mut parser = Parser {
        toks: &toks,
        pos: 0,
        pointer_bits,
    };
    let mut decls = Vec::new();
    while parser.pos < parser.toks.len() {
        decls.push(parser.parse_decl()?);
    }
    Ok(decls)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn primitive_sizes_and_alignment() {
        let lib = TypeLibrary::new(64);
        assert_eq!(
            lib.size_align(&Type::Int {
                bits: 32,
                signed: true
            })
            .unwrap(),
            (4, 4)
        );
        assert_eq!(
            lib.size_align(&Type::Int {
                bits: 64,
                signed: false
            })
            .unwrap(),
            (8, 8)
        );
        assert_eq!(
            lib.size_align(&Type::Pointer(Box::new(Type::Void)))
                .unwrap(),
            (8, 8)
        );
        let lib32 = TypeLibrary::new(32);
        assert_eq!(
            lib32
                .size_align(&Type::Pointer(Box::new(Type::Void)))
                .unwrap(),
            (4, 4)
        );
    }

    #[test]
    fn struct_layout_inserts_padding_for_alignment() {
        let mut lib = TypeLibrary::new(64);
        // struct { char a; int b; char c; } -> a@0, pad, b@4, c@8, size 12
        lib.define_struct(
            "S",
            &[
                (
                    "a".into(),
                    Type::Int {
                        bits: 8,
                        signed: true,
                    },
                ),
                (
                    "b".into(),
                    Type::Int {
                        bits: 32,
                        signed: true,
                    },
                ),
                (
                    "c".into(),
                    Type::Int {
                        bits: 8,
                        signed: true,
                    },
                ),
            ],
        )
        .expect("define struct");
        let s = lib.get_struct("S").expect("struct exists");
        assert_eq!(s.fields[0].offset, 0);
        assert_eq!(s.fields[1].offset, 4);
        assert_eq!(s.fields[2].offset, 8);
        assert_eq!(s.size, 12);
        assert_eq!(s.align, 4);
    }

    #[test]
    fn struct_containing_a_pointer_to_itself_does_not_need_its_own_size() {
        let mut lib = TypeLibrary::new(64);
        let result = lib.define_struct(
            "Node",
            &[
                (
                    "value".into(),
                    Type::Int {
                        bits: 32,
                        signed: true,
                    },
                ),
                (
                    "next".into(),
                    Type::Pointer(Box::new(Type::Named("Node".into()))),
                ),
            ],
        );
        assert!(result.is_ok(), "{result:?}");
        let s = lib.get_struct("Node").expect("struct exists");
        assert_eq!(s.fields[1].offset, 8); // padded up to the pointer's 8-byte alignment
        assert_eq!(s.size, 16);
    }

    #[test]
    fn union_members_all_start_at_zero_and_size_is_the_widest() {
        let mut lib = TypeLibrary::new(64);
        lib.define_union(
            "U",
            &[
                (
                    "as_i32".into(),
                    Type::Int {
                        bits: 32,
                        signed: true,
                    },
                ),
                (
                    "as_i64".into(),
                    Type::Int {
                        bits: 64,
                        signed: true,
                    },
                ),
                (
                    "as_i8".into(),
                    Type::Int {
                        bits: 8,
                        signed: true,
                    },
                ),
            ],
        )
        .expect("define union");
        let u = lib.get_union("U").expect("union exists");
        assert!(u.fields.iter().all(|f| f.offset == 0));
        assert_eq!(u.size, 8);
        assert_eq!(u.align, 8);
    }

    #[test]
    fn unknown_type_reference_is_an_error_not_a_panic() {
        let mut lib = TypeLibrary::new(64);
        let err = lib
            .define_struct("Bad", &[("x".into(), Type::Named("NeverDefined".into()))])
            .expect_err("undefined type must error");
        assert!(err.contains("NeverDefined"), "{err}");
    }

    #[test]
    fn parses_a_struct_with_pointer_array_and_nested_struct_fields() {
        let source = r#"
            // A doubly-linked, tagged node.
            struct Header {
                uint32_t magic;
                uint16_t version;
            };

            struct Node {
                struct Header header;
                char name[16];
                struct Node *next;
                struct Node *prev;
                void *payload;
            };
        "#;
        let mut lib = TypeLibrary::new(64);
        let defined = lib.import_header(source).expect("import header");
        assert_eq!(defined, vec!["Header", "Node"]);

        let header = lib.get_struct("Header").expect("Header defined");
        assert_eq!(header.size, 8); // u32 + u16 + 2 padding, aligned to 4
        assert_eq!(header.fields[1].offset, 4);

        let node = lib.get_struct("Node").expect("Node defined");
        assert_eq!(node.fields[0].name, "header");
        assert_eq!(node.fields[0].offset, 0);
        assert_eq!(node.fields[1].name, "name");
        assert_eq!(node.fields[1].offset, 8); // after the 8-byte Header
        assert_eq!(
            node.fields[1].ty,
            Type::Array(
                Box::new(Type::Int {
                    bits: 8,
                    signed: true
                }),
                16
            )
        );
        assert_eq!(node.fields[2].name, "next");
        assert_eq!(node.fields[2].offset, 24); // 8 (header) + 16 (name), already 8-aligned
    }

    #[test]
    fn parses_enum_with_explicit_and_implicit_values() {
        let source = "enum Color { RED, GREEN = 5, BLUE };";
        let mut lib = TypeLibrary::new(64);
        lib.import_header(source).expect("import header");
        let e = lib.get_enum("Color").expect("Color defined");
        assert_eq!(
            e.variants,
            vec![
                ("RED".to_string(), 0),
                ("GREEN".to_string(), 5),
                ("BLUE".to_string(), 6)
            ]
        );
    }

    #[test]
    fn parses_typedef_of_a_pointer_to_a_struct() {
        let source = r#"
            struct Widget { int id; };
            typedef struct Widget *WidgetPtr;
        "#;
        let mut lib = TypeLibrary::new(64);
        lib.import_header(source).expect("import header");
        let (size, align) = lib
            .size_align(&Type::Named("WidgetPtr".into()))
            .expect("resolves");
        assert_eq!((size, align), (8, 8));
    }

    #[test]
    fn skips_preprocessor_directives_and_comments() {
        let source = r#"
            #include <stdint.h>
            #define UNUSED(x) (void)(x)
            /* a block comment
               spanning lines */
            struct S { int a; }; // trailing comment
        "#;
        let mut lib = TypeLibrary::new(64);
        let defined = lib.import_header(source).expect("import header");
        assert_eq!(defined, vec!["S"]);
    }

    #[test]
    fn multi_declarator_member_line_declares_every_field() {
        let source = "struct S { int a, b, c[3]; };";
        let mut lib = TypeLibrary::new(64);
        lib.import_header(source).expect("import header");
        let s = lib.get_struct("S").expect("S defined");
        assert_eq!(s.fields.len(), 3);
        assert_eq!(
            s.fields[2].ty,
            Type::Array(
                Box::new(Type::Int {
                    bits: 32,
                    signed: true
                }),
                3
            )
        );
    }

    #[test]
    fn unsigned_long_long_combo_resolves_to_a_64_bit_unsigned_int() {
        let source = "typedef unsigned long long QWord;";
        let mut lib = TypeLibrary::new(64);
        lib.import_header(source).expect("import header");
        assert_eq!(
            lib.size_align(&Type::Named("QWord".into())).unwrap(),
            (8, 8)
        );
    }
}
