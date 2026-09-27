//! Architecture detection and disassembly, shared by every consumer.
//!
//! One place configures Capstone (BSD-3) for the target architecture, so the
//! static engine and the debugger decode identically. Anything that needs to
//! turn bytes into instructions goes through [`Arch`].

use std::path::Path;

use capstone::prelude::*;
use capstone::Endian;
use object::{Architecture, Object, ObjectSymbol, SymbolKind};

/// The target's architecture, as needed to decode its machine code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arch {
    /// Object-file architecture.
    pub architecture: Architecture,
    /// Byte order.
    pub little_endian: bool,
    /// ARM Thumb mode.
    pub thumb: bool,
}

/// One decoded instruction, from raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawInsn {
    /// Address the instruction was decoded at.
    pub addr: u64,
    /// Instruction bytes.
    pub bytes: Vec<u8>,
    /// Disassembly text (mnemonic + operands).
    pub text: String,
}

/// Fewest characters an immediate must spell before it is shown.
///
/// Below three, an immediate is far more often arithmetic than a word, and
/// showing `; 20` for a length or an index is noise rather than a label.
const INLINE_TEXT_MIN: usize = 3;

/// The text a bare hexadecimal immediate spells, when that text is printable.
///
/// A string constant compiled into the instruction stream is carried as an
/// immediate, one instruction per chunk, so the operand reads as noise until it
/// is decoded in the target's own byte order:
///
/// ```
/// use recurse_static::arch::inline_text;
/// // Little-endian: 0x3a465443 is the bytes 43 54 46 3a.
/// assert_eq!(inline_text("push 0x3a465443", true).as_deref(), Some("CTF:"));
/// assert_eq!(inline_text("push 0x20656874", true).as_deref(), Some("the "));
/// // Big-endian reads the same bytes the other way round.
/// assert_eq!(inline_text("push 0x43463a54", false).as_deref(), Some("CF:T"));
/// ```
///
/// Only a *bare* immediate qualifies. A value inside brackets is a memory
/// address rather than embedded text, so it is never decoded:
///
/// ```
/// # use recurse_static::arch::inline_text;
/// assert_eq!(inline_text("mov eax, [0x41424344]", true), None);
/// assert_eq!(inline_text("push 0x48", true), None);          // one character
/// assert_eq!(inline_text("push 0x20202020", true), None);     // all blanks
/// assert_eq!(inline_text("push 0x0", true), None);           // no bytes
/// assert_eq!(inline_text("call 0x8048090", true), None);      // not printable
/// ```
pub fn inline_text(operands: &str, little_endian: bool) -> Option<String> {
    // Only the operands: the mnemonic is never a value.
    let operands = operands.split_once(' ').map_or("", |(_, rest)| rest);
    // Drop every bracketed group, which holds addresses rather than text.
    let mut bare = operands;
    while let Some(open) = bare.find('[') {
        match bare[open..].find(']') {
            Some(close) => bare = &bare[open + close + 1..],
            None => {
                bare = &bare[..open];
                break;
            }
        }
    }
    bare.split(|c: char| !c.is_ascii_alphanumeric())
        .filter_map(|token| token.strip_prefix("0x"))
        .filter_map(|hex| u64::from_str_radix(hex, 16).ok())
        .find_map(|value| spelled_text(value, little_endian))
}

/// The characters `value` spells in `little_endian` order, if they are text.
///
/// Zero bytes are padding, and they sit at opposite ends depending on byte
/// order — high-order on a little-endian target, low-order on a big-endian one —
/// so both ends are trimmed. That also covers a null-terminated string, whose
/// terminator would otherwise sit in the middle of the candidate and fail the
/// printable test.
fn spelled_text(value: u64, little_endian: bool) -> Option<String> {
    let ordered = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    let start = ordered.iter().position(|b| *b != 0);
    let start = start.unwrap_or(ordered.len());
    let end = ordered
        .iter()
        .rposition(|b| *b != 0)
        .map_or(start, |i| i + 1);
    let significant = &ordered[start..end];
    if significant.len() < INLINE_TEXT_MIN {
        return None;
    }
    // Printable ASCII only. Control characters are excluded on purpose: the
    // comment shares a line with the instruction, so an embedded newline or
    // escape would break the layout of every view that renders it.
    if !significant.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return None;
    }
    // A run of blanks is padding, not a word.
    if significant.iter().all(|b| *b == b' ') {
        return None;
    }
    Some(String::from_utf8_lossy(significant).into_owned())
}

impl Arch {
    /// Detect the architecture from an already-parsed object file.
    pub fn from_file(file: &object::File<'_>) -> Self {
        Self {
            architecture: file.architecture(),
            little_endian: file.is_little_endian(),
            thumb: is_thumb(file),
        }
    }

    /// Detect the architecture by parsing the binary at `path`.
    ///
    /// ```
    /// use recurse_static::arch::Arch;
    /// let exe = std::env::current_exe().unwrap();
    /// assert!(Arch::detect(&exe).is_some());
    /// ```
    pub fn detect(path: &Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        let file = object::File::parse(&*data).ok()?;
        Some(Self::from_file(&file))
    }

    /// Friendly architecture name (matching the engine's `info`).
    pub fn name(&self) -> &'static str {
        match self.architecture {
            Architecture::X86_64 | Architecture::X86_64_X32 | Architecture::I386 => "x86",
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 | Architecture::Arm => "arm",
            Architecture::Mips | Architecture::Mips64 | Architecture::Mips64_N32 => "mips",
            Architecture::PowerPc | Architecture::PowerPc64 => "ppc",
            Architecture::Riscv32 | Architecture::Riscv64 => "riscv",
            Architecture::Sparc | Architecture::Sparc32Plus | Architecture::Sparc64 => "sparc",
            Architecture::S390x => "s390",
            Architecture::M68k => "m68k",
            Architecture::Bpf => "bpf",
            Architecture::Avr => "avr",
            Architecture::Wasm32 | Architecture::Wasm64 => "wasm",
            _ => "unknown",
        }
    }

    /// Build a Capstone disassembler for this architecture.
    ///
    /// # Errors
    /// A message when the architecture has no Capstone backend.
    pub fn capstone(&self) -> Result<Capstone, String> {
        let endian = if self.little_endian {
            Endian::Little
        } else {
            Endian::Big
        };
        let built = match self.architecture {
            Architecture::X86_64 | Architecture::X86_64_X32 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build(),
            Architecture::I386 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .detail(true)
                .build(),
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::Arm => Capstone::new()
                .arm()
                .mode(if self.thumb {
                    arch::arm::ArchMode::Thumb
                } else {
                    arch::arm::ArchMode::Arm
                })
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::Mips => Capstone::new()
                .mips()
                .mode(arch::mips::ArchMode::Mips32)
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::Mips64 | Architecture::Mips64_N32 => Capstone::new()
                .mips()
                .mode(arch::mips::ArchMode::Mips64)
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::PowerPc => Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode32)
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::PowerPc64 => Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode64)
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::Riscv32 => Capstone::new()
                .riscv()
                .mode(arch::riscv::ArchMode::RiscV32)
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::Riscv64 => Capstone::new()
                .riscv()
                .mode(arch::riscv::ArchMode::RiscV64)
                .endian(endian)
                .detail(true)
                .build(),
            Architecture::Sparc | Architecture::Sparc32Plus => Capstone::new()
                .sparc()
                .mode(arch::sparc::ArchMode::Default)
                .detail(true)
                .build(),
            Architecture::Sparc64 => Capstone::new()
                .sparc()
                .mode(arch::sparc::ArchMode::V9)
                .detail(true)
                .build(),
            Architecture::S390x => Capstone::new()
                .sysz()
                .mode(arch::sysz::ArchMode::Default)
                .detail(true)
                .build(),
            Architecture::M68k => Capstone::new().m68k().detail(true).build(),
            other => return Err(format!("no disassembler for {other:?}")),
        };
        built.map_err(|e| e.to_string())
    }
}

/// Decode at most `max` instructions from `bytes` located at `addr`.
///
/// # Errors
/// A message when the architecture has no backend or the bytes fail to decode.
///
/// ```
/// use recurse_static::arch::{disasm, Arch};
/// # let exe = std::env::current_exe().unwrap();
/// # let arch = Arch::detect(&exe).unwrap();
/// # if arch.name() == "x86" {
/// let insns = disasm(arch, &[0x90, 0x90], 0x1000, 2).unwrap();
/// assert_eq!(insns.len(), 2);
/// # }
/// ```
pub fn disasm(arch: Arch, bytes: &[u8], addr: u64, max: usize) -> Result<Vec<RawInsn>, String> {
    let cs = arch.capstone()?;
    let decoded = cs
        .disasm_all(bytes, addr)
        .map_err(|e| format!("disassemble: {e}"))?;
    Ok(decoded
        .iter()
        .take(max)
        .map(|insn| {
            let text = format!(
                "{} {}",
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or("")
            )
            .trim()
            .to_string();
            RawInsn {
                addr: insn.address(),
                bytes: insn.bytes().to_vec(),
                text: match inline_text(&text, arch.little_endian) {
                    Some(spelled) => format!("{text} ; '{spelled}'"),
                    None => text,
                },
            }
        })
        .collect())
}

/// True when the object uses the ARM Thumb instruction set.
fn is_thumb(file: &object::File<'_>) -> bool {
    if file.entry() & 1 == 1 {
        return true;
    }
    file.symbols().chain(file.dynamic_symbols()).any(|s| {
        if let Ok(name) = s.name() {
            if name.starts_with("$t") {
                return true;
            }
        }
        s.kind() == SymbolKind::Text && s.address() & 1 == 1
    })
}

impl Arch {
    /// DWARF register number for a register name, for unwinding.
    ///
    /// ```
    /// use recurse_static::arch::Arch;
    /// let exe = std::env::current_exe().unwrap();
    /// let arch = Arch::detect(&exe).unwrap();
    /// assert!(arch.dwarf_register("rsp").is_some() || arch.dwarf_register("sp").is_some());
    /// ```
    pub fn dwarf_register(&self, name: &str) -> Option<u16> {
        match self.architecture {
            Architecture::X86_64 | Architecture::X86_64_X32 => Some(match name {
                "rax" => 0,
                "rdx" => 1,
                "rcx" => 2,
                "rbx" => 3,
                "rsi" => 4,
                "rdi" => 5,
                "rbp" => 6,
                "rsp" => 7,
                "r8" => 8,
                "r9" => 9,
                "r10" => 10,
                "r11" => 11,
                "r12" => 12,
                "r13" => 13,
                "r14" => 14,
                "r15" => 15,
                "rip" => 16,
                _ => return None,
            }),
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => {
                if let Some(n) = name.strip_prefix('x').and_then(|s| s.parse::<u16>().ok()) {
                    if n <= 30 {
                        return Some(n);
                    }
                }
                match name {
                    "sp" => Some(31),
                    "pc" => Some(32),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// DWARF register number of the stack pointer.
    pub fn stack_pointer(&self) -> u16 {
        match self.architecture {
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => 31,
            _ => 7,
        }
    }

    /// DWARF register number of the program counter.
    pub fn pc_register(&self) -> u16 {
        match self.architecture {
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => 32,
            _ => 16,
        }
    }

    /// DWARF numbers of the callee-saved registers; a backtrace restores these
    /// at each step so the next frame's CFI can be evaluated.
    pub fn callee_saved(&self) -> &'static [u16] {
        match self.architecture {
            // rbx, rbp, r12..r15 (x86-64).
            Architecture::X86_64 | Architecture::X86_64_X32 => &[3, 6, 12, 13, 14, 15],
            // x19..x28, x29 (fp), x30 (lr).
            Architecture::Aarch64 | Architecture::Aarch64_Ilp32 => {
                &[19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30]
            }
            _ => &[],
        }
    }
}

#[cfg(test)]
mod inline_text_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::inline_text;

    /// `disasm` itself must carry the comment, so every consumer of a decoded
    /// instruction — the live debugger view included — gets it without having to
    /// annotate for itself.
    #[test]
    fn disasm_annotates_the_text_it_decodes() {
        use super::{disasm, Arch};
        use object::Architecture;

        let arch = Arch {
            architecture: Architecture::I386,
            little_endian: true,
            thumb: false,
        };
        // `push $0x3a465443`
        let insns = disasm(arch, &[0x68, 0x43, 0x54, 0x46, 0x3a], 0x1000, 1).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].text, "push 0x3a465443 ; 'CTF:'");

        // An instruction with nothing to spell is left exactly as decoded.
        let nop = disasm(arch, &[0x90], 0x1000, 1).unwrap();
        assert_eq!(nop[0].text, "nop");
    }

    #[test]
    fn spells_each_pushed_chunk() {
        // "Let's start the CTF:" laid down four bytes at a time, low byte first.
        for (imm, want) in [
            ("push 0x3a465443", "CTF:"),
            ("push 0x20656874", "the "),
            ("push 0x20747261", "art "),
            ("push 0x2774654c", "Let'"),
        ] {
            assert_eq!(inline_text(imm, true).as_deref(), Some(want), "{imm}");
        }
    }

    #[test]
    fn reads_big_endian_bytes_the_other_way_round() {
        assert_eq!(
            inline_text("push 0x43463a54", false).as_deref(),
            Some("CF:T")
        );
        // The same bytes, little-endian, are a different word.
        assert_eq!(
            inline_text("push 0x43463a54", true).as_deref(),
            Some("T:FC")
        );
    }

    #[test]
    fn drops_padding_zero_bytes() {
        // A 3-character string in a 4-byte immediate keeps its own length.
        assert_eq!(inline_text("push 0x00434241", true).as_deref(), Some("ABC"));
        // Big-endian pads on the other side.
        assert_eq!(
            inline_text("push 0x41424300", false).as_deref(),
            Some("ABC")
        );
    }

    #[test]
    fn ignores_a_bare_address_in_brackets() {
        assert_eq!(inline_text("mov eax, [0x41424344]", true), None);
        assert_eq!(inline_text("lea edi, [rip + 0x41424344]", true), None);
    }

    #[test]
    fn reads_a_bare_operand_next_to_a_bracketed_one() {
        // The address is skipped, the immediate next to it is still read.
        assert_eq!(
            inline_text("mov dword [rbp - 4], 0x3a465443", true).as_deref(),
            Some("CTF:")
        );
    }

    #[test]
    fn rejects_values_that_are_not_text() {
        for text in [
            "push 0x0",
            "push 0x48",
            "push 0x4142",
            "push 0x20202020",
            "push 0xffffffff",
            "push 0x00ff00ff",
            "nop",
            "ret",
            "",
        ] {
            assert_eq!(inline_text(text, true), None, "{text}");
        }
    }

    #[test]
    fn rejects_a_control_character_anywhere_in_the_value() {
        // 0x41420a41 is the bytes 41 0a 42 41: a newline in the middle. The
        // comment shares a line with the instruction, so this is never shown.
        assert_eq!(inline_text("push 0x41420a41", true), None);
        // A tab is a control character too, despite looking like whitespace.
        assert_eq!(inline_text("push 0x41420941", true), None);
    }

    #[test]
    fn keeps_spaces_inside_a_word() {
        // Spaces are printable, so a phrase is shown whole: "the ".
        assert_eq!(
            inline_text("push 0x20656874", true).as_deref(),
            Some("the ")
        );
    }

    #[test]
    fn trims_a_null_terminator() {
        // "ABC" then a terminator, in each byte order.
        assert_eq!(inline_text("push 0x00434241", true).as_deref(), Some("ABC"));
        assert_eq!(
            inline_text("push 0x41424300", false).as_deref(),
            Some("ABC")
        );
    }
}
