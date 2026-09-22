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
        .map(|insn| RawInsn {
            addr: insn.address(),
            bytes: insn.bytes().to_vec(),
            text: format!(
                "{} {}",
                insn.mnemonic().unwrap_or(""),
                insn.op_str().unwrap_or("")
            )
            .trim()
            .to_string(),
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
