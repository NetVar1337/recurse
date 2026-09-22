//! Canonical register identity for dataflow analysis.
//!
//! x86's sub-registers (`eax`/`ax`/`al`/`ah` are all part of `rax`) mean a
//! write to one and a read of another can be the *same* physical storage.
//! Everywhere else in this crate a register is just the name the
//! disassembler printed, because reproducing that text is all lifting needs
//! — but treating `eax` and `rax` as unrelated identities would make
//! whole-routine liveness ([`crate::liveness`]) *unsound*: a write to `eax`
//! could look dead just because the next read of the same storage happens to
//! be spelled `rax`. [`canonical`] maps every named x86-64 GPR to its 64-bit
//! root; every other register name (`xmm0`, ARM's `w0`, a lifter-introduced
//! [`crate::il::Register::Temp`], …) maps to itself, so this stays a safe
//! over-approximation — never wrong, occasionally coarser than the exact
//! hardware model (e.g. `ah` and `al` are independent byte lanes of the same
//! 16 bits, not the same byte) — rather than requiring a model per
//! architecture.
//!
//! This canonicalization is used **only** by liveness/dead-code elimination,
//! which only needs "could this storage still be observed" and is safe to
//! over-approximate in the direction of "assume it's needed". Constant/copy
//! propagation ([`crate::opt::propagate_and_fold`]) never uses it — folding
//! a 32-bit register's known value into a 16-bit read of the same family is
//! not generally correct (the low bits alias, the rest doesn't), so
//! propagation stays keyed on the exact operand name it was written with.

use crate::il::Register;

/// The canonical identity `reg` should be tracked under for liveness.
pub fn canonical(reg: &Register) -> Register {
    match reg {
        Register::Physical(name) => Register::Physical(canonical_name(name).to_string()),
        Register::Temp(n) => Register::Temp(*n),
    }
}

fn canonical_name(name: &str) -> &str {
    match name {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn sub_registers_share_a_canonical_identity() {
        let rax = canonical(&Register::Physical("rax".into()));
        assert_eq!(canonical(&Register::Physical("eax".into())), rax);
        assert_eq!(canonical(&Register::Physical("ax".into())), rax);
        assert_eq!(canonical(&Register::Physical("al".into())), rax);
        assert_eq!(canonical(&Register::Physical("ah".into())), rax);
        assert_ne!(canonical(&Register::Physical("rbx".into())), rax);
    }

    #[test]
    fn extended_registers_alias_correctly() {
        let r8 = canonical(&Register::Physical("r8".into()));
        assert_eq!(canonical(&Register::Physical("r8d".into())), r8);
        assert_eq!(canonical(&Register::Physical("r8w".into())), r8);
        assert_eq!(canonical(&Register::Physical("r8b".into())), r8);
    }

    #[test]
    fn unrecognised_and_temp_registers_map_to_themselves() {
        assert_eq!(
            canonical(&Register::Physical("xmm0".into())),
            Register::Physical("xmm0".into())
        );
        assert_eq!(canonical(&Register::Temp(3)), Register::Temp(3));
    }
}
