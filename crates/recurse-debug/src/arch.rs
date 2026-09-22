//! Architecture-specific constants: breakpoint opcodes and the call test.
//!
//! Kept OS-independent — the same instruction encoding is used whether we are
//! on Linux, macOS, or Windows.

/// The bytes that replace an instruction to trap on it (a software breakpoint).
///
/// x86/x86-64 use the one-byte `int3` (`0xCC`); AArch64 uses the four-byte
/// `BRK #0`.
///
/// ```
/// assert!(!recurse_debug::arch::breakpoint_bytes().is_empty());
/// ```
pub fn breakpoint_bytes() -> &'static [u8] {
    #[cfg(target_arch = "x86_64")]
    {
        &[0xCC]
    }
    #[cfg(target_arch = "x86")]
    {
        &[0xCC]
    }
    #[cfg(target_arch = "aarch64")]
    {
        // BRK #0, little-endian.
        &[0x00, 0x00, 0x20, 0xD4]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        &[0xCC]
    }
}

/// The address a breakpoint was hit at, given the pc after the trap.
///
/// x86 leaves `pc` one byte past the `int3`; AArch64 leaves `pc` on the `BRK`.
///
/// ```
/// use recurse_debug::arch::breakpoint_hit_addr;
/// #[cfg(target_arch = "x86_64")]
/// assert_eq!(breakpoint_hit_addr(0x401001), 0x401000);
/// ```
pub fn breakpoint_hit_addr(pc: u64) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        pc.wrapping_sub(1)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        pc
    }
}

/// True when the instruction at `bytes` is a direct or indirect call.
///
/// Used by step-over: a call is run to completion (a temporary breakpoint at the
/// return address), while anything else is a plain single-step. Unknown
/// encodings conservatively return `false`.
///
/// ```
/// use recurse_debug::arch::is_call;
/// // On x86-64, `e8 xx xx xx xx` is `call rel32`.
/// #[cfg(target_arch = "x86_64")]
/// assert!(is_call(&[0xe8, 0x00, 0x00, 0x00, 0x00]));
/// // An unknown/empty buffer is never a call.
/// assert!(!is_call(&[]));
/// ```
pub fn is_call(bytes: &[u8]) -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        match bytes.first() {
            // call rel32
            Some(0xE8) => true,
            // call r/m (0xFF /2 or /3): ModRM.reg == 2 or 3.
            Some(0xFF) => matches!(bytes.get(1), Some(m) if (m >> 3) & 0b111 >= 2),
            _ => false,
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let word = u32::from_le_bytes([
            *bytes.first().unwrap_or(&0u8),
            *bytes.get(1).unwrap_or(&0u8),
            *bytes.get(2).unwrap_or(&0u8),
            *bytes.get(3).unwrap_or(&0u8),
        ]);
        // BL: 100101 imm26; BLR: 1101011000111111000000 Rn 00000.
        (word & 0xFC00_0000) == 0x9400_0000 || (word & 0xFFFF_FC1F) == 0xD63F_0000
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        let _ = bytes;
        false
    }
}
