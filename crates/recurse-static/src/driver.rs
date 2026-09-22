//! Windows kernel driver analysis: recover the IOCTL codes a driver's
//! `IRP_MJ_DEVICE_CONTROL` dispatch routine handles (the first step of
//! any driver vulnerability hunt — every "arbitrary read/write via a
//! signed driver" finding starts here), and check a driver's hash
//! against a caller-supplied known-driver list in the same shape the
//! [LOLDrivers](https://www.loldrivers.io/) project publishes.
//!
//! # IOCTL recovery
//!
//! [`recover_ioctl_handlers`] scans a function's disassembly (any
//! `&[Instruction]`, the same shape `Engine::function_disasm`/
//! `Engine::disassemble` already return) for the classic dispatch shape:
//! a `cmp <reg-or-mem>, <immediate>` comparing the IRP's `IoControlCode`
//! field against a candidate IOCTL code, followed within a small window
//! by a conditional branch to that code's handler. This is real,
//! lightweight *textual* pattern matching over already-disassembled
//! instructions — see honest scope below for what it deliberately does
//! not attempt.
//!
//! [`IoctlCode::decode`] breaks a raw 32-bit code down using the real,
//! documented Windows `CTL_CODE` bitfield layout (device type / function
//! / transfer method / required access) — definitional Windows ABI
//! knowledge, the same honesty class as `crate::capa`'s Win32 API rules:
//! not an empirical claim needing a curated corpus, a documented fact
//! about how `CTL_CODE` packs its four fields. `TransferMethod::Neither`
//! in particular is worth an analyst's attention on sight: it hands the
//! driver raw, unvalidated user-mode pointers directly, the shape behind
//! most "arbitrary kernel read/write" driver vulnerabilities.
//!
//! # LOLDrivers-style known-driver lookup
//!
//! [`check_known_driver`] matches a driver's SHA-256 against a
//! caller-supplied [`KnownDriver`] list — the same shape (hash, name,
//! category/verdict) the community LOLDrivers project publishes for
//! known-vulnerable and known-malicious signed drivers. **No such list
//! ships here**: like `crate::sig`'s explicit refusal to ship a
//! fabricated "real-world" signature database, curating and keeping a
//! hash list like this current is a data-maintenance project of its own,
//! not something to hardcode as a handful of entries and call complete.
//! A caller feeds in a real, currently-maintained list (e.g. LOLDrivers'
//! own published JSON, converted to [`KnownDriver`]s) — this module
//! provides the real matching mechanism, honestly, with nothing behind
//! it invented.

use sha2::{Digest, Sha256};

use crate::engine::Instruction;

/// The four fields Windows' `CTL_CODE` macro packs into a 32-bit IOCTL
/// code: `(DeviceType << 16) | (Access << 14) | (Function << 2) | Method`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoctlCode {
    pub raw: u32,
    pub device_type: u16,
    pub function: u16,
    pub method: TransferMethod,
    pub access: RequiredAccess,
}

/// `METHOD_*` — how the I/O manager delivers the request's input/output
/// buffers to the driver. `Neither` is the one worth flagging: the
/// driver receives the raw user-mode virtual addresses directly, with no
/// I/O manager validation/copy at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferMethod {
    Buffered,
    InDirect,
    OutDirect,
    Neither,
}

/// `FILE_*_ACCESS` — the access rights a caller needs to issue this
/// IOCTL, as encoded in the code itself (not a guarantee the driver
/// actually enforces it — that's a separate, real thing to check).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredAccess {
    Any,
    Read,
    Write,
    ReadWrite,
}

impl IoctlCode {
    /// Decode `raw` per the documented `CTL_CODE` bit layout.
    #[must_use]
    pub fn decode(raw: u32) -> Self {
        let device_type = (raw >> 16) as u16;
        let access_bits = (raw >> 14) & 0b11;
        let function = ((raw >> 2) & 0xFFF) as u16;
        let method_bits = raw & 0b11;
        let method = match method_bits {
            0 => TransferMethod::Buffered,
            1 => TransferMethod::InDirect,
            2 => TransferMethod::OutDirect,
            _ => TransferMethod::Neither,
        };
        let access = match access_bits {
            0 => RequiredAccess::Any,
            1 => RequiredAccess::Read,
            2 => RequiredAccess::Write,
            _ => RequiredAccess::ReadWrite,
        };
        Self {
            raw,
            device_type,
            function,
            method,
            access,
        }
    }
}

/// One recovered `cmp`-against-immediate dispatch site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoctlHandler {
    pub code: IoctlCode,
    /// Address of the `cmp` instruction that compares against
    /// [`IoctlCode::raw`].
    pub compare_addr: u64,
    /// The conditional branch's taken-edge target, when the disassembly
    /// exposes one — the candidate handler's entry point.
    pub handler_addr: Option<u64>,
}

/// How many instructions after a `cmp` this scan looks for the
/// conditional branch it feeds — real dispatch code almost always
/// branches within one or two instructions (`cmp`; `jz`/`je`), a wider
/// window just tolerates an intervening no-op-ish instruction a compiler
/// occasionally emits.
const BRANCH_WINDOW: usize = 3;

/// Scan `instructions` (a function's disassembly, in address order) for
/// candidate IOCTL dispatch comparisons.
///
/// # Honest scope
///
/// This is textual pattern matching over `Instruction::disasm`, not a
/// dataflow proof that the compared register/memory actually holds
/// `IoControlCode` — a driver comparing some *other* field for an
/// unrelated reason produces a false positive here, and a jump-table or
/// binary-search dispatch (`switch` compiled as an indexed jump rather
/// than a `cmp` chain) produces false negatives. Both are real,
/// documented limits of a fast, disassembler-agnostic first pass; the
/// resulting candidate list is exactly that — candidates for an analyst
/// (or a follow-up dataflow pass) to confirm, the same "over-approximate,
/// don't claim precision this pass doesn't have" honesty
/// `crate::taint`/`crate::sig` already establish.
#[must_use]
pub fn recover_ioctl_handlers(instructions: &[Instruction]) -> Vec<IoctlHandler> {
    let mut handlers = Vec::new();
    for (i, insn) in instructions.iter().enumerate() {
        let Some(imm) = parse_cmp_immediate(&insn.disasm) else {
            continue;
        };
        let branch = instructions[i + 1..(i + 1 + BRANCH_WINDOW).min(instructions.len())]
            .iter()
            .find(|candidate| is_conditional_branch(&candidate.disasm));
        handlers.push(IoctlHandler {
            code: IoctlCode::decode(imm),
            compare_addr: insn.addr,
            handler_addr: branch.and_then(|b| b.jump),
        });
    }
    handlers
}

/// Parse `"cmp <anything>, <imm>"` (`disasm` text, case-insensitive
/// mnemonic) into the immediate operand, when the whole instruction
/// really is a compare-against-immediate — a compare against another
/// register (`cmp eax, ebx`) is not a candidate and correctly parses to
/// `None`.
fn parse_cmp_immediate(disasm: &str) -> Option<u32> {
    let trimmed = disasm.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("cmp ") {
        return None;
    }
    let operand = trimmed.rsplit(',').next()?.trim();
    parse_immediate(operand)
}

fn parse_immediate(text: &str) -> Option<u32> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if !text.is_empty() && text.chars().all(|c| c.is_ascii_digit()) {
        text.parse().ok()
    } else {
        None
    }
}

/// True for a conditional jump mnemonic (`je`, `jne`, `jz`, `ja`, …) —
/// deliberately excludes plain `jmp` (unconditional; never the "is this
/// the IOCTL I expect" comparison's own branch) and `jmp`-prefixed
/// mnemonics like `jmpq` some disassemblers emit for a plain jump.
fn is_conditional_branch(disasm: &str) -> bool {
    let mnemonic = disasm.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    mnemonic.starts_with('j') && mnemonic != "jmp" && !mnemonic.starts_with("jmp")
}

/// One entry from a LOLDrivers-style known-driver list: a SHA-256 hash,
/// the driver's name, and a caller-defined category/verdict string
/// (e.g. `"vulnerable"`, `"malicious"` — this module does not define or
/// constrain the taxonomy, since it does not ship any real entries; see
/// module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownDriver {
    pub sha256: String,
    pub name: String,
    pub category: String,
}

/// SHA-256 of `bytes`, lowercase hex — the same hash form LOLDrivers'
/// own published data uses, so a caller can hash a driver file and match
/// it against their own imported list with [`check_known_driver`]
/// directly.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Look up `sha256` (lowercase hex, as produced by [`sha256_hex`])
/// against `known`. Case-insensitive on the input hash, since hash
/// strings in the wild show up in either case.
#[must_use]
pub fn check_known_driver<'a>(sha256: &str, known: &'a [KnownDriver]) -> Option<&'a KnownDriver> {
    let needle = sha256.to_ascii_lowercase();
    known
        .iter()
        .find(|d| d.sha256.to_ascii_lowercase() == needle)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn insn(addr: u64, disasm: &str, jump: Option<u64>) -> Instruction {
        Instruction {
            addr,
            disasm: disasm.to_string(),
            bytes: None,
            kind: None,
            jump,
            fail: None,
            len: 4,
        }
    }

    #[test]
    fn ctl_code_decodes_the_documented_bit_layout() {
        // IOCTL_STORAGE_QUERY_PROPERTY = CTL_CODE(FILE_DEVICE_MASS_STORAGE=0x2d,
        // 0x500, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0) = 0x2d1400.
        let code = IoctlCode::decode(0x002D_1400);
        assert_eq!(code.device_type, 0x2d);
        assert_eq!(code.function, 0x500);
        assert_eq!(code.method, TransferMethod::Buffered);
        assert_eq!(code.access, RequiredAccess::Any);
    }

    #[test]
    fn ctl_code_decodes_method_neither_the_dangerous_one() {
        // Any code ending in binary 11 is METHOD_NEITHER.
        let code = IoctlCode::decode(0x0022_2003);
        assert_eq!(code.method, TransferMethod::Neither);
    }

    #[test]
    fn recovers_a_simple_cmp_then_branch_dispatch_site() {
        let instructions = vec![
            insn(0x1000, "mov eax, dword [rcx+0x18]", None),
            insn(0x1004, "cmp eax, 0x222000", None),
            insn(0x1008, "je 0x2000", Some(0x2000)),
            insn(0x100A, "cmp eax, 0x222004", None),
            insn(0x1010, "je 0x2100", Some(0x2100)),
        ];
        let handlers = recover_ioctl_handlers(&instructions);
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0].code.raw, 0x222000);
        assert_eq!(handlers[0].compare_addr, 0x1004);
        assert_eq!(handlers[0].handler_addr, Some(0x2000));
        assert_eq!(handlers[1].code.raw, 0x222004);
        assert_eq!(handlers[1].handler_addr, Some(0x2100));
    }

    #[test]
    fn a_cmp_between_two_registers_is_not_a_candidate() {
        let instructions = vec![
            insn(0x1000, "cmp eax, ebx", None),
            insn(0x1004, "je 0x2000", Some(0x2000)),
        ];
        assert!(recover_ioctl_handlers(&instructions).is_empty());
    }

    #[test]
    fn a_cmp_with_no_branch_within_the_window_yields_no_handler_addr_but_still_a_candidate() {
        let instructions = vec![
            insn(0x1000, "cmp eax, 0x222000", None),
            insn(0x1004, "mov ebx, 1", None),
            insn(0x1008, "mov ecx, 2", None),
            insn(0x100C, "mov edx, 3", None),
            insn(0x1010, "je 0x2000", Some(0x2000)), // outside the 3-instruction window
        ];
        let handlers = recover_ioctl_handlers(&instructions);
        assert_eq!(handlers.len(), 1);
        assert_eq!(
            handlers[0].handler_addr, None,
            "the branch is too far away to associate confidently"
        );
    }

    #[test]
    fn an_unconditional_jmp_does_not_count_as_the_dispatch_branch() {
        let instructions = vec![
            insn(0x1000, "cmp eax, 0x222000", None),
            insn(0x1004, "jmp 0x9999", Some(0x9999)),
        ];
        let handlers = recover_ioctl_handlers(&instructions);
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].handler_addr, None);
    }

    #[test]
    fn hex_and_decimal_immediates_both_parse() {
        assert_eq!(parse_immediate("0x222000"), Some(0x222000));
        assert_eq!(parse_immediate("2244608"), Some(2_244_608));
        assert_eq!(parse_immediate("not_a_number"), None);
    }

    #[test]
    fn sha256_hex_matches_a_known_test_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
        assert_eq!(
            sha256_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn check_known_driver_matches_case_insensitively_and_misses_cleanly() {
        let known = vec![KnownDriver {
            sha256: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855".to_string(),
            name: "empty.sys".to_string(),
            category: "test".to_string(),
        }];
        let hash = sha256_hex(&[]);
        let hit = check_known_driver(&hash, &known).expect("must match despite case difference");
        assert_eq!(hit.name, "empty.sys");
        assert!(check_known_driver(
            "0000000000000000000000000000000000000000000000000000000000000000",
            &known
        )
        .is_none());
    }
}
