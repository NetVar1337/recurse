//! CFI-based stack unwinding from `.eh_frame`.
//!
//! A frame-pointer walk is only correct for code that keeps a frame pointer;
//! optimized binaries don't. This evaluates the binary's own DWARF call-frame
//! information instead, so a backtrace is right on `-O2` output too.
//!
//! The unwinder is driven by the caller, because reading the debuggee's
//! registers and memory happens in the debugger.

use std::path::Path;

use gimli::{
    BaseAddresses, CfaRule, EhFrame, Register, RegisterRule, RunTimeEndian, UnwindContext,
    UnwindSection,
};
use object::{Object, ObjectSection};

/// A CFI unwinder over a binary's `.eh_frame`.
pub struct Unwinder {
    data: Vec<u8>,
    address: u64,
    endian: RunTimeEndian,
    address_size: u8,
}

/// One unwound frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwoundFrame {
    /// The caller's return address.
    pub return_address: u64,
    /// The caller's CFA (its stack pointer at entry).
    pub cfa: u64,
    /// The caller's callee-saved registers the CFI recovers, by DWARF number.
    pub restored: Vec<(u16, u64)>,
}

impl Unwinder {
    /// Load `.eh_frame` from the object at `path`, or `None` when absent.
    ///
    /// ```
    /// use recurse_static::unwind::Unwinder;
    /// let exe = std::env::current_exe().unwrap();
    /// let _ = Unwinder::from_path(&exe);
    /// ```
    pub fn from_path(path: &Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        let file = object::File::parse(&*data).ok()?;
        let section = file
            .section_by_name(".eh_frame")
            .or_else(|| file.section_by_name("__eh_frame"))?;
        let bytes = section.data().ok()?;
        Some(Self {
            data: bytes.to_vec(),
            address: section.address(),
            endian: if file.is_little_endian() {
                RunTimeEndian::Little
            } else {
                RunTimeEndian::Big
            },
            address_size: if file.is_64() { 8 } else { 4 },
        })
    }

    /// Unwind one frame.
    ///
    /// `callee_saved` lists the DWARF numbers to recover for the caller.
    /// `get_reg` returns a register value by DWARF number and `read_word` reads
    /// a pointer from the debuggee. Returns `None` when no FDE covers `pc` or
    /// the rule is one we cannot evaluate (an expression), so the caller can
    /// fall back.
    pub fn unwind(
        &self,
        pc: u64,
        callee_saved: &[u16],
        get_reg: &dyn Fn(u16) -> Option<u64>,
        read_word: &mut dyn FnMut(u64) -> Option<u64>,
    ) -> Option<UnwoundFrame> {
        let mut eh_frame = EhFrame::new(&self.data, self.endian);
        eh_frame.set_address_size(self.address_size);
        let bases = BaseAddresses::default().set_eh_frame(self.address);
        let get_cie = |section: &EhFrame<_>, bases: &BaseAddresses, offset| {
            section.cie_from_offset(bases, offset)
        };

        let fde = eh_frame.fde_for_address(&bases, pc, get_cie).ok()?;
        let ra_register = fde.cie().return_address_register();

        let mut ctx = UnwindContext::new();
        let row = eh_frame
            .unwind_info_for_address(&bases, &mut ctx, pc, get_cie)
            .ok()?;

        // The CFA: the caller's stack pointer at the call.
        let cfa = match row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => {
                (get_reg(register.0)? as i64).wrapping_add(*offset) as u64
            }
            CfaRule::Expression(_) => return None,
        };

        let return_address =
            eval_rule(row.register(ra_register), pc, cfa, get_reg, &mut *read_word)?;

        let mut restored = Vec::new();
        for &dwarf in callee_saved {
            if let Some(value) = eval_rule(
                row.register(Register(dwarf)),
                pc,
                cfa,
                get_reg,
                &mut *read_word,
            ) {
                restored.push((dwarf, value));
            }
        }

        Some(UnwoundFrame {
            return_address,
            cfa,
            restored,
        })
    }
}

/// Evaluate a register rule to a value.
fn eval_rule(
    rule: RegisterRule<usize>,
    pc: u64,
    cfa: u64,
    get_reg: &dyn Fn(u16) -> Option<u64>,
    read_word: &mut dyn FnMut(u64) -> Option<u64>,
) -> Option<u64> {
    match rule {
        RegisterRule::Undefined => None,
        RegisterRule::SameValue => Some(pc),
        RegisterRule::Offset(off) => read_word((cfa as i64).wrapping_add(off) as u64),
        RegisterRule::ValOffset(off) => Some((cfa as i64).wrapping_add(off) as u64),
        RegisterRule::Register(r) => get_reg(r.0),
        // Expression rules are rare; give up so the caller can fall back.
        RegisterRule::Expression(_) | RegisterRule::ValExpression(_) => None,
        _ => None,
    }
}
