//! Emulation-based deobfuscation: concretely execute a code region under
//! CPU emulation ([unicorn](https://www.unicorn-engine.org/)) and record
//! the exact instructions actually taken.
//!
//! # Why concrete execution, alongside static dataflow/symex
//!
//! [`crate::opt`]'s dataflow and [`crate::symex`]'s symbolic execution
//! both reason about *every statically possible* path through a routine.
//! That's exactly wrong for the obfuscation techniques this module
//! targets: an **opaque predicate** (`cmp eax, eax; je real_branch` — a
//! condition that's always true/false for *every* real input, but looks
//! data-dependent to static analysis) or a **VM-style dispatcher loop**
//! (one indirect-jump block executed repeatedly, `state = next_state(state)`,
//! with a different real handler address each iteration) both present an
//! enormous, mostly-fake static control-flow graph. Actually *running*
//! the code with concrete inputs collapses that fake graph down to the
//! one real path/handler sequence that ever executes — which is the
//! entire point of unicorn-based devirtualization tools: reasoning about
//! traces, not the static (and often deliberately misleading) CFG.
//!
//! # What this module gives you
//!
//! [`trace_x86_64`] runs a code buffer under real x86-64 emulation from
//! `entry_offset` and records every instruction address actually reached,
//! in execution order, plus the final register file. Feed it the output
//! of an opaque-predicate-guarded branch or one iteration of a dispatcher
//! loop, and the trace tells you — concretely, not "possibly" — which
//! side of each branch really executes, and which basic blocks are dead
//! code that static analysis alone cannot rule out.
//!
//! # Honest scope
//!
//! - **x86-64 only** (`Arch::X86`/`Mode::MODE_64`). Other architectures
//!   unicorn itself supports (ARM, AArch64, MIPS, …) are real, scoped
//!   follow-up work — the tracing logic itself isn't x86-specific, only
//!   [`trace_x86_64`]'s setup is.
//! - **No automatic loop/dispatcher unrolling.** A VM dispatcher needs
//!   the caller to drive multiple `trace_x86_64` calls (one per iteration,
//!   feeding back the recovered handler address as the next entry point)
//!   and stitch the results — this module provides the single-shot trace
//!   primitive that workflow is built from, not the workflow itself.
//! - **No memory-region auto-sizing/relocation handling.** The caller
//!   picks `base`/`stack_base` (must be 4 KiB-page-aligned, per unicorn's
//!   own requirement) — no attempt to infer a real image's actual
//!   preferred load address or fix up absolute references into other
//!   sections.
//! - **Not wired into `Engine`/`analyze` yet** — a standalone, fully-tested
//!   library capability first, same path this crate's other modules took
//!   before landing an op.

use std::collections::HashMap;

use unicorn_engine::{Arch, Mode, Prot, RegisterX86, Unicorn};

/// One instruction actually executed, in trace order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutedInstruction {
    pub address: u64,
    pub size: u32,
}

/// The result of concretely executing a code region.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionTrace {
    /// Every instruction executed, in the order it actually ran (a loop
    /// iterating twice records its body's addresses twice).
    pub instructions: Vec<ExecutedInstruction>,
    /// General-purpose register values after emulation stopped.
    pub final_registers: HashMap<&'static str, u64>,
}

impl ExecutionTrace {
    /// Whether any executed instruction started at `address` — the
    /// concrete-execution answer to "is this code actually reachable",
    /// as opposed to "is this code statically reachable".
    #[must_use]
    pub fn reached(&self, address: u64) -> bool {
        self.instructions.iter().any(|i| i.address == address)
    }
}

const PAGE_SIZE: u64 = 0x1000;
const STACK_SIZE: u64 = PAGE_SIZE * 4;

/// Concretely execute `code`, mapped at `base`, starting at `base +
/// entry_offset`, until either `base + until_offset` is reached or
/// `max_instructions` instructions have executed (whichever comes
/// first). `base` and a separate stack region are mapped fresh for this
/// call; `initial_registers` seeds any GPRs the caller wants a specific
/// concrete value for before execution starts (unlisted registers start
/// at 0).
pub fn trace_x86_64(
    code: &[u8],
    base: u64,
    entry_offset: u64,
    until_offset: u64,
    max_instructions: usize,
    initial_registers: &[(RegisterX86, u64)],
) -> Result<ExecutionTrace, String> {
    if !base.is_multiple_of(PAGE_SIZE) {
        return Err(format!(
            "base {base:#x} must be page-aligned ({PAGE_SIZE:#x})"
        ));
    }
    let mut uc =
        Unicorn::new_with_data(Arch::X86, Mode::MODE_64, Vec::<ExecutedInstruction>::new())
            .map_err(|e| format!("open unicorn: {e:?}"))?;

    let code_map_size = code.len().div_ceil(PAGE_SIZE as usize) as u64 * PAGE_SIZE;
    uc.mem_map(base, code_map_size.max(PAGE_SIZE), Prot::ALL)
        .map_err(|e| format!("map code region: {e:?}"))?;
    uc.mem_write(base, code)
        .map_err(|e| format!("write code: {e:?}"))?;

    // A separate stack region, well away from the code mapping, so a
    // `push`/`call`/local-variable write can't collide with instruction
    // bytes still being fetched.
    let stack_base = base
        .checked_add(code_map_size.max(PAGE_SIZE) + PAGE_SIZE)
        .ok_or("address overflow mapping stack")?;
    uc.mem_map(stack_base, STACK_SIZE, Prot::ALL)
        .map_err(|e| format!("map stack: {e:?}"))?;
    uc.reg_write(RegisterX86::RSP, stack_base + STACK_SIZE - PAGE_SIZE)
        .map_err(|e| format!("set rsp: {e:?}"))?;

    for &(reg, value) in initial_registers {
        uc.reg_write(reg, value)
            .map_err(|e| format!("set initial register: {e:?}"))?;
    }

    uc.add_code_hook(base, base + code_map_size, |uc, address, size| {
        uc.get_data_mut()
            .push(ExecutedInstruction { address, size });
    })
    .map_err(|e| format!("install code hook: {e:?}"))?;

    let entry = base + entry_offset;
    let until = base + until_offset;
    // `count == 0` means "no instruction limit" to unicorn; this module's
    // callers always want a bound (an obfuscated/adversarial routine is
    // exactly the case where "run until it naturally stops" is unsafe),
    // so 0 is rejected rather than silently becoming unlimited.
    if max_instructions == 0 {
        return Err("max_instructions must be nonzero".to_string());
    }
    // A real error (bad opcode, fault, memory violation) is still
    // reported; hitting `until` or the instruction limit is the expected
    // way for a trace to end and is not itself an error condition.
    match uc.emu_start(entry, until, 0, max_instructions) {
        Ok(()) => {}
        Err(unicorn_engine::uc_error::OK) => {}
        Err(e) => return Err(format!("emulation fault: {e:?}")),
    }

    let mut final_registers = HashMap::new();
    for (name, reg) in [
        ("rax", RegisterX86::RAX),
        ("rbx", RegisterX86::RBX),
        ("rcx", RegisterX86::RCX),
        ("rdx", RegisterX86::RDX),
        ("rsi", RegisterX86::RSI),
        ("rdi", RegisterX86::RDI),
        ("rip", RegisterX86::RIP),
    ] {
        if let Ok(value) = uc.reg_read(reg) {
            final_registers.insert(name, value);
        }
    }

    Ok(ExecutionTrace {
        instructions: uc.get_data().clone(),
        final_registers,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// Hand-assembled x86-64: an opaque predicate that is *always* true
    /// (`cmp eax, 1` right after `mov eax, 1`) guarding two different
    /// `mov ebx, imm32` blocks — exactly the shape real obfuscators use
    /// to hide which branch is the "real" one from static analysis.
    /// Static analysis alone cannot rule out the dead branch (`ebx =
    /// 0xDEAD`) without deep constant propagation across the whole
    /// function; concrete execution settles it in one run.
    ///
    /// ```text
    /// 0:  mov eax, 1
    /// 5:  cmp eax, 1
    /// 10: je 19            ; always taken
    /// 12: mov ebx, 0xDEAD  ; dead branch, never executed
    /// 17: jmp 24
    /// 19: mov ebx, 0xBEEF  ; real branch
    /// 24: <end>
    /// ```
    fn opaque_predicate_fixture() -> Vec<u8> {
        vec![
            0xB8, 0x01, 0x00, 0x00, 0x00, // 0:  mov eax, 1
            0x3D, 0x01, 0x00, 0x00, 0x00, // 5:  cmp eax, 1
            0x74, 0x07, // 10: je +7  -> 19
            0xBB, 0xAD, 0xDE, 0x00, 0x00, // 12: mov ebx, 0xDEAD
            0xEB, 0x05, // 17: jmp +5 -> 24
            0xBB, 0xEF, 0xBE, 0x00, 0x00, // 19: mov ebx, 0xBEEF
        ]
    }

    #[test]
    fn concrete_execution_resolves_the_opaque_predicate_to_the_real_branch() {
        let code = opaque_predicate_fixture();
        let end = code.len() as u64;
        let trace = trace_x86_64(&code, 0x1000, 0, end, 100, &[]).expect("trace");

        assert_eq!(trace.final_registers.get("rbx").copied(), Some(0xBEEF));
        assert!(
            trace.reached(0x1000 + 19),
            "the real branch must have executed"
        );
        assert!(
            !trace.reached(0x1000 + 12),
            "the dead branch must NOT have executed"
        );
    }

    #[test]
    fn instruction_count_limit_stops_execution_early() {
        let code = opaque_predicate_fixture();
        let trace = trace_x86_64(&code, 0x2000, 0, code.len() as u64, 1, &[]).expect("trace");
        // Only the first instruction (`mov eax, 1`) should have run.
        assert_eq!(trace.instructions.len(), 1);
        assert_eq!(trace.instructions[0].address, 0x2000);
    }

    #[test]
    fn initial_register_seeding_changes_which_branch_is_taken() {
        // Same code, but this time the predicate is data-dependent on a
        // register the caller seeds — proving `initial_registers` really
        // reaches the emulated CPU state, not just documentation.
        let code = vec![
            0x3D, 0x01, 0x00, 0x00, 0x00, // 0: cmp eax, 1
            0x74, 0x07, // 5: je +7 -> 14
            0xBB, 0xAD, 0xDE, 0x00, 0x00, // 7: mov ebx, 0xDEAD
            0xEB, 0x05, // 12: jmp +5 -> 19
            0xBB, 0xEF, 0xBE, 0x00, 0x00, // 14: mov ebx, 0xBEEF
        ];
        let end = code.len() as u64;

        let taken =
            trace_x86_64(&code, 0x3000, 0, end, 100, &[(RegisterX86::RAX, 1)]).expect("trace");
        assert_eq!(taken.final_registers.get("rbx").copied(), Some(0xBEEF));

        let not_taken =
            trace_x86_64(&code, 0x4000, 0, end, 100, &[(RegisterX86::RAX, 2)]).expect("trace");
        assert_eq!(not_taken.final_registers.get("rbx").copied(), Some(0xDEAD));
    }

    #[test]
    fn rejects_a_non_page_aligned_base() {
        let result = trace_x86_64(&[0x90], 0x1001, 0, 1, 10, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_a_zero_instruction_limit() {
        let result = trace_x86_64(&[0x90], 0x5000, 0, 1, 0, &[]);
        assert!(result.is_err());
    }
}
