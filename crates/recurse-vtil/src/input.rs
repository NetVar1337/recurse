//! Lifter input: a backend-neutral basic block, deliberately declared here
//! rather than imported from `recurse-static`.
//!
//! `recurse-static::engine::Engine::lift` (the intended caller) adapts its
//! own `FunctionGraph`/`BasicBlock`/`Instruction` into these shapes and calls
//! [`crate::lift::lift_routine`]. Keeping the dependency one-directional
//! (`recurse-static` depends on `recurse-vtil`, never the reverse) means this
//! crate has zero knowledge of Tauri, r2, or any specific binary format and
//! stays usable standalone — from a test fixture, a `.vtil`-style script, or
//! a future non-Recurse host — without pulling in a disassembler.

/// One instruction as any backend-neutral disassembly already reports it:
/// an address, the canonical `"mnemonic operand, operand"` text (comments
/// stripped by the lifter), and the coarse control-flow classification
/// (`"jmp" | "cjmp" | "call" | "ret"`, `None` for ordinary instructions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputInsn {
    pub addr: u64,
    pub disasm: String,
    pub kind: Option<String>,
    pub jump: Option<u64>,
    pub fail: Option<u64>,
}

/// One basic block, as recovered by any `Engine::function_graph`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputBlock {
    pub addr: u64,
    pub jump: Option<u64>,
    pub fail: Option<u64>,
    pub targets: Vec<u64>,
    pub ops: Vec<InputInsn>,
}
