//! Conditional breakpoints, software watchpoints, and tracepoints —
//! layered entirely on top of [`crate::Debugger`]'s existing public API
//! (`resume`/`step`/`registers`/`read_memory`), so none of this needs to
//! touch [`crate::session`] or [`crate::target`] at all.
//!
//! # Conditional breakpoints
//!
//! A real address breakpoint ([`crate::Debugger::add_breakpoint`]) stops
//! unconditionally every time it's hit. [`run_until_condition`] adds a
//! condition on top: when the hit address matches a
//! [`ConditionalBreakpoint`] whose [`Condition`] evaluates false against
//! the registers at that stop, it transparently resumes again instead of
//! returning control to the caller — the same "keep going until this
//! register expression is true" a real debugger's conditional breakpoint
//! gives you, built from a plain resume-loop rather than needing the
//! `target::Target` backend to know about conditions at all.
//!
//! # Watchpoints
//!
//! No hardware debug-register plumbing (`Dr0`-`Dr3`/`Dr7`) — that needs
//! backend-specific work in every `target::Target` implementation.
//! Instead, [`Watchpoint`] is a **software** watchpoint: the caller
//! single-steps ([`crate::Debugger::step`]) and calls
//! [`Watchpoint::poll`] with the current bytes at its address after each
//! step; `poll` reports whether the value changed since the last poll.
//! Correct, portable, and — being driven by real single-stepping rather
//! than a debug-register trap — proportionately slower than a hardware
//! watchpoint. That tradeoff, and the fact hardware watchpoints are real,
//! scoped follow-up work, are both intentional and documented here rather
//! than silently assumed.
//!
//! # Tracepoints
//!
//! [`Tracepoint::render`] turns a hit address into a log line by
//! interpolating `{register}` placeholders from the registers at that
//! stop — "log this and keep going" without turning every trace point
//! into a real stop. [`run_until_condition`] renders every tracepoint it
//! passes through into the returned log, alongside the specific
//! conditional breakpoint stop (or process exit) that finally ends the
//! run.

use std::collections::HashMap;

use crate::model::{Registers, StepKind, Stop, StopReason};
use crate::{Debugger, Error, Result};

/// A comparison operator for a [`Condition`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn apply(self, lhs: u64, rhs: u64) -> bool {
        match self {
            CmpOp::Eq => lhs == rhs,
            CmpOp::Ne => lhs != rhs,
            CmpOp::Lt => lhs < rhs,
            CmpOp::Le => lhs <= rhs,
            CmpOp::Gt => lhs > rhs,
            CmpOp::Ge => lhs >= rhs,
        }
    }
}

/// The right-hand side of a [`Condition`]: either a literal value or
/// another register, read at evaluation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rhs {
    Immediate(u64),
    Register(String),
}

/// A breakpoint condition: `register OP (immediate | register)`, e.g.
/// `"rax == 0"` or `"rcx != rdx"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    pub register: String,
    pub op: CmpOp,
    pub rhs: Rhs,
}

impl Condition {
    /// Parse `"reg OP value"` (whitespace-separated). `OP` is one of `==
    /// != < <= > >=`. `value` is either a register name or an integer
    /// (decimal, or `0x`-prefixed hex).
    ///
    /// # Errors
    /// A message describing the malformed part, when `expr` doesn't
    /// parse.
    pub fn parse(expr: &str) -> Result<Self> {
        let tokens: Vec<&str> = expr.split_whitespace().collect();
        let [register, op, rhs] = tokens[..] else {
            return Err(Error::msg(format!("expected `reg OP value`, got {expr:?}")));
        };
        let op = match op {
            "==" => CmpOp::Eq,
            "!=" => CmpOp::Ne,
            "<" => CmpOp::Lt,
            "<=" => CmpOp::Le,
            ">" => CmpOp::Gt,
            ">=" => CmpOp::Ge,
            other => return Err(Error::msg(format!("unknown operator {other:?}"))),
        };
        let rhs = if let Some(hex) = rhs.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
                .map(Rhs::Immediate)
                .map_err(|e| Error::msg(format!("bad hex value: {e}")))?
        } else if rhs.chars().all(|c| c.is_ascii_digit()) && !rhs.is_empty() {
            rhs.parse::<u64>()
                .map(Rhs::Immediate)
                .map_err(|e| Error::msg(format!("bad value: {e}")))?
        } else {
            Rhs::Register(rhs.to_string())
        };
        Ok(Condition {
            register: register.to_string(),
            op,
            rhs,
        })
    }

    /// Look up a register's value by its conventional name (`pc`/`rip`,
    /// `sp`/`rsp`, `fp`/`rbp`, or any name present in
    /// [`Registers::values`]).
    fn lookup(regs: &Registers, name: &str) -> Option<u64> {
        match name {
            "pc" | "rip" | "eip" => Some(regs.pc),
            "sp" | "rsp" | "esp" => Some(regs.sp),
            "fp" | "rbp" | "ebp" => Some(regs.fp),
            other => regs.values.get(other).copied(),
        }
    }

    /// Evaluate this condition against `regs`. An unknown register name
    /// (on either side) makes the condition false, not an error —
    /// consistent with "no match beats a wrong match": a condition
    /// referencing a register this architecture doesn't have should never
    /// silently stop every single hit.
    #[must_use]
    pub fn evaluate(&self, regs: &Registers) -> bool {
        let Some(lhs) = Self::lookup(regs, &self.register) else {
            return false;
        };
        let rhs = match &self.rhs {
            Rhs::Immediate(v) => Some(*v),
            Rhs::Register(name) => Self::lookup(regs, name),
        };
        let Some(rhs) = rhs else { return false };
        self.op.apply(lhs, rhs)
    }
}

/// A real address breakpoint, plus a [`Condition`] gating whether a hit
/// there actually stops the run.
#[derive(Clone, Debug)]
pub struct ConditionalBreakpoint {
    pub addr: u64,
    pub condition: Condition,
    pub hit_count: u64,
}

impl ConditionalBreakpoint {
    #[must_use]
    pub fn new(addr: u64, condition: Condition) -> Self {
        Self {
            addr,
            condition,
            hit_count: 0,
        }
    }
}

/// A software (poll-based) watchpoint over `size` bytes at `address`.
#[derive(Clone, Debug)]
pub struct Watchpoint {
    pub address: u64,
    pub size: usize,
    last_value: Option<Vec<u8>>,
}

impl Watchpoint {
    #[must_use]
    pub fn new(address: u64, size: usize) -> Self {
        Self {
            address,
            size,
            last_value: None,
        }
    }

    /// Record `current` as the new baseline, reporting whether it differs
    /// from the value seen at the previous call (the very first call
    /// always returns `false` — there is nothing yet to differ from).
    ///
    /// # Panics
    /// Never — a `current` slice shorter/longer than `self.size` is
    /// compared as-is (the caller is expected to pass exactly `self.size`
    /// bytes, from `Debugger::read_memory(self.address, self.size)`, but
    /// a short read at the end of a mapped region is a real possibility
    /// this method tolerates rather than panicking on).
    pub fn poll(&mut self, current: &[u8]) -> bool {
        let changed = self
            .last_value
            .as_deref()
            .is_some_and(|prev| prev != current);
        self.last_value = Some(current.to_vec());
        changed
    }
}

/// A breakpoint that logs a rendered message and keeps running.
#[derive(Clone, Debug)]
pub struct Tracepoint {
    pub addr: u64,
    /// A message template with `{register}` placeholders, e.g. `"enter
    /// with rcx={rcx}"`.
    pub template: String,
}

impl Tracepoint {
    #[must_use]
    pub fn new(addr: u64, template: impl Into<String>) -> Self {
        Self {
            addr,
            template: template.into(),
        }
    }

    /// Render this tracepoint's message against `regs`, substituting each
    /// `{name}` placeholder with that register's value in hex. An unknown
    /// register name is left as literal text (`{no_such_reg}`) rather
    /// than failing the whole render — one bad placeholder in a template
    /// shouldn't lose every other one.
    #[must_use]
    pub fn render(&self, regs: &Registers) -> String {
        let mut out = String::with_capacity(self.template.len());
        let mut rest = self.template.as_str();
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            rest = &rest[start + 1..];
            let Some(end) = rest.find('}') else {
                out.push('{');
                out.push_str(rest);
                rest = "";
                break;
            };
            let name = &rest[..end];
            match Condition::lookup(regs, name) {
                Some(value) => out.push_str(&format!("{value:#x}")),
                None => {
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        out
    }
}

/// Drive `dbg` with [`Debugger::resume`], treating every hit at a
/// [`ConditionalBreakpoint`]'s address whose condition is false, and
/// every hit at a [`Tracepoint`]'s address, as transparent — the run only
/// really stops at a *true* conditional breakpoint, an address neither
/// list names (a plain unconditional breakpoint the caller installed
/// directly, or a signal), or process exit. Returns that final [`Stop`]
/// plus every tracepoint message rendered along the way, in order.
///
/// `conditional_breakpoints` and `tracepoints` describe addresses the
/// caller has *already* installed with
/// [`Debugger::add_breakpoint`]/[`crate::model::BreakAt::Addr`] — this
/// function does not install anything itself, so the same list can be
/// reused across multiple calls without re-registering breakpoints.
///
/// # Errors
/// Whatever `dbg.resume()`/`dbg.registers()` returns; `max_iterations`
/// exhausted without a real stop is also an error (`Error::Message`) —
/// an unreachable condition should be discovered, not silently returned
/// as if the run legitimately ended.
pub fn run_until_condition(
    dbg: &Debugger,
    conditional_breakpoints: &mut [ConditionalBreakpoint],
    tracepoints: &[Tracepoint],
    max_iterations: usize,
) -> Result<(Stop, Vec<String>)> {
    let mut log = Vec::new();
    let mut by_addr: HashMap<u64, usize> = conditional_breakpoints
        .iter()
        .enumerate()
        .map(|(i, cb)| (cb.addr, i))
        .collect();
    let tp_by_addr: HashMap<u64, &Tracepoint> = tracepoints.iter().map(|t| (t.addr, t)).collect();

    for _ in 0..max_iterations {
        let stop = dbg.resume()?;
        if !matches!(stop.reason, StopReason::Breakpoint { .. }) {
            return Ok((stop, log));
        }
        let StopReason::Breakpoint { addr, .. } = stop.reason else {
            unreachable!()
        };

        if let Some(&idx) = by_addr.get(&addr) {
            let cb = &mut conditional_breakpoints[idx];
            if cb.condition.evaluate(&stop.registers) {
                cb.hit_count += 1;
                return Ok((stop, log));
            }
            cb.hit_count += 1;
            continue; // condition false: transparently resume past it
        }
        if let Some(tp) = tp_by_addr.get(&addr) {
            log.push(tp.render(&stop.registers));
            continue;
        }
        // A real stop this function doesn't model (an unconditional
        // breakpoint the caller wants to see every hit of, or an
        // unexpected signal) — hand control back rather than looping
        // forever past something the caller never asked to skip.
        return Ok((stop, log));
    }
    let _ = &mut by_addr; // keep the map alive for the whole loop above
    Err(Error::msg(format!(
        "run_until_condition: no qualifying stop within {max_iterations} resumes"
    )))
}

/// Software-watchpoint variant of [`run_until_condition`]: single-step
/// `dbg` up to `max_steps` times, polling every watchpoint's current
/// memory value after each step. Returns as soon as any watchpoint
/// reports a change, with the [`Stop`] from the step that caused it and
/// that watchpoint's index in `watchpoints`; `None` if nothing changed
/// within the step budget (not an error — "nothing changed" is a
/// legitimate, common outcome, unlike `run_until_condition`'s unreachable
/// condition).
///
/// # Errors
/// Whatever `dbg.step()`/`dbg.read_memory()` returns.
pub fn run_until_watchpoint_change(
    dbg: &Debugger,
    watchpoints: &mut [Watchpoint],
    max_steps: usize,
) -> Result<Option<(Stop, usize)>> {
    for _ in 0..max_steps {
        let stop = dbg.step(StepKind::Into)?;
        if !matches!(
            stop.reason,
            StopReason::Step | StopReason::Breakpoint { .. }
        ) {
            return Ok(Some((stop, usize::MAX))); // process ended/signaled mid-scan; hand back immediately
        }
        for (idx, wp) in watchpoints.iter_mut().enumerate() {
            let current = dbg.read_memory(wp.address, wp.size)?;
            if wp.poll(&current) {
                return Ok(Some((stop, idx)));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn regs(pairs: &[(&str, u64)]) -> Registers {
        let mut values = std::collections::BTreeMap::new();
        for (k, v) in pairs {
            values.insert((*k).to_string(), *v);
        }
        Registers {
            pc: values.get("rip").copied().unwrap_or(0),
            sp: 0,
            fp: 0,
            values,
        }
    }

    #[test]
    fn parses_and_evaluates_a_register_vs_immediate_condition() {
        let cond = Condition::parse("rax == 0x1234").expect("parse");
        assert!(cond.evaluate(&regs(&[("rax", 0x1234)])));
        assert!(!cond.evaluate(&regs(&[("rax", 0x1235)])));
    }

    #[test]
    fn parses_and_evaluates_a_register_vs_register_condition() {
        let cond = Condition::parse("rcx != rdx").expect("parse");
        assert!(cond.evaluate(&regs(&[("rcx", 1), ("rdx", 2)])));
        assert!(!cond.evaluate(&regs(&[("rcx", 5), ("rdx", 5)])));
    }

    #[test]
    fn all_six_operators_work() {
        let r = regs(&[("rax", 5)]);
        assert!(Condition::parse("rax == 5").unwrap().evaluate(&r));
        assert!(Condition::parse("rax != 6").unwrap().evaluate(&r));
        assert!(Condition::parse("rax < 6").unwrap().evaluate(&r));
        assert!(Condition::parse("rax <= 5").unwrap().evaluate(&r));
        assert!(Condition::parse("rax > 4").unwrap().evaluate(&r));
        assert!(Condition::parse("rax >= 5").unwrap().evaluate(&r));
    }

    #[test]
    fn an_unknown_register_makes_the_condition_false_not_an_error() {
        let cond = Condition::parse("nonexistent == 0").expect("parse");
        assert!(!cond.evaluate(&regs(&[("rax", 0)])));
    }

    #[test]
    fn rejects_a_malformed_expression() {
        assert!(Condition::parse("rax ==").is_err());
        assert!(Condition::parse("rax bogus 5").is_err());
        assert!(Condition::parse("").is_err());
    }

    #[test]
    fn watchpoint_reports_no_change_on_first_poll_then_detects_a_real_change() {
        let mut wp = Watchpoint::new(0x1000, 4);
        assert!(!wp.poll(&[1, 2, 3, 4]), "nothing to compare against yet");
        assert!(!wp.poll(&[1, 2, 3, 4]), "unchanged");
        assert!(wp.poll(&[1, 2, 3, 5]), "one byte differs");
        assert!(
            !wp.poll(&[1, 2, 3, 5]),
            "unchanged again, against the new baseline"
        );
    }

    #[test]
    fn tracepoint_renders_known_registers_and_leaves_unknown_placeholders_literal() {
        let tp = Tracepoint::new(0x2000, "rcx={rcx} unknown={nope} pc={pc}");
        let rendered = tp.render(&Registers {
            pc: 0x4000,
            sp: 0,
            fp: 0,
            values: [("rcx".to_string(), 7u64)].into(),
        });
        assert_eq!(rendered, "rcx=0x7 unknown={nope} pc=0x4000");
    }

    #[test]
    fn tracepoint_render_tolerates_an_unterminated_placeholder() {
        let tp = Tracepoint::new(0x2000, "trailing {rcx");
        let rendered = tp.render(&Registers::default());
        assert_eq!(rendered, "trailing {rcx");
    }
}
