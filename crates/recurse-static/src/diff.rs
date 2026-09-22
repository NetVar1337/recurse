//! Binary diffing: match functions between two versions/builds of a
//! binary by *shape*, not address — the same "which function in the
//! patched build corresponds to which function in the old build, even
//! though everything got relocated and renumbered" job as BinDiff/
//! Diaphora. The classic patch-diffing use case: find what a security
//! patch actually touched by diffing the patched binary against the
//! pre-patch one.
//!
//! # Design: decoupled from any particular disassembler
//!
//! This module takes plain [`FunctionSummary`] values, not an `Engine` or
//! a binary's raw bytes — the caller extracts a normalized instruction
//! shape from whichever backend (native/r2) they're already using and
//! hands it in. That keeps the *matching algorithm* (the actual value
//! here) testable with hand-built inputs, decoupled from disassembly, and
//! reusable across this crate's three `Engine` backends without adding a
//! fourth dependency direction.
//!
//! [`normalize_mnemonics`] is the suggested way to build that shape from
//! raw disassembly text: strip immediates/addresses (which differ across
//! builds even for byte-identical logic — a relocated call target,
//! a different stack-cookie constant) down to opcue+operand-*kind*
//! (`"mov reg,reg"`, `"call rel"`), matching this module's own tests.
//!
//! # Matching passes
//!
//! 1. **Exact**: functions whose full normalized-mnemonic sequence
//!    hashes identically. High confidence (`1.0`) — genuinely
//!    unchanged code, just moved/renamed/relinked.
//! 2. **Fuzzy**: for everything exact matching left unmatched, greedy
//!    best-first pairing by normalized-mnemonic-sequence similarity
//!    (longest-common-subsequence ratio — sequence *order* matters, so
//!    this survives instruction insertion/deletion in the middle of a
//!    function, not just a same-length one-opcode edit) above
//!    [`FUZZY_THRESHOLD`]. This is what finds "this function gained a
//!    bounds check" or "this function lost an early return" across a
//!    patch.
//!
//! # Honest scope
//!
//! - **No call-graph confidence propagation** (BinDiff's "MD index"
//!   technique: a function's match confidence rises when its *callers*
//!   and *callees* are already known-matched). [`FunctionSummary::calls`]
//!   is carried through so a caller can build that on top, but this
//!   module's own matcher only uses instruction shape. Real, scoped
//!   follow-up work.
//! - **No basic-block/CFG-shape matching**, only whole-function linear
//!   instruction sequences. Real follow-up work for functions where
//!   block reordering (but not content change) is the only difference.
//! - **Not wired into `Engine`/`analyze` yet** — a standalone, fully-tested
//!   library capability first, same path every other Tier-2 module here
//!   took.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// A caller-provided summary of one function's shape, enough to match it
/// against a function in another binary without needing the raw bytes or
/// a live disassembler here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionSummary {
    pub address: u64,
    pub name: String,
    /// Normalized instruction shape, in address order — see
    /// [`normalize_mnemonics`] for the suggested way to build this from
    /// raw disassembly.
    pub normalized_instructions: Vec<String>,
    /// Addresses this function calls, for a caller's own call-graph-aware
    /// matching on top of this module's per-function matches (see module
    /// docs: not used internally here).
    pub calls: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchMethod {
    /// Identical normalized instruction sequence.
    Exact,
    /// Similar (above [`FUZZY_THRESHOLD`]) but not identical.
    Fuzzy,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MatchedFunction {
    pub a: u64,
    pub b: u64,
    pub name_a: String,
    pub name_b: String,
    /// 0.0 (no similarity) .. 1.0 (identical shape).
    pub confidence: f64,
    pub method: MatchMethod,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DiffResult {
    pub matched: Vec<MatchedFunction>,
    /// Functions present in `a`, not matched in `b` — apparently removed.
    pub removed: Vec<u64>,
    /// Functions present in `b`, not matched in `a` — apparently added.
    pub added: Vec<u64>,
}

/// Minimum longest-common-subsequence ratio for a fuzzy match to count —
/// below this, two functions are treated as unrelated rather than a weak
/// match, the same philosophy `crate::sig`'s `min_concrete_bytes`
/// threshold uses for signature matches: an unreliable match is worse
/// than no match.
pub const FUZZY_THRESHOLD: f64 = 0.6;

/// Diff functions in binary `a` against binary `b`.
pub fn diff(a: &[FunctionSummary], b: &[FunctionSummary]) -> DiffResult {
    let mut matched_a: HashMap<u64, MatchedFunction> = HashMap::new();
    let mut used_b: std::collections::HashSet<u64> = std::collections::HashSet::new();

    // Pass 1: exact hash match. Build b's shape-hash -> addresses map
    // once; if a hash has exactly one unclaimed candidate in b, take it.
    let mut hash_to_b: HashMap<u64, Vec<u64>> = HashMap::new();
    for f in b {
        hash_to_b
            .entry(sequence_hash(&f.normalized_instructions))
            .or_default()
            .push(f.address);
    }
    let b_by_addr: HashMap<u64, &FunctionSummary> = b.iter().map(|f| (f.address, f)).collect();

    for fa in a {
        let h = sequence_hash(&fa.normalized_instructions);
        if let Some(candidates) = hash_to_b.get(&h) {
            if let Some(&addr) = candidates.iter().find(|addr| !used_b.contains(*addr)) {
                used_b.insert(addr);
                let fb = b_by_addr[&addr];
                matched_a.insert(
                    fa.address,
                    MatchedFunction {
                        a: fa.address,
                        b: addr,
                        name_a: fa.name.clone(),
                        name_b: fb.name.clone(),
                        confidence: 1.0,
                        method: MatchMethod::Exact,
                    },
                );
            }
        }
    }

    // Pass 2: fuzzy match everything left, greedy best-first so the
    // globally strongest pairs win before weaker ones claim a candidate.
    let mut remaining_a: Vec<&FunctionSummary> = a
        .iter()
        .filter(|f| !matched_a.contains_key(&f.address))
        .collect();
    let remaining_b: Vec<&FunctionSummary> =
        b.iter().filter(|f| !used_b.contains(&f.address)).collect();

    let mut candidates: Vec<(f64, u64, u64)> = Vec::new();
    for fa in &remaining_a {
        for fb in &remaining_b {
            let sim = lcs_ratio(&fa.normalized_instructions, &fb.normalized_instructions);
            if sim >= FUZZY_THRESHOLD {
                candidates.push((sim, fa.address, fb.address));
            }
        }
    }
    candidates.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap_or(std::cmp::Ordering::Equal));
    let a_by_addr: HashMap<u64, &FunctionSummary> = a.iter().map(|f| (f.address, f)).collect();

    let mut claimed_a: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for (sim, addr_a, addr_b) in candidates {
        if claimed_a.contains(&addr_a) || used_b.contains(&addr_b) {
            continue;
        }
        claimed_a.insert(addr_a);
        used_b.insert(addr_b);
        let Some(fa) = a_by_addr.get(&addr_a) else {
            continue;
        };
        let Some(fb) = b_by_addr.get(&addr_b) else {
            continue;
        };
        matched_a.insert(
            addr_a,
            MatchedFunction {
                a: addr_a,
                b: addr_b,
                name_a: fa.name.clone(),
                name_b: fb.name.clone(),
                confidence: sim,
                method: MatchMethod::Fuzzy,
            },
        );
    }
    remaining_a.retain(|f| !matched_a.contains_key(&f.address));

    let removed: Vec<u64> = a
        .iter()
        .filter(|f| !matched_a.contains_key(&f.address))
        .map(|f| f.address)
        .collect();
    let added: Vec<u64> = b
        .iter()
        .filter(|f| !used_b.contains(&f.address))
        .map(|f| f.address)
        .collect();
    let mut matched: Vec<MatchedFunction> = matched_a.into_values().collect();
    matched.sort_by_key(|m| m.a);

    DiffResult {
        matched,
        removed,
        added,
    }
}

fn sequence_hash(seq: &[String]) -> u64 {
    let mut hasher = DefaultHasher::new();
    seq.hash(&mut hasher);
    hasher.finish()
}

/// Longest-common-subsequence length, as a fraction of `max(len(a),
/// len(b))` — `1.0` for identical sequences, falling as they diverge, and
/// robust to insertions/deletions anywhere in the sequence (not just a
/// fixed-position diff), which is what actually happens across a real
/// source patch.
pub(crate) fn lcs_ratio(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (n, m) = (a.len(), b.len());
    let mut prev = vec![0u32; m + 1];
    let mut curr = vec![0u32; m + 1];
    for i in 1..=n {
        for j in 1..=m {
            curr[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1] + 1
            } else {
                prev[j].max(curr[j - 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    let lcs_len = prev[m] as f64;
    lcs_len / (n.max(m) as f64)
}

/// Build a [`FunctionSummary::normalized_instructions`]-shaped sequence
/// from raw `"mnemonic operand, operand"`-style disassembly lines,
/// stripping numeric immediates/addresses down to an `"imm"` placeholder
/// and register names down to their own text (registers *do* usually
/// matter to whether logic changed; literal addresses/offsets don't, since
/// those differ across any two builds even for identical source).
pub fn normalize_mnemonics(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            line.split_whitespace()
                .map(|tok| {
                    let cleaned: String = tok.trim_matches(',').to_string();
                    if is_numeric_operand(&cleaned) {
                        "imm".to_string()
                    } else {
                        cleaned
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect()
}

fn is_numeric_operand(tok: &str) -> bool {
    let t = tok.trim_start_matches('-');
    if let Some(hex) = t.strip_prefix("0x") {
        return !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit());
    }
    !t.is_empty() && t.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn func(addr: u64, name: &str, insns: &[&str]) -> FunctionSummary {
        FunctionSummary {
            address: addr,
            name: name.to_string(),
            normalized_instructions: insns.iter().map(|s| s.to_string()).collect(),
            calls: Vec::new(),
        }
    }

    #[test]
    fn identical_function_relocated_matches_exactly() {
        let a = [func(
            0x1000,
            "foo",
            &["push rbp", "mov rbp rsp", "mov eax imm", "pop rbp", "ret"],
        )];
        // Same shape, different address and different name (as if
        // stripped/renamed) — this is exactly the "same code, different
        // build" case this pass exists for.
        let b = [func(
            0x9000,
            "sub_9000",
            &["push rbp", "mov rbp rsp", "mov eax imm", "pop rbp", "ret"],
        )];
        let result = diff(&a, &b);
        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.matched[0].method, MatchMethod::Exact);
        assert_eq!(result.matched[0].confidence, 1.0);
        assert_eq!(result.matched[0].b, 0x9000);
        assert!(result.removed.is_empty());
        assert!(result.added.is_empty());
    }

    #[test]
    fn a_patched_function_with_an_inserted_bounds_check_fuzzy_matches() {
        let a = [func(
            0x1000,
            "parse",
            &["push rbp", "mov rbp rsp", "mov eax imm", "pop rbp", "ret"],
        )];
        // Same function, plus a patch inserting a bounds check in the
        // middle — not identical, but an LCS of 5 shared lines out of 6.
        let b = [func(
            0x2000,
            "parse",
            &[
                "push rbp",
                "mov rbp rsp",
                "cmp eax imm",
                "mov eax imm",
                "pop rbp",
                "ret",
            ],
        )];
        let result = diff(&a, &b);
        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.matched[0].method, MatchMethod::Fuzzy);
        assert!(
            result.matched[0].confidence > FUZZY_THRESHOLD,
            "{}",
            result.matched[0].confidence
        );
        assert!(result.matched[0].confidence < 1.0);
    }

    #[test]
    fn a_genuinely_new_function_is_reported_added_not_force_matched() {
        let a = [func(0x1000, "foo", &["push rbp", "ret"])];
        let b = [
            func(0x1000, "foo", &["push rbp", "ret"]),
            func(
                0x2000,
                "brand_new",
                &[
                    "xor eax eax",
                    "mov ecx imm",
                    "call rel",
                    "test eax eax",
                    "jz rel",
                ],
            ),
        ];
        let result = diff(&a, &b);
        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.added, vec![0x2000]);
        assert!(result.removed.is_empty());
    }

    #[test]
    fn a_removed_function_is_reported_removed_not_force_matched() {
        let a = [
            func(0x1000, "foo", &["push rbp", "ret"]),
            func(
                0x2000,
                "dead_code",
                &[
                    "xor eax eax",
                    "mov ecx imm",
                    "call rel",
                    "test eax eax",
                    "jz rel",
                ],
            ),
        ];
        let b = [func(0x1000, "foo", &["push rbp", "ret"])];
        let result = diff(&a, &b);
        assert_eq!(result.matched.len(), 1);
        assert_eq!(result.removed, vec![0x2000]);
        assert!(result.added.is_empty());
    }

    #[test]
    fn completely_unrelated_functions_do_not_fuzzy_match() {
        let a = [func(0x1000, "small", &["ret"])];
        let b = [func(
            0x2000,
            "huge_and_different",
            &[
                "push rbp",
                "mov rbp rsp",
                "sub rsp imm",
                "xor eax eax",
                "call rel",
                "leave",
                "ret",
            ],
        )];
        let result = diff(&a, &b);
        assert!(result.matched.is_empty());
        assert_eq!(result.removed, vec![0x1000]);
        assert_eq!(result.added, vec![0x2000]);
    }

    #[test]
    fn normalize_mnemonics_strips_immediates_and_addresses_but_keeps_registers() {
        let lines = vec![
            "mov eax, 0x1234".to_string(),
            "call 0x140001000".to_string(),
            "push rbp".to_string(),
        ];
        let normalized = normalize_mnemonics(&lines);
        assert_eq!(normalized, vec!["mov eax imm", "call imm", "push rbp"]);
    }

    #[test]
    fn lcs_ratio_is_one_for_identical_and_zero_for_disjoint() {
        let x = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(lcs_ratio(&x, &x), 1.0);
        let y = vec!["d".to_string(), "e".to_string(), "f".to_string()];
        assert_eq!(lcs_ratio(&x, &y), 0.0);
    }
}
