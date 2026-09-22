//! FLIRT-equivalent signature matching: identify statically-linked library
//! functions in a stripped binary by their byte pattern — the technique
//! IDA's FLIRT ("Fast Library Identification and Recognition Technology")
//! and Ghidra's FunctionID use, and a real time saver: nobody wants to
//! manually re-derive what a redistributed copy of zlib's `deflate()` does.
//!
//! # The core problem a naive byte-for-byte match gets wrong
//!
//! Two binaries that both statically link the exact same library function
//! are *not* byte-identical at that function's address, even with the same
//! compiler and flags: any `call`/`jmp`/RIP-relative reference inside the
//! function encodes a *relative* displacement to whatever else got linked
//! alongside it, and link layouts differ. [`generate_signature`] wildcards
//! exactly those bytes — the encoded rel8/rel32 operand of any instruction
//! with a resolved branch/call target — using the same per-instruction
//! length/target-resolution information [`crate::engine::Instruction`]
//! already carries, not a relocation table (a fully linked executable's
//! *intra-module* calls have no live relocation left to read by the time
//! you have the final binary — the call target was already resolved to a
//! link-time-relative encoding).
//!
//! # Scope, honestly
//!
//! - This module is the pattern representation, the matcher, and the
//!   generator. It does **not** ship a pre-populated signature database for
//!   real-world libraries (glibc, zlib, OpenSSL, …) — building one
//!   correctly needs a curated corpus built from many compiler/version/flag
//!   combinations, which is a data-curation project of its own, not
//!   something to fabricate here. [`SignatureDatabase::to_text`]/
//!   [`SignatureDatabase::from_text`] give a real database (built by a
//!   caller, from their own library builds) somewhere to live.
//! - Real FLIRT also cross-references *other* recognised functions to
//!   disambiguate identical prologues (`sub_401000` calls
//!   already-identified `malloc`, so the ambiguous 16-byte prologue it
//!   itself matches several candidates for is resolved by which of those
//!   candidates also calls something shaped like `malloc`). Not implemented
//!   here — [`Signature::confidence`] (how much of the pattern is concrete,
//!   not wildcarded) and [`SignatureDatabase::match_at`]'s
//!   `min_concrete_bytes` threshold are this module's — much simpler —
//!   substitute for filtering out unreliable matches.
//! - Not wired into `Engine`/`analyze` yet, same as `crate::types`: a
//!   standalone, fully-tested library capability first.

/// One byte of a [`Signature`] pattern: a required concrete byte, or `None`
/// for a wildcard (any byte matches).
type PatternByte = Option<u8>;

/// A named byte pattern — normally one library function's identifying
/// bytes, with link-layout-dependent bytes wildcarded.
#[derive(Clone, Debug, PartialEq)]
pub struct Signature {
    pub name: String,
    pub pattern: Vec<PatternByte>,
}

impl Signature {
    /// True when `bytes` (at least [`Signature::pattern`]'s length) matches
    /// this pattern byte-for-byte at every concrete position.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() >= self.pattern.len()
            && self
                .pattern
                .iter()
                .zip(bytes)
                .all(|(p, b)| p.is_none_or(|x| x == *b))
    }

    /// Fraction of the pattern that is concrete (not wildcarded), in
    /// `[0.0, 1.0]` — a rough reliability signal. Real FLIRT enforces a
    /// minimum pattern length (commonly 32 bytes) for the same reason: a
    /// short, heavily-wildcarded pattern matches too many unrelated
    /// functions to be useful.
    pub fn confidence(&self) -> f64 {
        if self.pattern.is_empty() {
            return 0.0;
        }
        let concrete = self.pattern.iter().filter(|b| b.is_some()).count();
        concrete as f64 / self.pattern.len() as f64
    }

    fn concrete_byte_count(&self) -> usize {
        self.pattern.iter().filter(|b| b.is_some()).count()
    }

    /// Render as `name\tXX XX ?? XX …` (`??` for a wildcard byte) — one
    /// line of [`SignatureDatabase::to_text`].
    pub fn to_text(&self) -> String {
        let bytes: Vec<String> = self
            .pattern
            .iter()
            .map(|b| match b {
                Some(v) => format!("{v:02x}"),
                None => "??".to_string(),
            })
            .collect();
        format!("{}\t{}", self.name, bytes.join(" "))
    }

    /// Parse one [`Signature::to_text`] line back.
    pub fn from_text(line: &str) -> Result<Self, String> {
        let mut parts = line.splitn(2, '\t');
        let name = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "missing name".to_string())?
            .to_string();
        let pattern_text = parts.next().ok_or_else(|| "missing pattern".to_string())?;
        let mut pattern = Vec::new();
        for tok in pattern_text.split_whitespace() {
            if tok == "??" {
                pattern.push(None);
            } else {
                let v =
                    u8::from_str_radix(tok, 16).map_err(|e| format!("bad byte {tok:?}: {e}"))?;
                pattern.push(Some(v));
            }
        }
        if pattern.is_empty() {
            return Err("empty pattern".to_string());
        }
        Ok(Signature { name, pattern })
    }
}

/// A collection of [`Signature`]s, matched/scanned as a set.
#[derive(Clone, Debug, Default)]
pub struct SignatureDatabase {
    signatures: Vec<Signature>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Signature> {
        self.signatures.iter()
    }

    /// The most reliable ([`Signature::confidence`]-highest) signature that
    /// matches `bytes` at offset `0` and has at least `min_concrete_bytes`
    /// concrete (non-wildcard) bytes — the threshold that keeps a
    /// short/heavily-wildcarded pattern from firing on unrelated code.
    pub fn match_at(&self, bytes: &[u8], min_concrete_bytes: usize) -> Option<&Signature> {
        self.signatures
            .iter()
            .filter(|s| s.concrete_byte_count() >= min_concrete_bytes)
            .filter(|s| s.matches(bytes))
            .max_by(|a, b| {
                a.confidence()
                    .partial_cmp(&b.confidence())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Every offset in `bytes` where some signature matches (subject to
    /// `min_concrete_bytes`), as `(offset, signature)` pairs. Meant to be
    /// called with `bytes` starting at each already-known function's own
    /// start address (from `Engine::functions`), not scanned across a whole
    /// section — a signature matching mid-instruction is a false positive
    /// this module does not try to filter out on its own.
    pub fn scan(&self, bytes: &[u8], min_concrete_bytes: usize) -> Vec<(usize, &Signature)> {
        let mut out = Vec::new();
        for offset in 0..bytes.len() {
            if let Some(sig) = self.match_at(&bytes[offset..], min_concrete_bytes) {
                out.push((offset, sig));
            }
        }
        out
    }

    /// One [`Signature::to_text`] line per signature.
    pub fn to_text(&self) -> String {
        self.signatures
            .iter()
            .map(Signature::to_text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Parse [`SignatureDatabase::to_text`]'s format back — blank lines and
    /// `#`-prefixed comment lines are skipped.
    pub fn from_text(source: &str) -> Result<Self, String> {
        let mut db = Self::new();
        for (i, raw_line) in source.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let sig = Signature::from_text(line).map_err(|e| format!("line {}: {e}", i + 1))?;
            db.add(sig);
        }
        Ok(db)
    }
}

/// One decoded instruction's shape, as far as signature generation needs:
/// its byte length and whether it carries a resolved branch/call target.
/// Deliberately not [`crate::engine::Instruction`] itself, so this module
/// composes with whatever produced the bytes (a live `Engine` session, a
/// `.o`/`.a` disassembled some other way, …) without needing a full
/// `Engine`.
#[derive(Clone, Copy, Debug)]
pub struct InsnShape {
    pub len: usize,
    /// True for a `call`/`jmp`/conditional branch whose target address was
    /// statically resolved (`Instruction::jump.is_some()` in the engine's
    /// own terms) — the case whose encoded displacement bytes differ
    /// between any two binaries linking the same code at a different
    /// address, and therefore need wildcarding.
    pub has_resolved_target: bool,
}

/// Build a [`Signature`] for one function from its raw bytes and the shape
/// of each instruction covering them (in address order, contiguous,
/// together covering exactly `bytes.len()`). Wildcards the trailing bytes
/// of any [`InsnShape`] with `has_resolved_target` — up to 4 bytes (a
/// `rel32` operand), never more than `len - 1` (the opcode byte itself is
/// always kept concrete) — which covers x86's common `call rel32`/`jmp
/// rel32`/`Jcc rel32` (5–6 byte instruction, 4-byte trailing operand) and
/// `jmp rel8`/`Jcc rel8` (2-byte instruction, 1-byte trailing operand)
/// encodings alike.
pub fn generate_signature(name: &str, bytes: &[u8], ops: &[InsnShape]) -> Signature {
    let mut pattern: Vec<PatternByte> = bytes.iter().map(|b| Some(*b)).collect();
    let mut cursor = 0usize;
    for op in ops {
        let end = (cursor + op.len).min(pattern.len());
        if op.has_resolved_target {
            let wildcard_len = op.len.saturating_sub(1).min(4);
            let start = end.saturating_sub(wildcard_len);
            for slot in pattern.iter_mut().take(end).skip(start) {
                *slot = None;
            }
        }
        cursor = end;
        if cursor >= pattern.len() {
            break;
        }
    }
    Signature {
        name: name.to_string(),
        pattern,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn sig(name: &str, pattern: &[PatternByte]) -> Signature {
        Signature {
            name: name.to_string(),
            pattern: pattern.to_vec(),
        }
    }

    #[test]
    fn matches_exact_bytes_and_respects_wildcards() {
        let s = sig("f", &[Some(0x55), Some(0x48), None, Some(0xc3)]);
        assert!(s.matches(&[0x55, 0x48, 0x89, 0xc3]));
        assert!(s.matches(&[0x55, 0x48, 0x00, 0xc3]));
        assert!(!s.matches(&[0x55, 0x48, 0x89, 0xc4])); // last concrete byte differs
        assert!(!s.matches(&[0x55, 0x48])); // too short
    }

    #[test]
    fn confidence_reflects_wildcard_fraction() {
        let all_concrete = sig("a", &[Some(1), Some(2)]);
        assert_eq!(all_concrete.confidence(), 1.0);
        let half = sig("b", &[Some(1), None]);
        assert_eq!(half.confidence(), 0.5);
        let empty = sig("c", &[]);
        assert_eq!(empty.confidence(), 0.0);
    }

    #[test]
    fn text_round_trips_through_a_database() {
        let mut db = SignatureDatabase::new();
        db.add(sig(
            "push_rbp_mov_rbp_rsp",
            &[Some(0x55), Some(0x48), None, Some(0xc3)],
        ));
        db.add(sig("ret_only", &[Some(0xc3)]));
        let text = db.to_text();
        assert!(text.contains("push_rbp_mov_rbp_rsp\t55 48 ?? c3"));

        let parsed = SignatureDatabase::from_text(&text).expect("parses back");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.match_at(&[0x55, 0x48, 0x89, 0xc3], 0).is_some());
    }

    #[test]
    fn from_text_skips_blank_and_comment_lines() {
        let source = "# a comment\n\nret_only\tc3\n";
        let db = SignatureDatabase::from_text(source).expect("parses");
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn match_at_rejects_a_match_below_the_concrete_byte_threshold() {
        let mut db = SignatureDatabase::new();
        db.add(sig("weak", &[Some(0x90), None, None, None]));
        assert!(db.match_at(&[0x90, 0, 0, 0], 1).is_some());
        assert!(
            db.match_at(&[0x90, 0, 0, 0], 2).is_none(),
            "only one concrete byte, threshold 2 should reject it"
        );
    }

    #[test]
    fn match_at_prefers_the_higher_confidence_signature() {
        let mut db = SignatureDatabase::new();
        db.add(sig("vague", &[Some(0x90), None, None]));
        db.add(sig("precise", &[Some(0x90), Some(0x90), Some(0x90)]));
        let best = db.match_at(&[0x90, 0x90, 0x90], 0).expect("some match");
        assert_eq!(best.name, "precise");
    }

    #[test]
    fn scan_finds_a_signature_at_its_real_offset() {
        let mut db = SignatureDatabase::new();
        db.add(sig(
            "marker",
            &[Some(0xde), Some(0xad), Some(0xbe), Some(0xef)],
        ));
        let haystack = [0x90, 0x90, 0xde, 0xad, 0xbe, 0xef, 0x90];
        let hits = db.scan(&haystack, 4);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 2);
        assert_eq!(hits[0].1.name, "marker");
    }

    /// The exact FLIRT value proposition: the same function, relinked at a
    /// different address, is *not* byte-identical (its `call`'s encoded
    /// `rel32` differs) — but a signature generated with
    /// [`generate_signature`] still recognises it, because the operand
    /// bytes that differ are exactly the ones it wildcards.
    #[test]
    fn generated_signature_recognises_the_same_function_relinked_elsewhere() {
        // push rbp ; mov rbp, rsp ; call rel32 ; pop rbp ; ret
        fn build(rel32: i32) -> Vec<u8> {
            let mut b = vec![0x55, 0x48, 0x89, 0xe5, 0xe8];
            b.extend_from_slice(&rel32.to_le_bytes());
            b.extend_from_slice(&[0x5d, 0xc3]);
            b
        }
        let binary_a = build(0x0000_1234);
        let binary_b = build(-0x0000_4321); // same function, different link layout

        let ops = [
            InsnShape {
                len: 1,
                has_resolved_target: false,
            }, // push rbp
            InsnShape {
                len: 3,
                has_resolved_target: false,
            }, // mov rbp, rsp
            InsnShape {
                len: 5,
                has_resolved_target: true,
            }, // call rel32
            InsnShape {
                len: 1,
                has_resolved_target: false,
            }, // pop rbp
            InsnShape {
                len: 1,
                has_resolved_target: false,
            }, // ret
        ];
        let signature = generate_signature("helper", &binary_a, &ops);

        // The raw bytes genuinely differ (proving this isn't a vacuous test).
        assert_ne!(binary_a, binary_b);
        // A literal byte-for-byte signature (no generation) would reject b.
        let literal = Signature {
            name: "literal".into(),
            pattern: binary_a.iter().map(|b| Some(*b)).collect(),
        };
        assert!(!literal.matches(&binary_b));

        // The generated (wildcarded) signature accepts both.
        assert!(signature.matches(&binary_a));
        assert!(
            signature.matches(&binary_b),
            "wildcarding the call's rel32 should make this match"
        );
        // And it still requires everything else to line up exactly.
        let mut corrupted = binary_b.clone();
        corrupted[0] = 0x90; // not `push rbp` anymore
        assert!(!signature.matches(&corrupted));
    }

    #[test]
    fn generate_signature_wildcards_a_short_rel8_jump_by_one_byte() {
        // jmp rel8 (2 bytes: opcode + 1-byte displacement)
        let bytes = [0xeb, 0x10];
        let ops = [InsnShape {
            len: 2,
            has_resolved_target: true,
        }];
        let signature = generate_signature("short_jmp", &bytes, &ops);
        assert_eq!(signature.pattern, vec![Some(0xeb), None]);
    }
}
