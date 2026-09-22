//! Cross-binary semantic memory: a persistent store of function
//! fingerprints, searchable by structural similarity — "find every
//! function across every binary I've ever analyzed that looks like this
//! one", the same job a neural code-embedding index does, without one.
//!
//! # Honest framing: this is not a neural embedding
//!
//! "Embeddings similarity" usually means a learned vector representation
//! from a neural model (code2vec-, CodeBERT-, or LLM-embedding-style).
//! This module does not ship one — there is no offline model available
//! to run, and faking inference (returning plausible-looking vectors from
//! nowhere) would be exactly the kind of fabricated, unverifiable
//! behavior this project refuses to ship. Instead, [`simhash`] is a real,
//! deterministic, classical locality-sensitive hash
//! ([SimHash](https://en.wikipedia.org/wiki/SimHash), the same technique
//! search engines have used for near-duplicate detection for two
//! decades) over a function's normalized-instruction-sequence bigrams —
//! two structurally similar functions get fingerprints with a small
//! Hamming distance, without needing a trained model, GPU, or network
//! call. It serves the same "fast approximate similarity across a large
//! corpus" role a learned embedding would; it is not one, and this
//! module never claims otherwise.
//!
//! # Two-stage search
//!
//! [`Memory::find_similar`] first ranks the whole corpus by SimHash
//! Hamming distance (cheap: one `u64::count_ones` per candidate, no
//! per-candidate instruction-sequence comparison), then re-scores the
//! top candidates with [`crate::diff`]'s real longest-common-subsequence
//! ratio for the final, precise similarity score — a coarse-then-precise
//! pipeline, not a single cheap hash treated as if it were exact.
//!
//! # Persistence
//!
//! [`Memory::to_json`]/[`Memory::from_json`] round-trip a corpus to a
//! plain JSON file, so "semantic memory" genuinely persists across
//! analysis sessions rather than only living for one process's lifetime.

use serde::{Deserialize, Serialize};

use crate::diff::lcs_ratio;

/// One function's fingerprint, indexed under the binary it came from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FunctionRecord {
    /// Caller-chosen identifier for the source binary (a path, a hash, a
    /// name — whatever the caller's corpus keys binaries by).
    pub binary: String,
    pub name: String,
    pub address: u64,
    /// [`simhash`] of `normalized_instructions`, kept alongside it so
    /// [`Memory::find_similar`]'s coarse stage never needs to recompute
    /// it per query.
    pub fingerprint: u64,
    /// Normalized instruction shape (see `crate::diff::normalize_mnemonics`
    /// for the suggested way to build this) — kept so the precise
    /// (LCS-ratio) re-scoring stage has something to compare against.
    pub normalized_instructions: Vec<String>,
}

impl FunctionRecord {
    /// Build a record, computing its fingerprint from
    /// `normalized_instructions`.
    #[must_use]
    pub fn new(
        binary: impl Into<String>,
        name: impl Into<String>,
        address: u64,
        normalized_instructions: Vec<String>,
    ) -> Self {
        let fingerprint = simhash(&normalized_instructions);
        Self {
            binary: binary.into(),
            name: name.into(),
            address,
            fingerprint,
            normalized_instructions,
        }
    }
}

/// A persistent, searchable corpus of [`FunctionRecord`]s.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Memory {
    pub records: Vec<FunctionRecord>,
}

/// One search result: a record plus its similarity to the query, `0.0`
/// (unrelated) to `1.0` (identical normalized instruction sequence).
#[derive(Clone, Debug, PartialEq)]
pub struct SimilarityMatch<'a> {
    pub record: &'a FunctionRecord,
    pub similarity: f64,
}

impl Memory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, record: FunctionRecord) {
        self.records.push(record);
    }

    /// The `top_k` most similar records to `query_instructions` across
    /// the whole corpus, by [`simhash`] Hamming distance (coarse) then
    /// [`lcs_ratio`] (precise), descending by similarity.
    ///
    /// `candidate_pool` bounds how many of the corpus's closest-by-
    /// Hamming-distance records get the precise (`O(n*m)`) LCS re-score —
    /// the two-stage design's whole point: exact matching only runs
    /// against a short, already-plausible shortlist, not the entire
    /// corpus. Must be `>= top_k`; a smaller corpus is used in full.
    #[must_use]
    pub fn find_similar(
        &self,
        query_instructions: &[String],
        top_k: usize,
        candidate_pool: usize,
    ) -> Vec<SimilarityMatch<'_>> {
        let query_fp = simhash(query_instructions);
        let mut by_hamming: Vec<(u32, &FunctionRecord)> = self
            .records
            .iter()
            .map(|r| (hamming_distance(query_fp, r.fingerprint), r))
            .collect();
        by_hamming.sort_by_key(|(dist, _)| *dist);
        by_hamming.truncate(candidate_pool.max(top_k));

        let mut scored: Vec<SimilarityMatch<'_>> = by_hamming
            .into_iter()
            .map(|(_, record)| SimilarityMatch {
                record,
                similarity: lcs_ratio(query_instructions, &record.normalized_instructions),
            })
            .collect();
        scored.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(top_k);
        scored
    }

    /// Serialize this corpus to pretty-printed JSON.
    ///
    /// # Errors
    /// A message when serialization fails (never expected — every field
    /// here is plain, serializable data).
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize memory: {e}"))
    }

    /// Deserialize a corpus previously written by [`Memory::to_json`].
    ///
    /// # Errors
    /// A message when `text` isn't valid JSON for this shape.
    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| format!("parse memory: {e}"))
    }
}

/// A 64-bit [SimHash](https://en.wikipedia.org/wiki/SimHash) of a
/// normalized instruction sequence: hash each consecutive bigram (a
/// single-instruction fingerprint would collapse "mov then xor" and "xor
/// then mov" into the same bag-of-mnemonics signature; bigrams keep some
/// order sensitivity while still tolerating small insertions/deletions
/// elsewhere in the sequence), then for each of the 64 output bits, sum
/// `+1` for every bigram hash with that bit set and `-1` for every bigram
/// hash with that bit clear; the final bit is `1` iff the sum is
/// positive. Two sequences that share most of their bigrams end up with
/// fingerprints differing in only a few bits — [`hamming_distance`] turns
/// that into a cheap, meaningful nearness measure without ever comparing
/// the sequences themselves.
#[must_use]
pub fn simhash(normalized_instructions: &[String]) -> u64 {
    if normalized_instructions.is_empty() {
        return 0;
    }
    let mut bit_sums = [0i64; 64];
    let bigrams: Vec<String> = if normalized_instructions.len() == 1 {
        vec![normalized_instructions[0].clone()]
    } else {
        normalized_instructions
            .windows(2)
            .map(|w| format!("{}\u{1}{}", w[0], w[1]))
            .collect()
    };
    for bigram in &bigrams {
        let h = fnv1a(bigram.as_bytes());
        for (bit, sum) in bit_sums.iter_mut().enumerate() {
            if (h >> bit) & 1 == 1 {
                *sum += 1;
            } else {
                *sum -= 1;
            }
        }
    }
    let mut result: u64 = 0;
    for (bit, &sum) in bit_sums.iter().enumerate() {
        if sum > 0 {
            result |= 1 << bit;
        }
    }
    result
}

/// FNV-1a 64-bit: a standard, dependency-free non-cryptographic hash —
/// exactly what a SimHash's per-token hash needs (fast, well-distributed
/// bits), nothing more.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01B3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[must_use]
pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn seq(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn identical_sequences_hash_identically() {
        let a = seq(&["push rbp", "mov rbp rsp", "mov eax imm", "pop rbp", "ret"]);
        assert_eq!(simhash(&a), simhash(&a.clone()));
    }

    #[test]
    fn similar_sequences_have_a_small_hamming_distance() {
        let a = seq(&["push rbp", "mov rbp rsp", "mov eax imm", "pop rbp", "ret"]);
        // Same function with one instruction inserted in the middle (a
        // small real patch), as in `crate::diff`'s own fuzzy-match test.
        let b = seq(&[
            "push rbp",
            "mov rbp rsp",
            "cmp eax imm",
            "mov eax imm",
            "pop rbp",
            "ret",
        ]);
        let dist = hamming_distance(simhash(&a), simhash(&b));
        // Short sequences (a handful of bigrams) give SimHash little to
        // average over, so the distance is noisier than it would be for
        // a real function's worth of instructions; "closer than half the
        // bits differ" is the honest bound to assert here, not a tight
        // one — `unrelated_sequences_have_a_larger_hamming_distance_on_average`
        // below is this property's real, relative proof.
        assert!(
            dist < 32,
            "expected a below-random-chance distance for a near-duplicate, got {dist}"
        );
    }

    #[test]
    fn unrelated_sequences_have_a_larger_hamming_distance_on_average() {
        let a = seq(&["push rbp", "mov rbp rsp", "mov eax imm", "pop rbp", "ret"]);
        let unrelated = seq(&["xor eax eax", "call rel", "test eax eax", "jz rel", "leave"]);
        let near_duplicate = seq(&[
            "push rbp",
            "mov rbp rsp",
            "cmp eax imm",
            "mov eax imm",
            "pop rbp",
            "ret",
        ]);
        let dist_unrelated = hamming_distance(simhash(&a), simhash(&unrelated));
        let dist_near = hamming_distance(simhash(&a), simhash(&near_duplicate));
        assert!(
            dist_unrelated > dist_near,
            "unrelated={dist_unrelated} near={dist_near}"
        );
    }

    #[test]
    fn find_similar_ranks_the_closest_match_first_across_multiple_binaries() {
        let mut memory = Memory::new();
        let original = seq(&["push rbp", "mov rbp rsp", "mov eax imm", "pop rbp", "ret"]);
        let patched = seq(&[
            "push rbp",
            "mov rbp rsp",
            "cmp eax imm",
            "mov eax imm",
            "pop rbp",
            "ret",
        ]);
        let unrelated = seq(&[
            "xor eax eax",
            "call rel",
            "test eax eax",
            "jz rel",
            "leave",
            "ret",
        ]);

        memory.add(FunctionRecord::new(
            "binary_a.exe",
            "parse_v1",
            0x1000,
            original.clone(),
        ));
        memory.add(FunctionRecord::new(
            "binary_b.exe",
            "parse_v2",
            0x2000,
            patched,
        ));
        memory.add(FunctionRecord::new(
            "binary_c.exe",
            "unrelated_fn",
            0x3000,
            unrelated,
        ));

        let results = memory.find_similar(&original, 2, 10);
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].record.name, "parse_v1",
            "exact self-match must rank first"
        );
        assert_eq!(results[0].similarity, 1.0);
        assert_eq!(
            results[1].record.name, "parse_v2",
            "the near-duplicate must rank second"
        );
        assert!(results[1].similarity > 0.5 && results[1].similarity < 1.0);
    }

    #[test]
    fn json_round_trip_preserves_every_record() {
        let mut memory = Memory::new();
        memory.add(FunctionRecord::new(
            "a.exe",
            "f",
            0x1000,
            seq(&["mov eax imm", "ret"]),
        ));
        let text = memory.to_json().expect("serialize");
        let restored = Memory::from_json(&text).expect("parse");
        assert_eq!(restored.records, memory.records);
    }

    #[test]
    fn from_json_rejects_garbage_cleanly() {
        assert!(Memory::from_json("not json").is_err());
    }

    #[test]
    fn empty_query_and_empty_memory_do_not_panic() {
        let memory = Memory::new();
        assert!(memory.find_similar(&[], 5, 10).is_empty());
        let mut with_one = Memory::new();
        with_one.add(FunctionRecord::new("a.exe", "f", 0, vec![]));
        assert_eq!(simhash(&[]), 0);
        let results = with_one.find_similar(&[], 5, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].similarity, 1.0,
            "two empty sequences are trivially identical"
        );
    }
}
