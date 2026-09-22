//! Self-verifying agent execution harness: re-derive ground truth for
//! every factual claim an agent makes about a binary from the same
//! `Engine` it used, independent of whatever the agent said — the
//! automated version of this project's own working discipline ("never
//! fabricate a finding; verify it for real") applied to the agent's own
//! output instead of relying on it to have followed that discipline
//! honestly.
//!
//! # Why this matters for an LLM-driven analysis agent specifically
//!
//! An LLM can state a finding ("function `parse_config` at `0x1400` calls
//! `strcpy` with unchecked user input") that sounds precise and confident
//! while being subtly or entirely wrong — a hallucinated address, a
//! function that doesn't exist, an import that was never actually
//! called. A report full of such claims is worse than no report: it
//! looks verified. [`Harness::run`] re-checks each [`Claim`] against the
//! real [`recurse_static::engine::Engine`] the agent had access to
//! (functions/strings/imports/disassembly are queried the same way
//! whether the harness or the agent asks), and reports which claims are
//! actually backed by the binary — a claim that fails becomes visible as
//! a **failure**, not a silently-accepted line in a report.
//!
//! # Claim kinds
//!
//! [`Claim`] covers the shapes of fact an analysis report typically
//! asserts: a function existing at an address, a string being present, an
//! import being present, an instruction's mnemonic at an address, and —
//! composing with `recurse_static::capa` from earlier in this series — a
//! named capability rule actually matching the binary's real imports and
//! strings, not just being asserted.

use std::collections::BTreeSet;

use recurse_static::capa::Evidence;
use recurse_static::engine::{Engine, Target};

/// One factual claim about a binary, as an agent might state it in a
/// finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Claim {
    /// A function exists at `addr`. `name`, when given, must also match.
    FunctionAt { addr: u64, name: Option<String> },
    /// Some recovered string contains `substring`.
    StringContains { substring: String },
    /// The binary imports a function named `name`.
    ImportPresent { name: String },
    /// The instruction at `addr` starts with `mnemonic` (case-sensitive,
    /// matching how `crate`'s disassembly text is already lowercased by
    /// convention).
    MnemonicAt { addr: u64, mnemonic: String },
    /// A named `recurse_static::capa` rule genuinely matches this
    /// binary's real imports/strings — re-runs the rule, it does not
    /// trust the agent's own "I found capability X" statement.
    CapabilityMatches { rule_name: String },
}

/// The result of checking one [`Claim`] against a real `Engine`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub claim: Claim,
    pub verified: bool,
    /// A short, human-readable reason — what was actually found (or not
    /// found) backing this verdict, e.g. `"3 functions in this binary;
    /// none at 0x1400"`.
    pub evidence: String,
}

/// Verify one [`Claim`] against `engine`. Never panics: an `Engine`
/// method returning `Err` is itself treated as "not verified" (with the
/// error as evidence), not propagated — a harness must always finish and
/// report, not abort partway through a batch of claims because one
/// lookup failed.
#[must_use]
pub fn verify_claim(engine: &dyn Engine, claim: &Claim) -> Verification {
    match claim {
        Claim::FunctionAt { addr, name } => {
            match engine.functions() {
                Ok(functions) => {
                    let found = functions.iter().find(|f| f.addr == *addr);
                    match (found, name) {
                    (Some(f), Some(expected)) if f.name == *expected => {
                        Verification { claim: claim.clone(), verified: true, evidence: format!("found {} at {addr:#x}", f.name) }
                    }
                    (Some(f), Some(expected)) => Verification {
                        claim: claim.clone(),
                        verified: false,
                        evidence: format!("a function exists at {addr:#x} but is named {:?}, not {expected:?}", f.name),
                    },
                    (Some(f), None) => {
                        Verification { claim: claim.clone(), verified: true, evidence: format!("found {} at {addr:#x}", f.name) }
                    }
                    (None, _) => Verification {
                        claim: claim.clone(),
                        verified: false,
                        evidence: format!("{} functions in this binary; none at {addr:#x}", functions.len()),
                    },
                }
                }
                Err(e) => Verification {
                    claim: claim.clone(),
                    verified: false,
                    evidence: format!("functions() failed: {e}"),
                },
            }
        }
        Claim::StringContains { substring } => match engine.strings() {
            Ok(strings) => {
                let hit = strings
                    .iter()
                    .find(|s| s.string.contains(substring.as_str()));
                match hit {
                    Some(s) => Verification {
                        claim: claim.clone(),
                        verified: true,
                        evidence: format!("found in string at {:#x}: {:?}", s.addr, s.string),
                    },
                    None => Verification {
                        claim: claim.clone(),
                        verified: false,
                        evidence: format!(
                            "{} strings recovered; none contain {:?}",
                            strings.len(),
                            substring
                        ),
                    },
                }
            }
            Err(e) => Verification {
                claim: claim.clone(),
                verified: false,
                evidence: format!("strings() failed: {e}"),
            },
        },
        Claim::ImportPresent { name } => match engine.imports() {
            Ok(imports) => {
                if imports.iter().any(|i| i.name == *name) {
                    Verification {
                        claim: claim.clone(),
                        verified: true,
                        evidence: format!("{name} is imported"),
                    }
                } else {
                    Verification {
                        claim: claim.clone(),
                        verified: false,
                        evidence: format!("{} imports; {name} is not one of them", imports.len()),
                    }
                }
            }
            Err(e) => Verification {
                claim: claim.clone(),
                verified: false,
                evidence: format!("imports() failed: {e}"),
            },
        },
        Claim::MnemonicAt { addr, mnemonic } => match engine
            .disassemble(&Target::Addr(*addr), Some(1))
        {
            Ok(disasm) => match disasm.ops.first() {
                Some(insn) if insn.disasm.split_whitespace().next() == Some(mnemonic.as_str()) => {
                    Verification {
                        claim: claim.clone(),
                        verified: true,
                        evidence: format!("{addr:#x}: {}", insn.disasm),
                    }
                }
                Some(insn) => Verification {
                    claim: claim.clone(),
                    verified: false,
                    evidence: format!("{addr:#x} is actually {:?}, not {mnemonic:?}", insn.disasm),
                },
                None => Verification {
                    claim: claim.clone(),
                    verified: false,
                    evidence: format!("no instruction decoded at {addr:#x}"),
                },
            },
            Err(e) => Verification {
                claim: claim.clone(),
                verified: false,
                evidence: format!("disassemble() failed: {e}"),
            },
        },
        Claim::CapabilityMatches { rule_name } => {
            let evidence = evidence_from_engine(engine);
            let rules = recurse_static::capa::built_in_rules();
            let matched = rules
                .evaluate(&evidence)
                .into_iter()
                .any(|r| r.name == *rule_name);
            if matched {
                Verification {
                    claim: claim.clone(),
                    verified: true,
                    evidence: format!("{rule_name} genuinely matches"),
                }
            } else {
                Verification {
                    claim: claim.clone(),
                    verified: false,
                    evidence: format!(
                        "{rule_name} does not match this binary's real imports/strings"
                    ),
                }
            }
        }
    }
}

fn evidence_from_engine(engine: &dyn Engine) -> Evidence {
    let imports: BTreeSet<String> = engine
        .imports()
        .unwrap_or_default()
        .into_iter()
        .map(|i| i.name)
        .collect();
    let strings: Vec<String> = engine
        .strings()
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.string)
        .collect();
    Evidence {
        imports,
        strings,
        ..Evidence::new()
    }
}

/// A batch of claims plus their verification outcomes.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub verifications: Vec<Verification>,
}

impl Report {
    #[must_use]
    pub fn verified_count(&self) -> usize {
        self.verifications.iter().filter(|v| v.verified).count()
    }

    #[must_use]
    pub fn failed(&self) -> Vec<&Verification> {
        self.verifications.iter().filter(|v| !v.verified).collect()
    }

    /// `true` only when every claim verified — the harness's pass/fail
    /// gate for "accept this agent report as-is".
    #[must_use]
    pub fn all_verified(&self) -> bool {
        !self.verifications.is_empty() && self.failed().is_empty()
    }
}

/// Drives [`verify_claim`] over a whole batch of claims from one agent
/// run.
#[derive(Debug, Default)]
pub struct Harness;

impl Harness {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Verify every claim in `claims` against `engine`, in order.
    #[must_use]
    pub fn run(&self, engine: &dyn Engine, claims: &[Claim]) -> Report {
        Report {
            verifications: claims.iter().map(|c| verify_claim(engine, c)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use recurse_static::engine::{
        BackendKind, Capabilities, Decompilation, Disassembly, FunctionGraph, FunctionInfo, Import,
        Instruction, StringRef, Xref, XrefDirection,
    };
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};

    /// A fully in-memory `Engine`, standing in for a real analyzed binary
    /// with a small, fixed set of functions/strings/imports/instructions
    /// — enough to prove `verify_claim`/`Harness` genuinely re-derive
    /// ground truth from `Engine` calls rather than trusting the `Claim`
    /// itself, without needing a real binary fixture for this crate's own
    /// harness logic (the binary-analysis primitives it calls are already
    /// tested with real fixtures elsewhere in this series).
    struct StubEngine {
        path: PathBuf,
    }

    impl Engine for StubEngine {
        fn backend(&self) -> BackendKind {
            BackendKind::Native
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::none()
        }
        fn path(&self) -> &Path {
            &self.path
        }
        fn analyze(&self) -> Result<(), String> {
            Ok(())
        }
        fn summary(&self) -> Result<Value, String> {
            Ok(json!({}))
        }
        fn info(&self) -> Result<Value, String> {
            Ok(json!({}))
        }
        fn functions(&self) -> Result<Vec<FunctionInfo>, String> {
            Ok(vec![FunctionInfo {
                addr: 0x1000,
                name: "main".to_string(),
                size: None,
                nbbs: None,
                edges: None,
                signature: None,
            }])
        }
        fn function_at(&self, _addr: u64) -> Result<Option<FunctionInfo>, String> {
            Ok(None)
        }
        fn disassemble(
            &self,
            target: &Target,
            _count: Option<usize>,
        ) -> Result<Disassembly, String> {
            let addr = match target {
                Target::Addr(a) => *a,
                Target::Symbol(_) => return Err("name resolution not stubbed".to_string()),
            };
            let ops = if addr == 0x1000 {
                vec![Instruction {
                    addr,
                    disasm: "push rbp".to_string(),
                    bytes: None,
                    kind: None,
                    jump: None,
                    fail: None,
                    len: 1,
                }]
            } else {
                vec![]
            };
            Ok(Disassembly {
                addr,
                name: "main".to_string(),
                size: None,
                ops,
            })
        }
        fn function_disasm(&self, addr: u64) -> Result<Disassembly, String> {
            self.disassemble(&Target::Addr(addr), None)
        }
        fn function_graph(&self, addr: u64) -> Result<FunctionGraph, String> {
            Ok(FunctionGraph {
                addr,
                name: "main".to_string(),
                blocks: vec![],
            })
        }
        fn strings(&self) -> Result<Vec<StringRef>, String> {
            Ok(vec![StringRef {
                addr: 0x2000,
                string: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
                kind: None,
            }])
        }
        fn imports(&self) -> Result<Vec<Import>, String> {
            Ok(vec![Import {
                name: "RegSetValueExA".to_string(),
                plt: None,
                bind: None,
                kind: None,
            }])
        }
        fn xrefs(&self, _target: &Target, _direction: XrefDirection) -> Result<Vec<Xref>, String> {
            Ok(vec![])
        }
        fn decompile(&self, _addr: u64) -> Result<Decompilation, String> {
            Err("unsupported".to_string())
        }
        fn raw(&self, _cmd: &str) -> Result<Value, String> {
            Err("unsupported".to_string())
        }
        fn resolve(&self, _name: &str) -> Result<Option<u64>, String> {
            Ok(None)
        }
    }

    fn stub() -> StubEngine {
        StubEngine {
            path: PathBuf::from("stub.exe"),
        }
    }

    #[test]
    fn a_true_function_claim_verifies() {
        let v = verify_claim(
            &stub(),
            &Claim::FunctionAt {
                addr: 0x1000,
                name: Some("main".to_string()),
            },
        );
        assert!(v.verified, "{v:?}");
    }

    #[test]
    fn a_hallucinated_function_address_fails() {
        let v = verify_claim(
            &stub(),
            &Claim::FunctionAt {
                addr: 0xDEAD_BEEF,
                name: Some("evil_fn".to_string()),
            },
        );
        assert!(!v.verified);
        assert!(v.evidence.contains("none at"), "{}", v.evidence);
    }

    #[test]
    fn a_right_address_wrong_name_fails() {
        let v = verify_claim(
            &stub(),
            &Claim::FunctionAt {
                addr: 0x1000,
                name: Some("not_main".to_string()),
            },
        );
        assert!(!v.verified);
        assert!(
            v.evidence.contains("not_main") || v.evidence.contains("main"),
            "{}",
            v.evidence
        );
    }

    #[test]
    fn a_true_string_claim_verifies_and_a_false_one_fails() {
        let ok = verify_claim(
            &stub(),
            &Claim::StringContains {
                substring: "CurrentVersion".to_string(),
            },
        );
        assert!(ok.verified);
        let bad = verify_claim(
            &stub(),
            &Claim::StringContains {
                substring: "does not exist".to_string(),
            },
        );
        assert!(!bad.verified);
    }

    #[test]
    fn a_true_import_claim_verifies_and_a_false_one_fails() {
        let ok = verify_claim(
            &stub(),
            &Claim::ImportPresent {
                name: "RegSetValueExA".to_string(),
            },
        );
        assert!(ok.verified);
        let bad = verify_claim(
            &stub(),
            &Claim::ImportPresent {
                name: "CreateProcessA".to_string(),
            },
        );
        assert!(!bad.verified);
    }

    #[test]
    fn a_true_mnemonic_claim_verifies_and_a_false_one_fails() {
        let ok = verify_claim(
            &stub(),
            &Claim::MnemonicAt {
                addr: 0x1000,
                mnemonic: "push".to_string(),
            },
        );
        assert!(ok.verified);
        let bad = verify_claim(
            &stub(),
            &Claim::MnemonicAt {
                addr: 0x1000,
                mnemonic: "call".to_string(),
            },
        );
        assert!(!bad.verified);
    }

    #[test]
    fn a_capability_claim_re_evaluates_the_real_rule_not_just_the_name() {
        // The stub's imports/strings genuinely satisfy capa's built-in
        // "persist via the Run key" rule (real registry API + real
        // Run-key string) -- this must verify by actually re-running that
        // rule, not by trusting the claim's rule_name alone.
        let ok = verify_claim(
            &stub(),
            &Claim::CapabilityMatches {
                rule_name: "persist via the Run key".to_string(),
            },
        );
        assert!(ok.verified, "{ok:?}");
        let bad = verify_claim(
            &stub(),
            &Claim::CapabilityMatches {
                rule_name: "create process".to_string(),
            },
        );
        assert!(!bad.verified, "{bad:?}");
    }

    #[test]
    fn harness_run_produces_a_report_with_an_accurate_pass_fail_gate() {
        let harness = Harness::new();
        let claims = vec![
            Claim::FunctionAt {
                addr: 0x1000,
                name: Some("main".to_string()),
            },
            Claim::ImportPresent {
                name: "RegSetValueExA".to_string(),
            },
            Claim::ImportPresent {
                name: "totally_hallucinated_import".to_string(),
            },
        ];
        let report = harness.run(&stub(), &claims);
        assert_eq!(report.verified_count(), 2);
        assert_eq!(report.failed().len(), 1);
        assert!(
            !report.all_verified(),
            "one failure must sink the whole batch"
        );
    }

    #[test]
    fn an_all_true_batch_reports_all_verified() {
        let harness = Harness::new();
        let claims = vec![Claim::ImportPresent {
            name: "RegSetValueExA".to_string(),
        }];
        let report = harness.run(&stub(), &claims);
        assert!(report.all_verified());
    }

    #[test]
    fn an_empty_claim_batch_is_not_reported_as_all_verified() {
        // An empty batch trivially satisfying "every claim passed" would
        // let an agent that made *no* verifiable claims at all sail
        // through as a clean report -- explicitly rejected instead.
        let harness = Harness::new();
        let report = harness.run(&stub(), &[]);
        assert!(!report.all_verified());
    }
}
