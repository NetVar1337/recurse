//! Capability detection: a small [capa](https://github.com/mandiant/capa)-class
//! rules engine that turns "this function imports `RegSetValueExA` and the
//! string `\\Software\\Run`" into "this function establishes persistence" —
//! human-readable capability labels instead of a raw import/string list an
//! analyst has to interpret themselves.
//!
//! # Model
//!
//! A [`Rule`] is a name plus a [`Predicate`] tree over [`Feature`]s
//! (import name, string, numeric constant, instruction mnemonic — real
//! capa uses several more feature kinds this module doesn't implement,
//! see honest scope below). [`Predicate`] supports the boolean
//! combinators capa rules use: `and`/`or`/`not`/`at_least` ("N of these
//! M sub-predicates"). [`RuleSet::evaluate`] checks every rule against a
//! caller-built [`Evidence`] snapshot (the imports/strings/numbers/
//! mnemonics a function or file actually contains) and returns every rule
//! that matched.
//!
//! # Decoupled from any particular disassembler
//!
//! Like `crate::diff` and `crate::sig`, this module takes a plain
//! [`Evidence`] value rather than an `Engine` or raw bytes — the caller
//! extracts imports/strings/numbers/mnemonics from whichever backend
//! they're already using. Keeps the *matching engine* (the actual value
//! here) testable with hand-built evidence and reusable across every
//! `Engine` backend.
//!
//! # The built-in rule pack: real API names, not a curated corpus
//!
//! [`built_in_rules`] ships a modest set of rules, each naming real,
//! well-documented Win32 API functions (`CreateProcessA`,
//! `RegSetValueExA`, `VirtualAlloc`, …). This is categorically different
//! from `crate::sig`'s or `crate::winpdb`'s explicit refusal to ship a
//! fabricated "real-world" signature/symbol database: "calling
//! `CreateProcessA` is process-creation capability" is a documented fact
//! about the Win32 API, not an empirical claim about some malware corpus
//! that would need curation to back up. What these rules do *not* claim:
//! that matching one means the binary is malicious, or that this is a
//! complete list of every way to exhibit a capability — both real,
//! stated limits (see each rule's `description` and the module's honest
//! scope section).

use std::collections::{BTreeMap, BTreeSet};

/// One fact the evaluator can check for.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Feature {
    /// An imported function name (bare, e.g. `"CreateProcessA"` — no
    /// module qualifier, matching how `crate::engine`'s import lists are
    /// already shaped).
    Import(String),
    /// A substring of any extracted string.
    String(String),
    /// A numeric constant appearing in the evidence (an immediate
    /// operand, typically).
    Number(u64),
    /// An instruction mnemonic appears at least once (e.g. `"xor"`,
    /// `"rdtsc"`).
    Mnemonic(String),
    /// An instruction mnemonic appears at least `n` times — genuine
    /// repetition counting, distinct from [`Feature::Mnemonic`]'s plain
    /// presence check (see [`Predicate::AtLeast`]'s doc for why that
    /// distinction matters: `AtLeast` counts true *sub-predicates*, not
    /// occurrences within one feature).
    MnemonicCount(String, usize),
}

/// A boolean combinator tree over [`Feature`]s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    Feature(Feature),
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
    /// True when at least `n` of `predicates` are true — capa's "N or
    /// more" construct, for rules like "uses at least 2 of these 3
    /// anti-debug checks".
    AtLeast(usize, Vec<Predicate>),
}

impl Predicate {
    #[must_use]
    pub fn feature(f: Feature) -> Self {
        Predicate::Feature(f)
    }

    #[must_use]
    pub fn import(name: impl Into<String>) -> Self {
        Predicate::Feature(Feature::Import(name.into()))
    }

    #[must_use]
    pub fn string(s: impl Into<String>) -> Self {
        Predicate::Feature(Feature::String(s.into()))
    }

    #[must_use]
    pub fn mnemonic(m: impl Into<String>) -> Self {
        Predicate::Feature(Feature::Mnemonic(m.into()))
    }

    #[must_use]
    pub fn mnemonic_count_at_least(m: impl Into<String>, n: usize) -> Self {
        Predicate::Feature(Feature::MnemonicCount(m.into(), n))
    }

    #[must_use]
    pub fn number(n: u64) -> Self {
        Predicate::Feature(Feature::Number(n))
    }

    fn eval(&self, evidence: &Evidence) -> bool {
        match self {
            Predicate::Feature(Feature::Import(name)) => evidence.imports.contains(name.as_str()),
            Predicate::Feature(Feature::Mnemonic(m)) => {
                evidence.mnemonic_counts.contains_key(m.as_str())
            }
            Predicate::Feature(Feature::MnemonicCount(m, n)) => {
                evidence
                    .mnemonic_counts
                    .get(m.as_str())
                    .copied()
                    .unwrap_or(0)
                    >= *n
            }
            Predicate::Feature(Feature::Number(n)) => evidence.numbers.contains(n),
            Predicate::Feature(Feature::String(needle)) => {
                evidence.strings.iter().any(|s| s.contains(needle.as_str()))
            }
            Predicate::And(subs) => subs.iter().all(|p| p.eval(evidence)),
            Predicate::Or(subs) => subs.iter().any(|p| p.eval(evidence)),
            Predicate::Not(sub) => !sub.eval(evidence),
            Predicate::AtLeast(n, subs) => subs.iter().filter(|p| p.eval(evidence)).count() >= *n,
        }
    }
}

/// What a rule matched against: imports, strings, numeric constants, and
/// mnemonic occurrence counts a function (or a whole file) actually
/// contains, gathered by the caller from whichever backend they're
/// already using.
#[derive(Clone, Debug, Default)]
pub struct Evidence {
    pub imports: BTreeSet<String>,
    pub strings: Vec<String>,
    pub numbers: BTreeSet<u64>,
    /// Mnemonic -> number of times it occurs, so rules can distinguish
    /// "appears at all" ([`Feature::Mnemonic`]) from "appears at least N
    /// times" ([`Feature::MnemonicCount`]).
    pub mnemonic_counts: BTreeMap<String, usize>,
}

impl Evidence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_imports(mut self, imports: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.imports.extend(imports.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn with_strings(mut self, strings: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.strings.extend(strings.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn with_numbers(mut self, numbers: impl IntoIterator<Item = u64>) -> Self {
        self.numbers.extend(numbers);
        self
    }

    /// Add mnemonic occurrences. Each item in `mnemonics` counts as one
    /// occurrence, so passing the same mnemonic `n` times (as a real
    /// disassembly listing naturally would, once per instruction) builds
    /// up its count correctly — this is a multiset, not a plain set.
    #[must_use]
    pub fn with_mnemonics(
        mut self,
        mnemonics: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        for m in mnemonics {
            *self.mnemonic_counts.entry(m.into()).or_insert(0) += 1;
        }
        self
    }
}

/// One capability rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub namespace: String,
    pub description: String,
    pub predicate: Predicate,
}

impl Rule {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        description: impl Into<String>,
        predicate: Predicate,
    ) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            description: description.into(),
            predicate,
        }
    }
}

/// A collection of [`Rule`]s, evaluated together against one [`Evidence`].
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Every rule whose predicate is true against `evidence`, in
    /// declaration order.
    #[must_use]
    pub fn evaluate<'a>(&'a self, evidence: &Evidence) -> Vec<&'a Rule> {
        self.rules
            .iter()
            .filter(|r| r.predicate.eval(evidence))
            .collect()
    }
}

/// A modest, hand-authored rule pack over real, documented Win32 API
/// names — see the module doc's "built-in rule pack" section for what
/// this does and does not claim.
#[must_use]
pub fn built_in_rules() -> RuleSet {
    let mut rules = RuleSet::new();

    rules.add(Rule::new(
        "create process",
        "process/create",
        "Starts a new process (CreateProcess family).",
        Predicate::Or(vec![
            Predicate::import("CreateProcessA"),
            Predicate::import("CreateProcessW"),
        ]),
    ));
    rules.add(Rule::new(
        "create thread",
        "process/create-thread",
        "Starts a new thread in the current process.",
        Predicate::Or(vec![
            Predicate::import("CreateThread"),
            Predicate::import("CreateRemoteThread"),
        ]),
    ));
    rules.add(Rule::new(
        "inject into a remote process",
        "process/inject",
        "Allocates and writes memory in another process and starts execution there \
         (VirtualAllocEx/WriteProcessMemory plus a remote-thread or APC primitive) \
         -- the classic process-injection shape, not a specific injection technique.",
        Predicate::And(vec![
            Predicate::import("VirtualAllocEx"),
            Predicate::import("WriteProcessMemory"),
            Predicate::Or(vec![
                Predicate::import("CreateRemoteThread"),
                Predicate::import("QueueUserAPC"),
            ]),
        ]),
    ));
    rules.add(Rule::new(
        "read/write the registry",
        "host-interaction/registry",
        "Opens and reads or writes a registry value.",
        Predicate::And(vec![
            Predicate::Or(vec![
                Predicate::import("RegOpenKeyExA"),
                Predicate::import("RegOpenKeyExW"),
            ]),
            Predicate::Or(vec![
                Predicate::import("RegSetValueExA"),
                Predicate::import("RegSetValueExW"),
                Predicate::import("RegQueryValueExA"),
                Predicate::import("RegQueryValueExW"),
            ]),
        ]),
    ));
    rules.add(Rule::new(
        "persist via the Run key",
        "persistence/registry-run-key",
        "Writes a registry value under a well-known auto-run key path.",
        Predicate::And(vec![
            Predicate::Or(vec![
                Predicate::import("RegSetValueExA"),
                Predicate::import("RegSetValueExW"),
            ]),
            Predicate::Or(vec![
                Predicate::string(r"\Software\Microsoft\Windows\CurrentVersion\Run"),
                Predicate::string(r"CurrentVersion\Run"),
            ]),
        ]),
    ));
    rules.add(Rule::new(
        "read/write files",
        "host-interaction/file-system",
        "Opens a file and reads or writes its contents.",
        Predicate::And(vec![
            Predicate::import("CreateFileA").or(Predicate::import("CreateFileW")),
            Predicate::import("ReadFile").or(Predicate::import("WriteFile")),
        ]),
    ));
    rules.add(Rule::new(
        "http communication",
        "communication/http",
        "Opens an HTTP connection (WinINet or WinHTTP).",
        Predicate::Or(vec![
            Predicate::import("InternetOpenA"),
            Predicate::import("InternetOpenW"),
            Predicate::import("WinHttpOpen"),
            Predicate::import("HttpSendRequestA"),
            Predicate::import("WinHttpSendRequest"),
        ]),
    ));
    rules.add(Rule::new(
        "raw sockets",
        "communication/socket",
        "Uses the Winsock API directly rather than a higher-level HTTP client.",
        Predicate::And(vec![
            Predicate::import("WSAStartup"),
            Predicate::Or(vec![
                Predicate::import("connect"),
                Predicate::import("send"),
                Predicate::import("recv"),
            ]),
        ]),
    ));
    rules.add(Rule::new(
        "encrypt/decrypt data",
        "data-manipulation/encryption",
        "Uses CryptoAPI (CryptEncrypt/CryptDecrypt) or an equivalent CNG call.",
        Predicate::Or(vec![
            Predicate::import("CryptEncrypt"),
            Predicate::import("CryptDecrypt"),
            Predicate::import("BCryptEncrypt"),
            Predicate::import("BCryptDecrypt"),
        ]),
    ));
    rules.add(Rule::new(
        "check for a debugger",
        "anti-analysis/anti-debugging",
        "Calls a well-known debugger-presence check.",
        Predicate::Or(vec![
            Predicate::import("IsDebuggerPresent"),
            Predicate::import("CheckRemoteDebuggerPresent"),
            Predicate::import("NtQueryInformationProcess"),
        ]),
    ));
    rules.add(Rule::new(
        "timing-based anti-debug/anti-emulation",
        "anti-analysis/anti-debugging",
        "Reads the CPU timestamp counter directly, a common building block for \
         detecting a debugger's or emulator's single-step overhead.",
        Predicate::mnemonic("rdtsc"),
    ));
    rules.add(Rule::new(
        "allocate executable memory",
        "process/executable-memory",
        "Allocates memory with an executable protection flag -- a common shellcode \
         or unpacking-stage building block (also see `inject into a remote process` \
         for the cross-process variant).",
        Predicate::Or(vec![
            Predicate::import("VirtualAlloc"),
            Predicate::import("VirtualAllocEx"),
        ]),
    ));
    rules.add(Rule::new(
        "dynamically resolve APIs",
        "linking/dynamic-resolution",
        "Resolves function addresses at runtime (GetProcAddress) rather than through \
         the normal import table -- a common way to hide which APIs a binary actually \
         uses from static import-table inspection alone.",
        Predicate::And(vec![
            Predicate::import("LoadLibraryA").or(Predicate::import("LoadLibraryW")),
            Predicate::import("GetProcAddress"),
        ]),
    ));
    rules.add(Rule::new(
        "xor-based obfuscation",
        "data-manipulation/obfuscation",
        "Uses XOR (a common lightweight string/config obfuscation primitive) at \
         least twice in the same scope -- a single XOR is far too common an \
         instruction on its own to be meaningful signal.",
        Predicate::mnemonic_count_at_least("xor", 2),
    ));

    rules
}

// A tiny combinator so the built-in rule pack above reads left-to-right
// (`a.or(b)`) instead of nesting `Predicate::Or(vec![a, b])` everywhere.
impl Predicate {
    #[must_use]
    pub fn or(self, other: Predicate) -> Predicate {
        Predicate::Or(vec![self, other])
    }

    #[must_use]
    pub fn and(self, other: Predicate) -> Predicate {
        Predicate::And(vec![self, other])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn feature_predicates_match_their_own_evidence_kind_only() {
        let evidence = Evidence::new()
            .with_imports(["CreateProcessA"])
            .with_strings(["hello world"])
            .with_numbers([42])
            .with_mnemonics(["xor"]);
        assert!(Predicate::import("CreateProcessA").eval(&evidence));
        assert!(!Predicate::import("CreateProcessW").eval(&evidence));
        assert!(Predicate::string("hello").eval(&evidence));
        assert!(!Predicate::string("goodbye").eval(&evidence));
        assert!(Predicate::number(42).eval(&evidence));
        assert!(!Predicate::number(43).eval(&evidence));
        assert!(Predicate::mnemonic("xor").eval(&evidence));
        assert!(!Predicate::mnemonic("add").eval(&evidence));
    }

    #[test]
    fn and_requires_every_sub_predicate() {
        let evidence = Evidence::new().with_imports(["A"]);
        assert!(!Predicate::import("A")
            .and(Predicate::import("B"))
            .eval(&evidence));
        let evidence2 = Evidence::new().with_imports(["A", "B"]);
        assert!(Predicate::import("A")
            .and(Predicate::import("B"))
            .eval(&evidence2));
    }

    #[test]
    fn or_requires_any_sub_predicate() {
        let evidence = Evidence::new().with_imports(["B"]);
        assert!(Predicate::import("A")
            .or(Predicate::import("B"))
            .eval(&evidence));
        let evidence2 = Evidence::new().with_imports(["C"]);
        assert!(!Predicate::import("A")
            .or(Predicate::import("B"))
            .eval(&evidence2));
    }

    #[test]
    fn not_inverts() {
        let evidence = Evidence::new().with_imports(["A"]);
        assert!(!Predicate::Not(Box::new(Predicate::import("A"))).eval(&evidence));
        assert!(Predicate::Not(Box::new(Predicate::import("B"))).eval(&evidence));
    }

    #[test]
    fn at_least_counts_true_sub_predicates() {
        let evidence = Evidence::new().with_mnemonics(["xor", "add"]);
        let two_of_three = Predicate::AtLeast(
            2,
            vec![
                Predicate::mnemonic("xor"),
                Predicate::mnemonic("add"),
                Predicate::mnemonic("sub"),
            ],
        );
        assert!(two_of_three.eval(&evidence));
        let three_of_three = Predicate::AtLeast(
            3,
            vec![
                Predicate::mnemonic("xor"),
                Predicate::mnemonic("add"),
                Predicate::mnemonic("sub"),
            ],
        );
        assert!(!three_of_three.eval(&evidence));
    }

    #[test]
    fn ruleset_evaluate_returns_only_matching_rules_in_order() {
        let mut set = RuleSet::new();
        set.add(Rule::new("has a", "test", "", Predicate::import("A")));
        set.add(Rule::new("has b", "test", "", Predicate::import("B")));
        set.add(Rule::new("has c", "test", "", Predicate::import("C")));
        let evidence = Evidence::new().with_imports(["A", "C"]);
        let matched: Vec<&str> = set
            .evaluate(&evidence)
            .into_iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(matched, vec!["has a", "has c"]);
    }

    #[test]
    fn built_in_process_injection_rule_needs_all_three_apis() {
        let rules = built_in_rules();
        let injection = rules
            .rules
            .iter()
            .find(|r| r.name == "inject into a remote process")
            .expect("rule present");

        let partial = Evidence::new().with_imports(["VirtualAllocEx", "WriteProcessMemory"]);
        assert!(
            !injection.predicate.eval(&partial),
            "missing the remote-execution primitive"
        );

        let complete = Evidence::new().with_imports([
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ]);
        assert!(injection.predicate.eval(&complete));
    }

    #[test]
    fn built_in_persistence_rule_needs_both_the_api_and_the_run_key_string() {
        let rules = built_in_rules();
        let persist = rules
            .rules
            .iter()
            .find(|r| r.name == "persist via the Run key")
            .expect("rule present");

        let api_only = Evidence::new().with_imports(["RegSetValueExA"]);
        assert!(!persist.predicate.eval(&api_only));

        let both = Evidence::new()
            .with_imports(["RegSetValueExA"])
            .with_strings([r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]);
        assert!(persist.predicate.eval(&both));
    }

    #[test]
    fn built_in_xor_obfuscation_rule_needs_at_least_two_real_occurrences_not_one() {
        let rules = built_in_rules();
        let xor_rule = rules
            .rules
            .iter()
            .find(|r| r.name == "xor-based obfuscation")
            .expect("rule present");
        let one_xor = Evidence::new().with_mnemonics(["xor"]);
        assert!(
            !xor_rule.predicate.eval(&one_xor),
            "a single xor must not be enough"
        );
        let two_xor = Evidence::new().with_mnemonics(["xor", "xor"]);
        assert!(xor_rule.predicate.eval(&two_xor));
        let no_xor = Evidence::new().with_mnemonics(["add"]);
        assert!(!xor_rule.predicate.eval(&no_xor));
    }

    #[test]
    fn mnemonic_count_is_a_genuine_multiset_not_a_presence_flag() {
        // Passing the same mnemonic 3 times (as a real disassembly
        // listing would, once per matching instruction) must build up a
        // real count of 3, not collapse to "present" the way a
        // `BTreeSet` would.
        let evidence = Evidence::new().with_mnemonics(["xor", "xor", "xor"]);
        assert!(Predicate::mnemonic_count_at_least("xor", 3).eval(&evidence));
        assert!(!Predicate::mnemonic_count_at_least("xor", 4).eval(&evidence));
        assert!(
            Predicate::mnemonic("xor").eval(&evidence),
            "plain presence check still works"
        );
    }

    #[test]
    fn evidence_evaluates_against_an_empty_ruleset_without_panicking() {
        let set = RuleSet::new();
        assert!(set.evaluate(&Evidence::new()).is_empty());
    }
}
