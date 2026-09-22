//! Automatic finding/report generation: turn structured analysis output
//! (capability matches, verified claims, or any other caller-built
//! [`Finding`]) into one coherent Markdown report — deterministic,
//! algorithmic document assembly, not LLM-generated narrative text.
//!
//! # Why algorithmic, not LLM-generated
//!
//! An LLM call to "write up these findings nicely" is unverifiable and
//! non-deterministic — this project's own standard (real, tested,
//! reproducible output) rules it out as the mechanism here. [`ReportDoc`]
//! instead assembles a plain, structured document from data every field
//! of which traces back to something a caller already computed and can
//! point to: `crate::verify`'s pass/fail claims, `recurse_static::capa`'s
//! rule matches, or any other analysis this project's earlier modules
//! produce. "Automatic" means "no human hand-assembling Markdown
//! sections", not "written by a model with no ground truth behind it".
//!
//! # Composes with `crate::verify` and `recurse_static::capa`
//!
//! [`ReportDoc::from_verification`] builds a report directly from a
//! `crate::verify::Report`: every *verified* claim becomes a confirmed
//! [`Finding`]; every failed claim is kept, visibly, in an
//! [`ReportDoc::unconfirmed`] section instead of being silently dropped
//! — a report that hides what it couldn't confirm is exactly the kind of
//! overclaiming this whole series has refused to ship.
//! [`capability_findings`] turns `recurse_static::capa::Rule` matches
//! into [`Finding`]s with a namespace-derived [`Severity`].

use crate::verify::Report as VerificationReport;

/// A rough severity band, deterministically derived from where a finding
/// came from (see [`severity_for_capa_namespace`]) — not a claim about
/// real-world exploitability, which needs a human (or a much deeper
/// analysis) to judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }
}

/// One reportable fact: a title, a severity, a description, and the
/// concrete evidence backing it (never just an assertion).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub description: String,
    /// Concrete evidence strings (an address, a matched string/import, a
    /// verification's own evidence text, …) — a `Finding` with empty
    /// evidence is a bare assertion, not a finding; callers are expected
    /// to always populate this.
    pub evidence: Vec<String>,
    pub address: Option<u64>,
}

impl Finding {
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            severity,
            description: description.into(),
            evidence: Vec::new(),
            address: None,
        }
    }

    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    #[must_use]
    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}

/// A complete report for one binary.
#[derive(Clone, Debug, Default)]
pub struct ReportDoc {
    pub binary: String,
    pub findings: Vec<Finding>,
    /// Claims/checks that were attempted but could not be confirmed —
    /// kept visible rather than silently dropped (see module docs).
    pub unconfirmed: Vec<String>,
}

impl ReportDoc {
    #[must_use]
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
            findings: Vec::new(),
            unconfirmed: Vec::new(),
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn add_unconfirmed(&mut self, description: impl Into<String>) {
        self.unconfirmed.push(description.into());
    }

    /// Build a report entirely from a `crate::verify::Report`: every
    /// verified claim becomes a confirmed [`Finding`] (severity `Info` —
    /// verification confirms a *fact*, not a risk judgment); every failed
    /// claim goes to [`ReportDoc::unconfirmed`] instead of being dropped.
    #[must_use]
    pub fn from_verification(binary: impl Into<String>, report: &VerificationReport) -> Self {
        let mut doc = Self::new(binary);
        for v in &report.verifications {
            if v.verified {
                let mut finding = Finding::new(
                    format!("{:?}", v.claim),
                    Severity::Info,
                    "Verified against the analyzed binary.",
                )
                .with_evidence(v.evidence.clone());
                if let crate::verify::Claim::FunctionAt { addr, .. }
                | crate::verify::Claim::MnemonicAt { addr, .. } = &v.claim
                {
                    finding = finding.with_address(*addr);
                }
                doc.add(finding);
            } else {
                doc.add_unconfirmed(format!("{:?} -- {}", v.claim, v.evidence));
            }
        }
        doc
    }

    /// Render this report as Markdown: an H1 title, findings grouped by
    /// descending severity (each with its evidence as a bullet list), and
    /// — only when non-empty — an "Unconfirmed" section at the end.
    /// Deterministic: the same `ReportDoc` always renders to the same
    /// text (findings/evidence are never reordered non-deterministically;
    /// grouping is a stable sort by severity, preserving each severity
    /// band's original insertion order).
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# Findings: {}\n\n", self.binary));

        if self.findings.is_empty() {
            out.push_str("No confirmed findings.\n\n");
        } else {
            let mut by_severity = self.findings.clone();
            by_severity.sort_by_key(|f| std::cmp::Reverse(f.severity));
            let mut current: Option<Severity> = None;
            for finding in &by_severity {
                if current != Some(finding.severity) {
                    out.push_str(&format!("## {}\n\n", finding.severity.label()));
                    current = Some(finding.severity);
                }
                out.push_str(&format!("### {}\n\n", finding.title));
                out.push_str(&format!("{}\n\n", finding.description));
                if let Some(addr) = finding.address {
                    out.push_str(&format!("- Address: `{addr:#x}`\n"));
                }
                for e in &finding.evidence {
                    out.push_str(&format!("- {e}\n"));
                }
                out.push('\n');
            }
        }

        if !self.unconfirmed.is_empty() {
            out.push_str("## Unconfirmed\n\n");
            out.push_str("Claims checked but not backed by the analyzed binary:\n\n");
            for u in &self.unconfirmed {
                out.push_str(&format!("- {u}\n"));
            }
            out.push('\n');
        }

        out
    }
}

/// The rule-namespace-to-severity mapping [`capability_findings`] uses —
/// a real, if simple, deterministic heuristic (namespace prefix match),
/// documented as such rather than presented as a risk-scoring model.
#[must_use]
pub fn severity_for_capa_namespace(namespace: &str) -> Severity {
    if namespace.starts_with("process/inject")
        || namespace.starts_with("anti-analysis")
        || namespace.starts_with("persistence")
    {
        Severity::Medium
    } else if namespace.starts_with("process/")
        || namespace.starts_with("linking/dynamic-resolution")
    {
        Severity::Low
    } else {
        Severity::Info
    }
}

/// Turn a list of matched `recurse_static::capa::Rule`s into `Finding`s.
/// Takes `(name, namespace, description)` tuples rather than borrowing
/// `capa::Rule` directly, so this crate does not need `capa` module
/// internals beyond what it already re-exports through `recurse_static`
/// — the same decoupled, caller-wires-in-already-resolved-data shape
/// `crate::verify`'s own `Claim` variants use.
#[must_use]
pub fn capability_findings(matches: &[(&str, &str, &str)]) -> Vec<Finding> {
    matches
        .iter()
        .map(|(name, namespace, description)| {
            Finding::new(
                (*name).to_string(),
                severity_for_capa_namespace(namespace),
                (*description).to_string(),
            )
            .with_evidence(format!(
                "capa rule `{namespace}/{name}` matched this binary's real imports/strings"
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::verify::{Claim, Verification};

    #[test]
    fn empty_report_renders_a_clean_no_findings_message() {
        let doc = ReportDoc::new("test.exe");
        let md = doc.to_markdown();
        assert!(md.contains("# Findings: test.exe"));
        assert!(md.contains("No confirmed findings."));
    }

    #[test]
    fn findings_are_grouped_by_descending_severity() {
        let mut doc = ReportDoc::new("test.exe");
        doc.add(Finding::new("low finding", Severity::Low, "d"));
        doc.add(Finding::new("high finding", Severity::High, "d"));
        doc.add(Finding::new("info finding", Severity::Info, "d"));
        let md = doc.to_markdown();
        let high_pos = md.find("high finding").expect("present");
        let low_pos = md.find("low finding").expect("present");
        let info_pos = md.find("info finding").expect("present");
        assert!(high_pos < low_pos, "high must render before low");
        assert!(low_pos < info_pos, "low must render before info");
    }

    #[test]
    fn evidence_and_address_appear_in_the_rendered_markdown() {
        let mut doc = ReportDoc::new("test.exe");
        doc.add(
            Finding::new("f", Severity::Info, "d")
                .with_evidence("evidence line")
                .with_address(0x1400),
        );
        let md = doc.to_markdown();
        assert!(md.contains("evidence line"));
        assert!(md.contains("0x1400"));
    }

    #[test]
    fn unconfirmed_claims_stay_visible_not_silently_dropped() {
        let mut doc = ReportDoc::new("test.exe");
        doc.add_unconfirmed("hallucinated function at 0xdeadbeef -- not found");
        let md = doc.to_markdown();
        assert!(md.contains("Unconfirmed"));
        assert!(md.contains("hallucinated function"));
    }

    #[test]
    fn a_report_with_no_unconfirmed_claims_omits_that_section_entirely() {
        let mut doc = ReportDoc::new("test.exe");
        doc.add(Finding::new("f", Severity::Info, "d"));
        let md = doc.to_markdown();
        assert!(!md.contains("Unconfirmed"));
    }

    #[test]
    fn from_verification_splits_verified_and_failed_claims_correctly() {
        let report = VerificationReport {
            verifications: vec![
                Verification {
                    claim: Claim::ImportPresent {
                        name: "RegSetValueExA".to_string(),
                    },
                    verified: true,
                    evidence: "RegSetValueExA is imported".to_string(),
                },
                Verification {
                    claim: Claim::ImportPresent {
                        name: "totally_made_up".to_string(),
                    },
                    verified: false,
                    evidence: "not one of them".to_string(),
                },
            ],
        };
        let doc = ReportDoc::from_verification("test.exe", &report);
        assert_eq!(doc.findings.len(), 1);
        assert_eq!(doc.unconfirmed.len(), 1);
        assert!(doc.unconfirmed[0].contains("totally_made_up"));
    }

    #[test]
    fn capability_findings_assigns_severity_from_namespace() {
        let matches = [
            (
                "persist via the Run key",
                "persistence/registry-run-key",
                "d1",
            ),
            ("inject into a remote process", "process/inject", "d2"),
            ("read/write files", "host-interaction/file-system", "d3"),
        ];
        let findings = capability_findings(&matches);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[1].severity, Severity::Medium);
        assert_eq!(findings[2].severity, Severity::Info);
    }

    #[test]
    fn rendering_is_deterministic_across_repeated_calls() {
        let mut doc = ReportDoc::new("test.exe");
        doc.add(Finding::new("a", Severity::Info, "d").with_evidence("e1"));
        doc.add(Finding::new("b", Severity::Medium, "d").with_evidence("e2"));
        assert_eq!(doc.to_markdown(), doc.to_markdown());
    }
}
