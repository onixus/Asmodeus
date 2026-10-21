//! Scenario **fidelity** model (S01).
//!
//! INV-0 (ARCHITECTURE.md §0) makes every Asmodeus action synthetic: the engine
//! *imitates* a technique, it never carries real capability. Fidelity records
//! *how faithfully* a given synthetic scenario imitates its ATT&CK technique,
//! and — crucially — therefore **what coverage it is allowed to claim**.
//!
//! This is the honesty gate that keeps reports from overstating validation. A
//! scenario that only drops a canary marker proves an *indicator* can be
//! produced and observed; it does not prove the technique's behaviour ran, and
//! it must never be reported as behavioural or prevention coverage of the whole
//! technique. Prevention / containment are never asserted from the attack side
//! at all — they additionally require confirmed Blue-Team feedback, gated in
//! the telemetry layer.

use serde::{Deserialize, Serialize};

/// How faithfully a synthetic scenario reproduces its ATT&CK technique.
///
/// Ordering is by trust: `Unspecified` < `MarkerOnly` < `Behavioral`. No higher
/// variant exists — a "weaponized" / real-impact level is forbidden by INV-0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Fidelity {
    /// Legacy or undeclared fidelity (e.g. a `v1alpha1` manifest). Treated as
    /// the **lowest** trust — equivalent to marker-only for every coverage
    /// decision — so old results are read without being promoted.
    #[default]
    Unspecified,
    /// Creates or touches a synthetic marker/canary artifact: a decoy file, a
    /// honeytoken, a beacon-event log, a recovery pulse. Proves an indicator is
    /// present and detectable — not that the technique's behaviour executed.
    MarkerOnly,
    /// Executes a representative but strictly synthetic behaviour confined to
    /// canary / reserved-test scope (reversible XOR over canary docs, synthetic
    /// beaconing to RFC 5737 test nets, synthetic network perturbation).
    /// Produces a behavioural signal — an imitation, never real impact.
    Behavioral,
}

/// The strongest kind of coverage a fidelity level may contribute to a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageClass {
    /// Only that a synthetic indicator/artifact exists and can be seen.
    IndicatorOnly,
    /// A representative synthetic behaviour ran and is observable.
    BehavioralSignal,
}

impl Fidelity {
    /// Parse a manifest string. Unknown / empty → `None` (caller decides the
    /// default); recognised values are case-insensitive.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "unspecified" => Some(Self::Unspecified),
            "marker_only" | "marker-only" | "markeronly" => Some(Self::MarkerOnly),
            "behavioral" | "behavioural" => Some(Self::Behavioral),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::MarkerOnly => "marker_only",
            Self::Behavioral => "behavioral",
        }
    }

    /// Strongest coverage this fidelity may contribute. `Unspecified` and
    /// `MarkerOnly` are both indicator-only; only `Behavioral` reaches a
    /// behavioural signal.
    pub fn coverage_class(self) -> CoverageClass {
        match self {
            Self::Unspecified | Self::MarkerOnly => CoverageClass::IndicatorOnly,
            Self::Behavioral => CoverageClass::BehavioralSignal,
        }
    }

    /// True iff a scenario at this fidelity may count toward **behavioural**
    /// coverage of its technique. Marker-only and undeclared never do.
    pub fn claims_behavioral(self) -> bool {
        matches!(self.coverage_class(), CoverageClass::BehavioralSignal)
    }

    /// True iff a scenario at this fidelity may, *with confirmed feedback*,
    /// contribute to a **prevention/containment** claim. Marker-only and
    /// undeclared never do, regardless of feedback — an indicator being blocked
    /// is not evidence the technique's behaviour was prevented.
    ///
    /// This gates only the attack side; the telemetry layer additionally
    /// requires confirmed Blue-Team feedback before any prevention claim.
    pub fn permits_prevention_claim(self) -> bool {
        self.claims_behavioral()
    }

    /// Human-readable one-liner for reports/CLI.
    pub fn summary(self) -> &'static str {
        match self {
            Self::Unspecified => {
                "undeclared fidelity (legacy); treated as marker-only — no behavioural coverage"
            }
            Self::MarkerOnly => {
                "synthetic marker/indicator only — not behavioural or prevention coverage"
            }
            Self::Behavioral => "representative synthetic behaviour within canary/test scope",
        }
    }
}

/// ATT&CK platform a procedure applies to. Kept small and synthetic-scope
/// oriented; serialized as snake_case strings in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    Windows,
    Macos,
    Containers,
    Kubernetes,
    Network,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Containers => "containers",
            Self::Kubernetes => "kubernetes",
            Self::Network => "network",
        }
    }
}

/// A scenario's reference to one ATT&CK technique, carrying the fidelity at
/// which that technique is exercised. A scenario may hold several of these
/// (multi-technique / multi-tactic), with exactly one marked primary by the
/// catalog (it is the first in the list by convention).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueRef {
    /// ATT&CK technique or sub-technique ID (must resolve in [`crate::mitre`]).
    pub technique_id: String,
    /// Fidelity at which this scenario exercises the technique.
    #[serde(default)]
    pub fidelity: Fidelity,
}

impl TechniqueRef {
    pub fn new(technique_id: impl Into<String>, fidelity: Fidelity) -> Self {
        Self {
            technique_id: technique_id.into(),
            fidelity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_only_and_unspecified_never_claim_behavioral() {
        assert!(!Fidelity::Unspecified.claims_behavioral());
        assert!(!Fidelity::MarkerOnly.claims_behavioral());
        assert!(Fidelity::Behavioral.claims_behavioral());
    }

    #[test]
    fn marker_only_and_unspecified_never_permit_prevention() {
        assert!(!Fidelity::Unspecified.permits_prevention_claim());
        assert!(!Fidelity::MarkerOnly.permits_prevention_claim());
        assert!(Fidelity::Behavioral.permits_prevention_claim());
    }

    #[test]
    fn coverage_class_matches_trust() {
        assert_eq!(
            Fidelity::MarkerOnly.coverage_class(),
            CoverageClass::IndicatorOnly
        );
        assert_eq!(
            Fidelity::Behavioral.coverage_class(),
            CoverageClass::BehavioralSignal
        );
    }

    #[test]
    fn trust_ordering_holds() {
        assert!(Fidelity::Unspecified < Fidelity::MarkerOnly);
        assert!(Fidelity::MarkerOnly < Fidelity::Behavioral);
    }

    #[test]
    fn parse_is_case_insensitive_and_total() {
        assert_eq!(Fidelity::parse("Behavioural"), Some(Fidelity::Behavioral));
        assert_eq!(Fidelity::parse("MARKER-ONLY"), Some(Fidelity::MarkerOnly));
        assert_eq!(Fidelity::parse("marker_only"), Some(Fidelity::MarkerOnly));
        assert_eq!(Fidelity::parse("nonsense"), None);
    }

    #[test]
    fn default_fidelity_is_lowest_trust() {
        assert_eq!(Fidelity::default(), Fidelity::Unspecified);
        assert!(!Fidelity::default().claims_behavioral());
    }

    #[test]
    fn technique_ref_defaults_fidelity_when_absent() {
        let r: TechniqueRef = serde_json::from_str(r#"{"technique_id":"T1486"}"#).unwrap();
        assert_eq!(r.fidelity, Fidelity::Unspecified);
    }
}
