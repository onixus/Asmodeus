//! asmodeus-common — shared domain types, error taxonomy and config primitives
//! used across every Asmodeus crate. No external dependencies at skeleton stage.

/// Roles recognised by the RBAC engine. The CISO/Auditor/SecOps invariant
/// (403 on any run/inject) is enforced in `asmodeus-control-plane`, never in
/// the upstream APEX gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    RedTeam,
    DevSecOps,
    Ciso,
    SecOps,
    Auditor,
}

/// Canonical lifecycle state of a scenario run (see ARCHITECTURE.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Idle,
    Validated,
    Armed,
    Injecting,
    Detected,
    Contained,
    CircuitBreakerTripped,
    Cleanup,
    Completed,
}

/// Placeholder crate-wide error type; widen with `thiserror` when wiring deps.
#[derive(Debug)]
pub enum Error {
    Unauthorized,
    InvalidSignature,
    OutOfScope,
    CircuitBreaker,
}

pub const EXERCISE_TAG_RED_TEAM: &str = "🔴 [RED TEAM EXERCISE]";
pub const EXERCISE_TAG_CHAOS: &str = "⚡ [CHAOS TEST]";

/// INV-0 (Synthetic-Only): the root safety invariant of Asmodeus.
///
/// Asmodeus imitates adversary techniques to measure Blue Team response; it
/// never carries operational capability. Every action must be a synthetic
/// marker (canary files, pseudo-encryption in canary scope, benign probes,
/// test-segment network noise). Real malware, working exploits, real container
/// escape, defense-evasion, or targeting outside the canary scope are
/// OUT OF PROJECT SCOPE and must not be merged (see ARCHITECTURE.md §0).
///
/// The boundary is defined by the nature of the artifact, not the dev phase.
pub const INV_0_SYNTHETIC_ONLY: &str =
    "Asmodeus is synthetic-only: imitate techniques, never carry operational capability";

/// Classifies whether a runner action stays within INV-0. Real/operational
/// payloads are rejected before any state transition into `Injecting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionNature {
    /// Synthetic marker or benign probe — permitted.
    Synthetic,
    /// Operational/weaponizable capability — forbidden, out of scope.
    Operational,
}

impl ActionNature {
    /// INV-0 gate: only synthetic actions may execute.
    pub fn is_permitted(self) -> bool {
        matches!(self, ActionNature::Synthetic)
    }
}
