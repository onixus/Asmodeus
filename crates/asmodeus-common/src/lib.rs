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
