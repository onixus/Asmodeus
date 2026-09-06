//! asmodeus-dsl — declarative scenario manifests (`AttackScenario`,
//! `ChaosExperiment`), type validation and safety whitelisting of paths/ports.
//! The REST API accepts only a validated, signed `scenario_id` — never a body.

/// Canary filesystem sandbox: the only paths any runner action may touch.
pub const CANARY_PREFIXES: [&str; 2] = ["/var/tmp/asmodeus-canary/", "/tmp/asmodeus-canary/"];

pub fn path_in_scope(path: &str) -> bool {
    CANARY_PREFIXES.iter().any(|p| path.starts_with(p))
}
