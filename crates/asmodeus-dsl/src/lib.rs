//! asmodeus-dsl — declarative scenario manifests (`AttackScenario`,
//! `ChaosExperiment`), type validation and safety whitelisting of paths/ports.
//! The REST API accepts only a validated, signed `scenario_id` — never a body.
//!
//! Enforces the root invariant INV-0 (Synthetic-Only, see ARCHITECTURE.md §0):
//! a manifest whose action is operational/weaponizable is rejected here, before
//! it can ever reach a runner.

use asmodeus_common::{ActionNature, RunState};

/// Canary filesystem sandbox: the only paths any runner action may touch.
pub const CANARY_PREFIXES: [&str; 2] = ["/var/tmp/asmodeus-canary/", "/tmp/asmodeus-canary/"];

pub fn path_in_scope(path: &str) -> bool {
    CANARY_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Reason a manifest is refused validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// INV-0 breach: the action carries operational capability.
    NotSynthetic,
    /// Filesystem target lies outside the canary scope.
    OutOfScope,
}

/// INV-0 gate. Returns the next state (`Validated`) only for synthetic actions
/// confined to canary scope; otherwise the manifest is refused and never armed.
pub fn validate(nature: ActionNature, target_path: &str) -> Result<RunState, RejectReason> {
    if !nature.is_permitted() {
        return Err(RejectReason::NotSynthetic);
    }
    if !path_in_scope(target_path) {
        return Err(RejectReason::OutOfScope);
    }
    Ok(RunState::Validated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_action_in_scope_validates() {
        let r = validate(ActionNature::Synthetic, "/tmp/asmodeus-canary/doc1");
        assert_eq!(r, Ok(RunState::Validated));
    }

    #[test]
    fn operational_action_is_rejected_by_inv0() {
        let r = validate(ActionNature::Operational, "/tmp/asmodeus-canary/doc1");
        assert_eq!(r, Err(RejectReason::NotSynthetic));
    }

    #[test]
    fn out_of_scope_path_is_rejected() {
        let r = validate(ActionNature::Synthetic, "/etc/passwd");
        assert_eq!(r, Err(RejectReason::OutOfScope));
    }
}
