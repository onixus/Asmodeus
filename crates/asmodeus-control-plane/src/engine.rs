//! Run engine — drives one scenario through the canonical state machine
//! (ARCHITECTURE.md §4) under INV-0. For the MVP the injection is synthetic and
//! measurements are deterministic; the transition guards are real.

use asmodeus_common::{RunEvent, RunState, StateError};
use asmodeus_dsl::{validate, RejectReason};
use thiserror::Error;

use crate::catalog::ScenarioEntry;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("scenario rejected by INV-0 / scope validation: {0:?}")]
    Rejected(RejectReason),
    #[error(transparent)]
    Transition(#[from] StateError),
}

/// Result of a completed run.
/// The engine drives the lifecycle; measurements are a catalog/telemetry
/// concern (see `http.rs`), so the outcome is just the terminal state.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub final_state: RunState,
}

/// Execute a scenario end to end. Every step is a checked state transition:
/// an illegal step aborts the run instead of proceeding.
pub fn execute(entry: &ScenarioEntry) -> Result<Outcome, EngineError> {
    // INV-0 + canary-scope gate before anything is armed.
    validate(entry.nature, &entry.target_path).map_err(EngineError::Rejected)?;

    let mut state = RunState::Idle;
    state = state.on(RunEvent::Validate)?;
    state = state.on(RunEvent::Arm)?;
    state = state.on(RunEvent::Inject)?;

    // Synthetic injection happens here; Blue Team reacts.
    state = state.on(RunEvent::Detect)?;
    state = state.on(RunEvent::Contain)?;
    state = state.on(RunEvent::Cleanup)?;
    state = state.on(RunEvent::Complete)?;

    Ok(Outcome { final_state: state })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;

    #[test]
    fn seeded_scenarios_run_to_completed() {
        let cat = Catalog::seeded();
        assert_eq!(cat.entries().count(), 11);
        for entry in cat.entries() {
            let outcome = execute(entry).unwrap();
            assert_eq!(outcome.final_state, RunState::Completed);
        }
    }
}
