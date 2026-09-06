//! Run lifecycle state machine — the canonical automaton (ARCHITECTURE.md §4),
//! reconciling the FTT and TT diagrams into one deterministic transition table.
//!
//! ```text
//! Idle -Validate-> Validated -Arm-> Armed -Inject-> Injecting
//!   Injecting -Detect-> Detected -Contain-> Contained -Cleanup-> Cleanup
//!   Injecting -TripBreaker-> CircuitBreakerTripped -Cleanup-> Cleanup
//!   Cleanup -Complete-> Completed
//! ```
//!
//! Invariant: `Injecting` is unreachable without first passing `Validated`
//! (signature + INV-0) and `Armed` (RBAC + sandbox). Any fault forces Cleanup.

use std::fmt;

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

/// Events that drive the machine forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEvent {
    /// DSL + Ed25519 signature verified.
    Validate,
    /// RBAC passed, canary sandbox + dead-man switch initialised.
    Arm,
    /// Begin synthetic injection.
    Inject,
    /// Blue Team detected the activity (MTTD measured).
    Detect,
    /// Containment applied (MTTR measured).
    Contain,
    /// Safety governor tripped: resource breach, timeout or lost heartbeat.
    TripBreaker,
    /// Remove canary files, reset network rules.
    Cleanup,
    /// Archive the completed run.
    Complete,
}

/// Rejected transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateError {
    pub from: RunState,
    pub event: RunEvent,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal transition {:?} on {:?}", self.event, self.from)
    }
}

impl std::error::Error for StateError {}

impl RunState {
    /// Apply an event, returning the next state or a `StateError` for any
    /// transition not in the table. Total function: no panics.
    pub fn on(self, event: RunEvent) -> Result<RunState, StateError> {
        use RunEvent as E;
        use RunState as S;
        let next = match (self, event) {
            (S::Idle, E::Validate) => S::Validated,
            (S::Validated, E::Arm) => S::Armed,
            (S::Armed, E::Inject) => S::Injecting,
            (S::Injecting, E::Detect) => S::Detected,
            (S::Injecting, E::TripBreaker) => S::CircuitBreakerTripped,
            (S::Detected, E::Contain) => S::Contained,
            (S::Contained, E::Cleanup) => S::Cleanup,
            (S::CircuitBreakerTripped, E::Cleanup) => S::Cleanup,
            (S::Cleanup, E::Complete) => S::Completed,
            _ => return Err(StateError { from: self, event }),
        };
        Ok(next)
    }

    /// Terminal states admit no further events.
    pub fn is_terminal(self) -> bool {
        matches!(self, RunState::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::RunEvent as E;
    use super::RunState as S;

    #[test]
    fn happy_path_reaches_completed() {
        let mut s = S::Idle;
        for ev in [
            E::Validate,
            E::Arm,
            E::Inject,
            E::Detect,
            E::Contain,
            E::Cleanup,
            E::Complete,
        ] {
            s = s.on(ev).expect("legal transition");
        }
        assert_eq!(s, S::Completed);
        assert!(s.is_terminal());
    }

    #[test]
    fn breaker_path_reaches_cleanup() {
        let s = S::Idle
            .on(E::Validate)
            .and_then(|s| s.on(E::Arm))
            .and_then(|s| s.on(E::Inject))
            .and_then(|s| s.on(E::TripBreaker))
            .and_then(|s| s.on(E::Cleanup))
            .and_then(|s| s.on(E::Complete))
            .unwrap();
        assert_eq!(s, S::Completed);
    }

    #[test]
    fn cannot_inject_without_arming() {
        // Injecting is unreachable straight from Validated.
        assert!(S::Validated.on(E::Inject).is_err());
        // ...and unreachable from Idle.
        assert!(S::Idle.on(E::Inject).is_err());
    }

    #[test]
    fn illegal_transition_is_reported() {
        let err = S::Idle.on(E::Contain).unwrap_err();
        assert_eq!(err.from, S::Idle);
        assert_eq!(err.event, E::Contain);
    }
}
