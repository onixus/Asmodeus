//! asmodeus-safety — the independent control loop that guarantees no harm:
//! blast-radius scope, a resource circuit breaker and a dead-man switch. Any
//! breach forces the run into CLEANUP unconditionally (ARCHITECTURE.md §5).
//!
//! Pure logic, no timers of its own: callers feed it observations (CPU sample,
//! elapsed time, heartbeat ticks) and act on the returned `Trip`.

/// Trip thresholds. Defaults match TT §3 / FTT §4.3.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    pub cpu_trip_percent: u8,
    pub heartbeat_miss_limit: u8,
    pub max_duration_ms: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            cpu_trip_percent: 85,
            heartbeat_miss_limit: 3,
            max_duration_ms: 120_000,
        }
    }
}

/// Why the breaker tripped. Every variant leads to CLEANUP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trip {
    Cpu(u8),
    Timeout(u64),
    Heartbeat(u8),
}

/// Resource circuit breaker: evaluates a single observation against thresholds.
#[derive(Debug, Clone, Copy)]
pub struct CircuitBreaker {
    thresholds: Thresholds,
}

impl CircuitBreaker {
    pub fn new(thresholds: Thresholds) -> Self {
        CircuitBreaker { thresholds }
    }

    /// Returns `Some(Trip)` if this observation breaches a limit, else `None`.
    pub fn evaluate(
        &self,
        cpu_percent: u8,
        elapsed_ms: u64,
        heartbeats_missed: u8,
    ) -> Option<Trip> {
        if cpu_percent > self.thresholds.cpu_trip_percent {
            return Some(Trip::Cpu(cpu_percent));
        }
        if elapsed_ms > self.thresholds.max_duration_ms {
            return Some(Trip::Timeout(elapsed_ms));
        }
        if heartbeats_missed >= self.thresholds.heartbeat_miss_limit {
            return Some(Trip::Heartbeat(heartbeats_missed));
        }
        None
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        CircuitBreaker::new(Thresholds::default())
    }
}

/// Dead-man switch: the runner must hear a heartbeat from the control-plane at
/// a fixed cadence. `record_beat` resets the miss count; `miss` increments it.
/// Once `is_expired`, the runner kills everything and rolls back.
#[derive(Debug, Clone, Copy)]
pub struct DeadManSwitch {
    limit: u8,
    missed: u8,
}

impl DeadManSwitch {
    pub fn new(limit: u8) -> Self {
        DeadManSwitch { limit, missed: 0 }
    }

    pub fn record_beat(&mut self) {
        self.missed = 0;
    }

    pub fn miss(&mut self) {
        self.missed = self.missed.saturating_add(1);
    }

    pub fn missed(&self) -> u8 {
        self.missed
    }

    pub fn is_expired(&self) -> bool {
        self.missed >= self.limit
    }
}

impl Default for DeadManSwitch {
    fn default() -> Self {
        DeadManSwitch::new(3)
    }
}

/// Back-compat convenience: trip on CPU or heartbeat with default thresholds.
pub fn should_trip(cpu_percent: u8, heartbeats_missed: u8) -> bool {
    CircuitBreaker::default()
        .evaluate(cpu_percent, 0, heartbeats_missed)
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_trips_on_cpu() {
        let b = CircuitBreaker::default();
        assert_eq!(b.evaluate(90, 0, 0), Some(Trip::Cpu(90)));
        assert_eq!(b.evaluate(85, 0, 0), None); // boundary: not strictly greater
    }

    #[test]
    fn breaker_trips_on_timeout_and_heartbeat() {
        let b = CircuitBreaker::default();
        assert_eq!(b.evaluate(10, 120_001, 0), Some(Trip::Timeout(120_001)));
        assert_eq!(b.evaluate(10, 0, 3), Some(Trip::Heartbeat(3)));
    }

    #[test]
    fn dead_man_switch_expires_after_limit() {
        let mut dms = DeadManSwitch::new(3);
        dms.miss();
        dms.miss();
        assert!(!dms.is_expired());
        dms.miss();
        assert!(dms.is_expired());
        dms.record_beat();
        assert!(!dms.is_expired());
        assert_eq!(dms.missed(), 0);
    }
}
