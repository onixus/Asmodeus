//! asmodeus-safety — independent control loop guaranteeing no harm to prod:
//! blast-radius enforcement, resource watchdog, Dead-Man switch and mandatory
//! rollback. Any breach forces the run into CLEANUP unconditionally.

/// Trip thresholds for the circuit breaker (see ARCHITECTURE.md §5).
pub const CPU_TRIP_PERCENT: u8 = 85;

pub fn should_trip(cpu_percent: u8, heartbeats_missed: u8) -> bool {
    cpu_percent > CPU_TRIP_PERCENT || heartbeats_missed >= 3
}
