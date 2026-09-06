//! asmodeus-telemetry — measures MTTD/MTTR, tags every artifact as an exercise
//! and exports Prometheus/OTel metrics into the shared APEX ClickHouse bus.
#[derive(Debug, Default, Clone, Copy)]
pub struct Measurements {
    pub mttd_ms: u64,
    pub mttr_ms: u64,
    pub blue_team_detected: bool,
}

/// Integral 0..100 cyber-resilience index.
pub fn resilience_score(attacks_repelled_pct: f32, recovery_speed_pct: f32) -> u8 {
    (0.5 * attacks_repelled_pct + 0.5 * recovery_speed_pct).clamp(0.0, 100.0) as u8
}
