//! asmodeus-telemetry — measures MTTD/MTTR, tags every artifact as an exercise
//! and exports Prometheus metrics into the shared APEX ClickHouse bus.
//! Pure computation + text exposition; no async scrape server yet.

/// Detection/containment timings for one run.
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

/// Rolling aggregate over completed runs, feeding the `/metrics` endpoint.
#[derive(Debug, Default, Clone)]
pub struct Aggregate {
    pub scenarios_executed: u64,
    pub detected: u64,
    sum_mttd_ms: u64,
    sum_mttr_ms: u64,
}

impl Aggregate {
    pub fn record(&mut self, m: Measurements) {
        self.scenarios_executed += 1;
        if m.blue_team_detected {
            self.detected += 1;
        }
        self.sum_mttd_ms += m.mttd_ms;
        self.sum_mttr_ms += m.mttr_ms;
    }

    pub fn mean_mttd_ms(&self) -> u64 {
        self.sum_mttd_ms
            .checked_div(self.scenarios_executed)
            .unwrap_or(0)
    }

    pub fn mean_mttr_ms(&self) -> u64 {
        self.sum_mttr_ms
            .checked_div(self.scenarios_executed)
            .unwrap_or(0)
    }

    /// Percentage of runs the Blue Team detected (0..100).
    pub fn detection_rate_pct(&self) -> f32 {
        if self.scenarios_executed == 0 {
            return 0.0;
        }
        100.0 * self.detected as f32 / self.scenarios_executed as f32
    }

    /// Prometheus text exposition (see TT §4.3).
    pub fn prometheus_text(&self) -> String {
        let score = resilience_score(self.detection_rate_pct(), 100.0);
        format!(
            "# HELP asmodeus_resilience_score Integral cyber-resilience index (0..100)\n\
             # TYPE asmodeus_resilience_score gauge\n\
             asmodeus_resilience_score {score}\n\
             # HELP asmodeus_mttd_seconds Mean time to detect\n\
             # TYPE asmodeus_mttd_seconds gauge\n\
             asmodeus_mttd_seconds {:.3}\n\
             # HELP asmodeus_mttr_seconds Mean time to remediate\n\
             # TYPE asmodeus_mttr_seconds gauge\n\
             asmodeus_mttr_seconds {:.3}\n\
             # HELP asmodeus_scenarios_executed_total Scenarios executed\n\
             # TYPE asmodeus_scenarios_executed_total counter\n\
             asmodeus_scenarios_executed_total {}\n",
            self.mean_mttd_ms() as f64 / 1000.0,
            self.mean_mttr_ms() as f64 / 1000.0,
            self.scenarios_executed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_is_clamped() {
        assert_eq!(resilience_score(120.0, 120.0), 100);
        assert_eq!(resilience_score(-5.0, 0.0), 0);
        assert_eq!(resilience_score(100.0, 0.0), 50);
    }

    #[test]
    fn aggregate_means_and_rate() {
        let mut agg = Aggregate::default();
        agg.record(Measurements {
            mttd_ms: 100,
            mttr_ms: 200,
            blue_team_detected: true,
        });
        agg.record(Measurements {
            mttd_ms: 300,
            mttr_ms: 400,
            blue_team_detected: false,
        });
        assert_eq!(agg.mean_mttd_ms(), 200);
        assert_eq!(agg.mean_mttr_ms(), 300);
        assert_eq!(agg.detection_rate_pct(), 50.0);
    }

    #[test]
    fn prometheus_text_has_expected_series() {
        let mut agg = Aggregate::default();
        agg.record(Measurements {
            mttd_ms: 142,
            mttr_ms: 280,
            blue_team_detected: true,
        });
        let text = agg.prometheus_text();
        assert!(text.contains("asmodeus_resilience_score "));
        assert!(text.contains("asmodeus_scenarios_executed_total 1"));
        assert!(text.contains("asmodeus_mttd_seconds 0.142"));
    }

    #[test]
    fn empty_aggregate_is_safe() {
        let agg = Aggregate::default();
        assert_eq!(agg.mean_mttd_ms(), 0);
        assert_eq!(agg.detection_rate_pct(), 0.0);
    }
}
